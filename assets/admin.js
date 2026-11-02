/* global elderwardAdmin */
(function () {
	'use strict';

	var cfg = window.elderwardAdmin || {};
	var startBtn = document.getElementById('elderward-start');
	var cancelBtn = document.getElementById('elderward-cancel');
	var logInput = document.getElementById('elderward-log');
	var progress = document.getElementById('elderward-progress');
	var bar = progress ? progress.querySelector('.elderward-bar-fill') : null;
	var statusText = document.getElementById('elderward-status-text');
	var runnerNote = document.getElementById('elderward-runner-note');
	var stopped = false;
	// Background mode: the page only watches. If WP-Cron stops reporting
	// progress for `stale` seconds it is kicked once; if that changes nothing
	// within KICK_GRACE_MS the page steps the job itself, as in browser mode.
	var STALE = Number(cfg.stale) || 120;
	var KICK_GRACE_MS = 30000;
	var kickedAt = 0;
	var tookOver = false;

	scheduleForm();

	if (!startBtn) {
		return;
	}

	function post(action, fields) {
		var body = new FormData();
		body.append('action', action);
		body.append('nonce', cfg.nonce);
		Object.keys(fields || {}).forEach(function (key) {
			body.append(key, fields[key]);
		});
		return fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
			.then(function (response) { return response.json(); });
	}

	function setText(text) {
		if (statusText) {
			statusText.textContent = text;
		}
	}

	function setNote(text) {
		if (runnerNote) {
			runnerNote.textContent = text;
		}
	}

	function render(data) {
		if (!data) {
			return;
		}
		if (bar) {
			bar.style.width = Math.max(0, Math.min(100, data.percent || 0)) + '%';
		}
		var line = data.stage ? cfg.i18n.running.replace('%s', data.stage) : cfg.i18n.starting;
		if (data.message) {
			line += ' — ' + data.message;
		}
		if (data.background && !tookOver && typeof data.idle === 'number') {
			line += ' (' + cfg.i18n.idle.replace('%d', String(data.idle)) + ')';
		}
		setText(line);
	}

	function finished(data) {
		startBtn.disabled = false;
		cancelBtn.disabled = true;
		if (data.status === 'done') {
			setText(cfg.i18n.done);
			window.location.reload();
		} else if (data.status === 'failed') {
			setText(cfg.i18n.failed.replace('%s', data.error || ''));
			window.setTimeout(function () { window.location.reload(); }, 1500);
		} else {
			setText(cfg.i18n.cancelled);
			window.setTimeout(function () { window.location.reload(); }, 800);
		}
	}

	// Browser mode (and the fallback): this tab runs the steps.
	function loop() {
		if (stopped) {
			return;
		}
		post('elderward_step').then(function (result) {
			if (!result || !result.success) {
				setText((result && result.data && result.data.message) || cfg.i18n.network);
				window.setTimeout(loop, 3000);
				return;
			}
			var data = result.data;
			render(data);
			if (data.status === 'running') {
				window.setTimeout(loop, 250);
			} else {
				finished(data);
			}
		}).catch(function () {
			setText(cfg.i18n.network);
			window.setTimeout(loop, 3000);
		});
	}

	// Background mode: WP-Cron runs the steps, this tab shows the status.
	function watch() {
		if (stopped) {
			return;
		}
		post('elderward_status').then(function (result) {
			if (!result || !result.success) {
				setText((result && result.data && result.data.message) || cfg.i18n.network);
				window.setTimeout(watch, 3000);
				return;
			}
			var data = result.data;
			render(data);
			if (data.status !== 'running') {
				finished(data);
				return;
			}
			if (typeof data.idle === 'number' && data.idle >= STALE) {
				if (!kickedAt) {
					kickedAt = Date.now();
					post('elderward_kick').catch(function () {});
				} else if (Date.now() - kickedAt > KICK_GRACE_MS) {
					tookOver = true;
					setNote(cfg.i18n.takeover);
					loop();
					return;
				}
			} else {
				kickedAt = 0;
			}
			window.setTimeout(watch, 2000);
		}).catch(function () {
			setText(cfg.i18n.network);
			window.setTimeout(watch, 3000);
		});
	}

	function follow(background) {
		setNote(background ? cfg.i18n.background : cfg.i18n.browser);
		if (background) {
			watch();
		} else {
			loop();
		}
	}

	function begin() {
		stopped = false;
		kickedAt = 0;
		tookOver = false;
		startBtn.disabled = true;
		cancelBtn.disabled = false;
		progress.hidden = false;
		setText(cfg.i18n.starting);
	}

	startBtn.addEventListener('click', function () {
		begin();
		post('elderward_start', { log: logInput ? logInput.value : '' }).then(function (result) {
			if (!result || !result.success) {
				startBtn.disabled = false;
				cancelBtn.disabled = true;
				setText((result && result.data && result.data.message) || cfg.i18n.network);
				return;
			}
			render(result.data);
			follow(!!result.data.background);
		}).catch(function () {
			startBtn.disabled = false;
			cancelBtn.disabled = true;
			setText(cfg.i18n.network);
		});
	});

	cancelBtn.addEventListener('click', function () {
		if (!window.confirm(cfg.i18n.confirm)) {
			return;
		}
		stopped = true;
		post('elderward_cancel').then(function (result) {
			finished(result && result.data ? result.data : { status: 'cancelled' });
		});
	});

	// A scan left running (page reload, closed tab) is picked up again.
	if (cfg.status === 'running') {
		begin();
		follow(!!cfg.background);
	}

	// Settings: show the time and weekday fields only when they apply.
	function scheduleForm() {
		var select = document.getElementById('elderward-schedule');
		if (!select) {
			return;
		}
		var when = document.querySelector('.elderward-schedule-when');
		var day = document.querySelector('.elderward-schedule-day');
		function update() {
			if (when) {
				when.hidden = select.value === 'off';
			}
			if (day) {
				day.hidden = select.value !== 'weekly';
			}
		}
		select.addEventListener('change', update);
		update();
	}
})();
