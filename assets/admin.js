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
	falsePositives();
	signatureEditor();
	copyButtons();

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

	// Findings: mark as false positive, undo, remove saved ones.
	function falsePositives() {
		document.addEventListener('click', function (event) {
			var button = event.target.closest ? event.target.closest('[data-fp-action]') : null;
			if (!button) {
				return;
			}
			var action = button.getAttribute('data-fp-action');
			var row = button.closest('tr');
			var fields = {};
			if (action === 'mark') {
				var note = window.prompt(cfg.i18n.fpPrompt, '');
				if (note === null) {
					return;
				}
				fields = { op: 'mark', id: row.getAttribute('data-id'), note: note };
			} else if (action === 'unmark') {
				fields = { op: 'unmark', fingerprint: row.getAttribute('data-fingerprint') };
			} else if (action === 'forget_all') {
				if (!window.confirm(cfg.i18n.fpForget)) {
					return;
				}
				fields = { op: 'forget_all' };
			} else {
				return;
			}
			button.disabled = true;
			post('elderward_fp', fields).then(function (result) {
				if (!result || !result.success) {
					button.disabled = false;
					window.alert((result && result.data && result.data.message) || cfg.i18n.network);
					return;
				}
				if (action === 'forget_all') {
					window.location.reload();
					return;
				}
				replaceRow(row, action === 'mark' ? cfg.i18n.fpMarked : cfg.i18n.fpRemoved, action === 'mark');
			}).catch(function () {
				button.disabled = false;
				window.alert(cfg.i18n.network);
			});
		});
	}

	// Collapse a row into a one-line message, with an undo after marking.
	function replaceRow(row, text, undo) {
		var cell = document.createElement('td');
		cell.colSpan = row.children.length;
		cell.className = 'elderward-row-message';
		cell.appendChild(document.createTextNode(text + ' '));
		if (undo) {
			var link = document.createElement('button');
			link.type = 'button';
			link.className = 'button-link';
			link.setAttribute('data-fp-action', 'unmark');
			link.textContent = cfg.i18n.fpUndo;
			cell.appendChild(link);
		}
		while (row.firstChild) {
			row.removeChild(row.firstChild);
		}
		row.appendChild(cell);
	}

	// Signature editor: confirm deletes, run the tester.
	function signatureEditor() {
		document.querySelectorAll('form[data-confirm="sig-delete"]').forEach(function (form) {
			form.addEventListener('submit', function (event) {
				if (!window.confirm(cfg.i18n.sigDelete)) {
					event.preventDefault();
				}
			});
		});
		var run = document.getElementById('elderward-test-run');
		if (!run) {
			return;
		}
		var out = document.getElementById('elderward-test-result');
		run.addEventListener('click', function () {
			run.disabled = true;
			out.textContent = '';
			post('elderward_sig_test', {
				path: document.getElementById('elderward-test-path').value,
				text: document.getElementById('elderward-test-text').value
			}).then(function (result) {
				run.disabled = false;
				if (!result || !result.success) {
					out.textContent = (result && result.data && result.data.message) || cfg.i18n.network;
					return;
				}
				var hits = result.data.hits || [];
				if (!hits.length) {
					out.textContent = cfg.i18n.sigNone;
					return;
				}
				var p = document.createElement('p');
				p.textContent = cfg.i18n.sigHits.replace('%d', String(hits.length));
				var ul = document.createElement('ul');
				hits.forEach(function (hit) {
					var li = document.createElement('li');
					var code = document.createElement('code');
					code.textContent = (hit.source === 'custom' ? 'custom.' : '') + hit.id;
					li.appendChild(code);
					li.appendChild(document.createTextNode(' ' + hit.severity + ', ' + hit.target + ', ' + hit.source + (hit.enabled ? '' : ' (' + cfg.i18n.disabled + ')')));
					ul.appendChild(li);
				});
				out.appendChild(p);
				out.appendChild(ul);
			}).catch(function () {
				run.disabled = false;
				out.textContent = cfg.i18n.network;
			});
		});
	}

	// AI assistants tab: select-on-focus and copy buttons.
	function copyButtons() {
		document.querySelectorAll('textarea.elderward-copy').forEach(function (area) {
			area.addEventListener('focus', function () { area.select(); });
		});
		document.querySelectorAll('[data-copy]').forEach(function (button) {
			button.addEventListener('click', function () {
				var area = document.getElementById(button.getAttribute('data-copy'));
				if (!area) {
					return;
				}
				area.select();
				var done = function () { button.textContent = cfg.i18n.copied; };
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText(area.value).then(done, function () { document.execCommand('copy'); done(); });
				} else {
					document.execCommand('copy');
					done();
				}
			});
		});
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
