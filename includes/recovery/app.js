(function () {
	var L = function (text) { return FACHEIRO_L[text] || text; };
	var box = document.getElementById('scan');
	if (!box) { return; }
	var token = box.getAttribute('data-token');
	var start = document.getElementById('start');
	var cancel = document.getElementById('cancel');
	var progress = document.getElementById('progress');
	var fill = progress.querySelector('.fill');
	var status = document.getElementById('status');
	var stopped = false;
	function post(action, extra) {
		var body = new URLSearchParams();
		body.append('do', action);
		body.append('token', token);
		Object.keys(extra || {}).forEach(function (k) { body.append(k, extra[k]); });
		return fetch(location.pathname, { method: 'POST', credentials: 'same-origin', body: body }).then(function (r) { return r.json(); });
	}
	function show(data) {
		fill.style.width = (data.percent || 0) + '%';
		status.textContent = data.stage ? (L('Verificando: ') + data.stage + (data.message ? ' — ' + data.message : '')) : (data.message || L('Trabalhando…'));
	}
	function loop() {
		if (stopped) { return; }
		post('step').then(function (data) {
			if (!data.ok) { status.textContent = data.message || L('Erro.'); return; }
			show(data);
			if (data.status === 'running') { setTimeout(loop, 200); } else { location.reload(); }
		}).catch(function () { status.textContent = L('Perdemos o contato com o servidor; tentando de novo…'); setTimeout(loop, 3000); });
	}
	start.addEventListener('click', function () {
		start.disabled = true; cancel.disabled = false; progress.hidden = false; stopped = false;
		status.textContent = L('Iniciando…');
		post('start', { log: document.getElementById('log').value }).then(function (data) {
			if (!data.ok) { status.textContent = data.message || L('Não foi possível iniciar.'); start.disabled = false; cancel.disabled = true; return; }
			show(data); loop();
		});
	});
	cancel.addEventListener('click', function () {
		stopped = true;
		post('cancel').then(function () { location.reload(); });
	});
	if (box.getAttribute('data-running') === '1') { loop(); }
})();
