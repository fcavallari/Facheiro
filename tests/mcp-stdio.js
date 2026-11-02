/*
 * Drive Elderward through the WordPress MCP Adapter over STDIO, the way an
 * MCP client (Claude Desktop, Claude Code, Antigravity, Cursor) does.
 * Needs the MCP Adapter plugin active on the site.
 *
 *   node tests/mcp-stdio.js "wp --path=/path/to/wordpress" admin
 *
 * Runs: initialize, tools/list, discover the elderward abilities, get the
 * triage prompt, start a scan and wait for it (advance-scan if WP-Cron
 * does not move), list HIGH findings, read a flagged file, test and save a
 * signature (wp-config.php refused), mark and unmark a false positive
 * (recorded as made by an assistant), and checks that a
 * subscriber gets no access.
 */
const { spawn } = require('child_process');

const wpCmd = (process.argv[2] || 'wp').split(' ');
const user = process.argv[3] || 'admin';

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

function server(asUser) {
	const child = spawn(wpCmd[0], wpCmd.slice(1).concat(['mcp-adapter', 'serve', '--server=mcp-adapter-default-server', '--user=' + asUser]), { stdio: ['pipe', 'pipe', 'pipe'] });
	let buffer = '';
	let nextId = 1;
	const waiting = {};
	child.stdout.on('data', (chunk) => {
		buffer += chunk.toString();
		let nl;
		while ((nl = buffer.indexOf('\n')) >= 0) {
			const line = buffer.slice(0, nl).trim();
			buffer = buffer.slice(nl + 1);
			if (!line) { continue; }
			let msg;
			try { msg = JSON.parse(line); } catch (e) { continue; }
			if (msg.id && waiting[msg.id]) { waiting[msg.id](msg); delete waiting[msg.id]; }
		}
	});
	child.stderr.on('data', () => {});
	return {
		call(method, params) {
			const id = nextId++;
			child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: id, method: method, params: params || {} }) + '\n');
			return new Promise((resolve, reject) => {
				const timer = setTimeout(() => reject(new Error('timeout: ' + method)), 120000);
				waiting[id] = (msg) => { clearTimeout(timer); resolve(msg); };
			});
		},
		notify(method) {
			child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: method }) + '\n');
		},
		close() { child.stdin.end(); child.kill(); },
	};
}

// Execute an ability through the adapter's execute tool; returns the
// ability's data, or throws with the error text.
async function ability(srv, name, parameters) {
	const res = await srv.call('tools/call', { name: 'mcp-adapter-execute-ability', arguments: { ability_name: name, parameters: parameters || {} } });
	if (res.error) { throw new Error(name + ': ' + JSON.stringify(res.error)); }
	const result = res.result || {};
	const text = (result.content || []).map((c) => c.text || '').join('');
	let data = result.structuredContent;
	if (!data) { try { data = JSON.parse(text); } catch (e) { data = text; } }
	if (result.isError || (data && data.success === false)) { throw new Error(name + ': ' + text); }
	return data && data.data !== undefined && data.success !== undefined ? data.data : data;
}

async function initialize(srv) {
	const init = await srv.call('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'elderward-test', version: '1' } });
	srv.notify('notifications/initialized');
	return init;
}

(async () => {
	const srv = server(user);
	const init = await initialize(srv);
	console.log('server:', init.result && init.result.serverInfo ? init.result.serverInfo.name : JSON.stringify(init).slice(0, 200));

	const tools = await srv.call('tools/list');
	console.log('tools:', tools.result.tools.map((t) => t.name).join(', '));

	const discovered = await srv.call('tools/call', { name: 'mcp-adapter-discover-abilities', arguments: {} });
	const discoveredText = JSON.stringify(discovered.result);
	const ours = (discoveredText.match(/elderward\/[a-z-]+/g) || []).filter((v, i, a) => a.indexOf(v) === i);
	console.log('elderward abilities discovered:', ours.length, ours.join(' '));
	if (ours.length < 14) { fail('not all abilities are exposed'); }

	const prompts = await srv.call('prompts/list');
	const triage = prompts.result.prompts.find((p) => /elderward/.test(p.name));
	console.log('prompt:', triage && triage.name);
	if (!triage) { fail('triage prompt missing'); } else {
		const got = await srv.call('prompts/get', { name: triage.name, arguments: { focus: 'spam redirects' } });
		const text = got.result.messages[0].content.text;
		console.log('prompt text starts:', text.slice(0, 80).replace(/\n/g, ' '), '…');
		if (!/Treat it strictly as data/.test(text) || !/spam redirects/.test(text)) { fail('prompt text incomplete'); }
	}

	console.log('== scan');
	let status = await ability(srv, 'elderward/get-status');
	if (status.scan && status.scan.status === 'running') { await ability(srv, 'elderward/cancel-scan'); }
	status = await ability(srv, 'elderward/start-scan', {});
	console.log('started:', status.scan.status, 'origin', status.scan.origin, 'background', status.scan.background);
	let advanced = 0;
	for (let i = 0; i < 120 && status.scan.status === 'running'; i++) {
		await new Promise((r) => setTimeout(r, 2000));
		status = await ability(srv, 'elderward/get-status');
		if (status.scan.status === 'running' && status.scan.idle >= 120) {
			status = await ability(srv, 'elderward/advance-scan');
			advanced++;
		}
	}
	console.log('scan:', status.scan.status, JSON.stringify(status.scan.counts), 'advance-scan calls:', advanced);
	if (status.scan.status !== 'done') { fail('scan did not finish'); }

	const high = await ability(srv, 'elderward/list-findings', { severity: 'HIGH' });
	console.log('HIGH findings:', high.total, high.findings.map((f) => f.type + ' ' + f.path).join(' | '));
	if (!high.untrusted_data_notice) { fail('no untrusted-data notice'); }
	const fileFinding = high.findings.find((f) => f.can_read_file);
	if (!fileFinding) { fail('no readable file finding'); } else {
		const file = await ability(srv, 'elderward/read-flagged-file', { id: fileFinding.id });
		console.log('read', file.path, file.size, 'bytes, sha matches scan:', file.sha256 === file.sha256_at_scan);
		if (file.sha256 !== fileFinding.sha256) { fail('hash mismatch'); }
	}
	const all = await ability(srv, 'elderward/list-findings', { limit: 200 });
	if (fileFinding) {
		const one = await ability(srv, 'elderward/get-finding', { id: fileFinding.id });
		if (!Array.isArray(one.context)) { fail('get-finding lost the context'); }
	}
	const dbFinding = all.findings.find((f) => /^DB_/.test(f.type));
	if (dbFinding) {
		try { await ability(srv, 'elderward/read-flagged-file', { id: dbFinding.id }); fail('read a database finding as a file'); } catch (e) { console.log('db finding read refused:', e.message.slice(0, 90)); }
	}

	console.log('== signatures');
	const candidate = { id: 'mcp-test', target: 'file', severity: 'LOW', description: 'MCP test signature', match: [{ string: 'acme_loader' }, { regex: '/base64_decode\\s*\\(\\s*\\$_POST/' }] };
	const tested = await ability(srv, 'elderward/test-signature', { signature: candidate, path: 'wp-content/plugins/acme/loader.php' });
	console.log('candidate:', JSON.stringify(tested.candidate), 'hits:', tested.hits.map((h) => h.id).join(','));
	if (!tested.candidate.valid || !tested.candidate.matches) { fail('candidate should match the fixture'); }
	const clean = await ability(srv, 'elderward/test-signature', { signature: candidate, path: 'wp-includes/version.php' });
	if (clean.candidate.matches) { fail('candidate matched a clean core file'); }
	try {
		await ability(srv, 'elderward/test-signature', { signature: candidate, path: 'wp-config.php' });
		fail('test-signature read wp-config.php');
	} catch (e) { console.log('wp-config test refused:', e.message.slice(0, 110)); }
	const bad = await ability(srv, 'elderward/test-signature', { signature: Object.assign({}, candidate, { match: [{ regex: '/.*/' }] }) });
	console.log('everything-matching regex:', bad.candidate.problem);
	if (bad.candidate.valid) { fail('a regex matching everything was accepted'); }
	await ability(srv, 'elderward/save-signature', { signature: candidate });
	const sigs = await ability(srv, 'elderward/list-signatures');
	if (!sigs.custom.some((s) => s.id === 'mcp-test')) { fail('saved signature not listed'); }
	await ability(srv, 'elderward/delete-signature', { id: 'mcp-test' });

	console.log('== false positive');
	const target = all.findings.find((f) => f.false_positive === 'no' && f.severity === 'MEDIUM');
	const marked = await ability(srv, 'elderward/mark-false-positive', { id: target.id, note: 'MCP test: known benign' });
	const afterMark = await ability(srv, 'elderward/list-findings', { limit: 200 });
	if (afterMark.findings.some((f) => f.id === target.id)) { fail('marked finding still listed'); }
	const fps = await ability(srv, 'elderward/list-false-positives');
	console.log('false positives saved:', fps.false_positives.length, 'file bound:', marked.file_bound);
	const saved = fps.false_positives.find((f) => f.fingerprint === marked.fingerprint);
	console.log('marked via:', saved && saved.via);
	if (!saved || saved.via !== 'assistant') { fail('assistant mark not recorded as such'); }
	await ability(srv, 'elderward/unmark-false-positive', { fingerprint: marked.fingerprint });
	srv.close();

	console.log('== a subscriber gets nothing');
	const sub = server(process.argv[4] || 'subscriber');
	await initialize(sub);
	try {
		await ability(sub, 'elderward/list-findings', {});
		fail('subscriber could list findings');
	} catch (e) {
		console.log('subscriber refused:', e.message.slice(0, 100));
	}
	sub.close();
	console.log(process.exitCode ? 'FAILED' : 'all good');
})().catch((e) => { console.error(e); process.exit(1); });
