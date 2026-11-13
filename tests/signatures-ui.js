/*
 * Playwright check of the signature editor (Facheiro > Signatures).
 *
 *   FACHEIRO_URL=http://127.0.0.1:8089 FACHEIRO_USER=admin FACHEIRO_PASS=adminpass \
 *   node tests/signatures-ui.js <fixture path relative to the WordPress root>
 *
 * The fixture must contain "acme_loader" and "eval($". Steps: a bad regex is
 * refused with the form kept; a valid signature is added; the tester matches
 * the fixture by path and a pasted sample, refuses wp-config.php; disable/enable; export; import
 * of a second signature; delete. Leaves the "acme-loader" signature in place
 * so a following scan can be checked for SIGNATURE_MATCH.
 */
const { chromium } = require('playwright');

const base = process.env.FACHEIRO_URL || 'http://127.0.0.1:8089';
const user = process.env.FACHEIRO_USER || 'admin';
const pass = process.env.FACHEIRO_PASS || 'adminpass';
const fixture = process.argv[2] || 'wp-content/plugins/acme/loader.php';
const tabUrl = base + '/wp-admin/admin.php?page=facheiro&tab=signatures';

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

async function notices(page) {
	return page.$$eval('.notice', (els) => els.map((el) => el.className.replace(/.*notice-(\w+).*/, '$1') + ': ' + el.textContent.trim()));
}

async function fillForm(page, values) {
	await page.fill('#facheiro-sig-id', values.id);
	await page.selectOption('#facheiro-sig-target', values.target);
	await page.selectOption('#facheiro-sig-severity', values.severity);
	await page.fill('#facheiro-sig-description', values.description);
	await page.fill('#facheiro-sig-conditions', values.conditions);
	await page.click('#facheiro-sig-form input[type="submit"]');
	await page.waitForURL(/tab=signatures/);
}

async function runTest(page, fields) {
	await page.fill('#facheiro-test-path', fields.path || '');
	await page.fill('#facheiro-test-text', fields.text || '');
	await page.click('#facheiro-test-run');
	await page.waitForFunction(() => document.getElementById('facheiro-test-result').textContent.trim() !== '');
	return (await page.textContent('#facheiro-test-result')).trim();
}

(async () => {
	const browser = await chromium.launch();
	const context = await browser.newContext({ acceptDownloads: true });
	const page = await context.newPage();
	const errors = [];
	page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
	page.on('dialog', (d) => d.accept());

	await page.goto(base + '/wp-login.php');
	await page.fill('#user_login', user);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
	await page.waitForURL(/wp-admin/);
	await page.goto(tabUrl);
	if (!(await page.textContent('.nav-tab-active')).includes('Signatures')) { fail('signatures tab not active'); }
	// A previous run leaves acme-loader in place on purpose; start clean.
	if (await page.$('.facheiro-sig-table tr:has-text("acme-loader") button:has-text("Delete")')) {
		await page.click('.facheiro-sig-table tr:has-text("acme-loader") button:has-text("Delete")');
		await page.waitForURL(/tab=signatures/);
	}

	console.log('== bad regex is refused, form keeps the input');
	await fillForm(page, { id: 'acme-loader', target: 'file', severity: 'medium', description: 'ACME loader backdoor', conditions: 'text: acme_loader\nregex: /eval\\s*\\(/' + '[' });
	let n = await notices(page);
	console.log(n);
	if (!n.some((x) => /^error:.*does not compile/.test(x))) { fail('no compile error notice'); }
	if ((await page.inputValue('#facheiro-sig-conditions')).indexOf('acme_loader') === -1) { fail('form lost the input'); }

	console.log('== add a valid signature');
	await fillForm(page, { id: 'acme-loader', target: 'file', severity: 'medium', description: 'ACME loader backdoor', conditions: 'text: acme_loader\nregex: /eval\\s*\\(\\s*\\$/' });
	n = await notices(page);
	console.log(n);
	if (!n.some((x) => /^success:.*acme-loader saved/.test(x))) { fail('no saved notice'); }
	const listed = await page.textContent('.facheiro-sig-table');
	if (!/acme-loader/.test(listed) || !/regex: \/eval/.test(listed)) { fail('signature not listed'); }

	console.log('== tester');
	let out = await runTest(page, { path: fixture });
	console.log('path:', out.replace(/\s+/g, ' '));
	if (!/custom\.acme-loader/.test(out)) { fail('tester did not match the fixture file'); }
	out = await runTest(page, { text: '<?php // acme_loader\n eval($_POST[1]);' });
	console.log('text:', out.replace(/\s+/g, ' '));
	if (!/custom\.acme-loader/.test(out) || !/db\.post\.js-obfuscation/.test(out)) { fail('tester did not match the pasted sample'); }
	out = await runTest(page, { text: 'harmless text' });
	if (!/No signature matches/.test(out)) { fail('tester matched harmless text'); }
	out = await runTest(page, { path: '../../../../etc/passwd' });
	console.log('outside root:', out);
	if (!/inside the WordPress folder/.test(out)) { fail('tester read a file outside the root'); }
	out = await runTest(page, { path: 'wp-config.php' });
	console.log('wp-config:', out);
	if (!/wp-config files/.test(out)) { fail('tester read wp-config.php'); }

	console.log('== disable, enable');
	await page.click('.facheiro-sig-table tr:has-text("acme-loader") button:has-text("Disable")');
	await page.waitForURL(/tab=signatures/);
	if (!/disabled/.test(await page.textContent('.facheiro-sig-table tr:has-text("acme-loader")'))) { fail('not shown as disabled'); }
	await page.click('.facheiro-sig-table tr:has-text("acme-loader") button:has-text("Enable")');
	await page.waitForURL(/tab=signatures/);

	console.log('== import a second signature, export, delete it');
	await page.fill('#facheiro-sig-import', JSON.stringify({ facheiro_signatures: 1, signatures: [{ id: 'spam-casino', target: 'db_post', severity: 'LOW', description: 'Casino spam links', pattern: '@casino-bonus\\.example@i' }] }));
	await page.click('form:has(#facheiro-sig-import) input[type="submit"]');
	await page.waitForURL(/tab=signatures/);
	n = await notices(page);
	console.log(n);
	if (!n.some((x) => /^success:.*1 signature imported/.test(x))) { fail('import failed'); }
	const [download] = await Promise.all([page.waitForEvent('download'), page.click('a:has-text("Export custom signatures")')]);
	const exported = JSON.parse(require('fs').readFileSync(await download.path(), 'utf8'));
	console.log('exported ids:', exported.signatures.map((s) => s.id).join(', '));
	if (exported.signatures.length !== 2) { fail('export does not list both signatures'); }
	await page.click('.facheiro-sig-table tr:has-text("spam-casino") button:has-text("Delete")');
	await page.waitForURL(/tab=signatures/);
	if (/spam-casino/.test(await page.textContent('.facheiro-sig-table'))) { fail('delete did not remove it'); }

	console.log('== nonce and capability');
	const anon = await (await browser.newContext()).request.post(base + '/wp-admin/admin-post.php', { form: { action: 'facheiro_signature', op: 'delete', id: 'acme-loader' }, maxRedirects: 0 });
	console.log('anonymous delete -> HTTP', anon.status());
	await page.goto(tabUrl);
	if (!/acme-loader/.test(await page.textContent('.facheiro-sig-table'))) { fail('anonymous request deleted the signature'); }

	console.log('page errors:', errors.length ? errors : 'none');
	if (errors.length) { process.exitCode = 1; }
	await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
