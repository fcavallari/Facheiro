/*
 * Playwright check of recovery mode, end to end:
 *
 *   ELDERWARD_URL=http://127.0.0.1:8090 ELDERWARD_USER=admin ELDERWARD_PASS=adminpass \
 *   node tests/recovery.js [path/to/wordpress]
 *
 * Creates a key on the Recovery tab (shown once), then - with WordPress
 * broken by a must-use plugin with a syntax error, when the WordPress path
 * is given - signs in to recovery.php, checks that "What broke the site"
 * names that file, runs the scan to the end, exports it, signs out, and
 * finally repairs the site and revokes the key (recovery.php -> 404).
 */
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const base = process.env.ELDERWARD_URL || 'http://127.0.0.1:8090';
const user = process.env.ELDERWARD_USER || 'admin';
const pass = process.env.ELDERWARD_PASS || 'adminpass';
const wpRoot = process.argv[2] || '';
const recoveryUrl = base + '/wp-content/plugins/elderward/recovery.php';
const broken = wpRoot ? path.join(wpRoot, 'wp-content/mu-plugins/zz-elderward-test-broken.php') : '';

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

async function adminLogin(page) {
	await page.goto(base + '/wp-login.php');
	await page.fill('#user_login', user);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
	await page.waitForURL(/wp-admin/);
}

(async () => {
	const browser = await chromium.launch();
	const context = await browser.newContext({ acceptDownloads: true });
	const page = await context.newPage();
	const errors = [];
	page.on('pageerror', (e) => errors.push(e.message));
	page.on('dialog', (d) => d.accept());

	console.log('== no key: 404');
	await adminLogin(page);
	await page.goto(base + '/wp-admin/admin.php?page=elderward&tab=recovery');
	if (await page.$('button[value="revoke"]')) {
		await Promise.all([page.waitForURL(/tab=recovery/), page.click('button[value="revoke"]')]);
	}
	let res = await context.request.get(recoveryUrl);
	console.log('recovery.php ->', res.status());
	if (res.status() !== 404) { fail('recovery page answers without a key'); }

	console.log('== create a key on the Recovery tab');
	await Promise.all([page.waitForURL(/tab=recovery/), page.click('button[value="create"]')]);
	const key = await page.inputValue('#elderward-recovery-key');
	console.log('key length', key.length, '| status:', (await page.textContent('.elderward-card-head .elderward-check')).trim());
	if (key.length !== 32) { fail('no 32-character key shown'); }
	await page.reload();
	if (await page.$('#elderward-recovery-key')) { fail('key shown a second time'); }

	if (broken) {
		fs.mkdirSync(path.dirname(broken), { recursive: true });
		fs.writeFileSync(broken, '<?php\nfunction elderward_test_broken( {\n');
		res = await context.request.get(base + '/');
		console.log('site with the broken mu-plugin ->', res.status());
	}

	console.log('== recovery page');
	const rec = await (await browser.newContext({ acceptDownloads: true })).newPage();
	await rec.goto(recoveryUrl);
	await rec.fill('#key', key);
	await rec.click('button[type=submit]');
	await rec.waitForSelector('#scan');
	if (broken) {
		const broke = await rec.textContent('section.card:has(h2:has-text("What broke"))');
		console.log('names the broken file:', /zz-elderward-test-broken\.php/.test(broke));
		if (!/zz-elderward-test-broken\.php/.test(broke)) { fail('"What broke the site" does not name the broken file'); }
	}
	// Results of an earlier scan may already be on the page: wait for the
	// reload that ends this one.
	const before = (await rec.$('.last')) ? (await rec.textContent('.last')) : '';
	const startedAt = Date.now();
	await rec.click('#start');
	await rec.waitForFunction((old) => {
		const last = document.querySelector('.last');
		return last && last.textContent !== old && document.getElementById('progress').hidden;
	}, before, { timeout: 600000 }).catch(async () => {
		// Same minute as the earlier scan: fall back to waiting for the reload.
		await rec.waitForLoadState('load');
	});
	await rec.waitForSelector('#progress[hidden]', { state: 'attached', timeout: 600000 });
	console.log('scan took', Math.round((Date.now() - startedAt) / 1000), 's');
	console.log((await rec.textContent('.last')).trim(), '|', (await rec.textContent('.counts')).replace(/\s+/g, ' ').trim());
	if (!/complete/.test(await rec.textContent('.last'))) { fail('scan did not complete'); }
	const rows = await rec.$$eval('table tbody tr', (trs) => trs.length);
	const [download] = await Promise.all([rec.waitForEvent('download'), rec.click('a:has-text("Export JSON")')]);
	const lines = fs.readFileSync(await download.path(), 'utf8').trim().split('\n').filter(Boolean);
	console.log('rows', rows, '| export lines', lines.length);
	if (rows !== lines.length) { fail('table and export differ'); }
	await rec.click('.signout button');
	await rec.waitForSelector('#key');

	console.log('== repair and revoke');
	if (broken) {
		fs.unlinkSync(broken);
	}
	await page.goto(base + '/wp-admin/admin.php?page=elderward&tab=recovery');
	await Promise.all([page.waitForURL(/tab=recovery/), page.click('button[value="revoke"]')]);
	res = await context.request.get(recoveryUrl);
	console.log('recovery.php after revoke ->', res.status());
	if (res.status() !== 404) { fail('recovery page still answers after revoke'); }

	console.log('page errors:', errors.length ? errors : 'none');
	if (errors.length) { process.exitCode = 1; }
	console.log(process.exitCode ? 'FAILED' : 'all good');
	await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
