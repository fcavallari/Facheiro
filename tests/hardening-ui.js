/*
 * Playwright check of the Hardening tab. Needs a site served by Apache (or
 * LiteSpeed) with AllowOverride All, since the rules are .htaccess files:
 *
 *   FACHEIRO_URL=http://127.0.0.1:8090 FACHEIRO_USER=admin FACHEIRO_PASS=adminpass \
 *   node tests/hardening-ui.js
 *
 * Steps: Recommended template applied from the page; "Check now" reports
 * every Recommended protection as protected and a PHP request in uploads
 * gets 403; the Nginx file downloads with the matching locations; Remove
 * takes the rules out and the uploads protection reports "Not protected".
 */
const { chromium } = require('playwright');

const base = process.env.FACHEIRO_URL || 'http://127.0.0.1:8090';
const user = process.env.FACHEIRO_USER || 'admin';
const pass = process.env.FACHEIRO_PASS || 'adminpass';
const tabUrl = base + '/wp-admin/admin.php?page=facheiro&tab=hardening';
const recommended = ['uploads_php', 'core_includes', 'config', 'sensitive', 'dotfiles', 'indexes'];

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

async function notices(page) {
	return page.$$eval('.notice', (els) => els.map((el) => el.className.replace(/.*notice-(\w+).*/, '$1') + ': ' + el.textContent.trim()));
}

async function check(page) {
	await page.click('#facheiro-harden-check-run');
	await page.waitForFunction(() => /just now/.test(document.getElementById('facheiro-harden-check-when').textContent), null, { timeout: 120000 });
	return page.$$eval('.facheiro-check[data-feature]', (els) => Object.fromEntries(els.map((el) => [el.getAttribute('data-feature'), el.className.replace(/.*facheiro-check-(\w+).*/, '$1')])));
}

(async () => {
	const browser = await chromium.launch();
	const context = await browser.newContext({ acceptDownloads: true });
	const page = await context.newPage();
	const errors = [];
	page.on('pageerror', (e) => errors.push(e.message));
	page.on('dialog', (d) => d.accept());

	await page.goto(base + '/wp-login.php');
	await page.fill('#user_login', user);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
	await page.waitForURL(/wp-admin/);
	await page.goto(tabUrl);

	console.log('== apply Recommended (Apache)');
	await page.click('label.facheiro-choice:has-text("Apache")');
	await page.click('label.facheiro-choice:has-text("Recommended")');
	await page.waitForSelector('#facheiro-harden-preview pre');
	const files = await page.$$eval('.facheiro-preview-file', (n) => n.map((x) => x.textContent.trim()));
	console.log('preview files:', files.join(', '));
	if (!files.includes('wp-content/uploads/.htaccess')) { fail('preview does not list the uploads .htaccess'); }
	await Promise.all([page.waitForURL(/tab=hardening/), page.click('button[value="apply"]')]);
	let n = await notices(page);
	console.log(n);
	if (!n.some((x) => /^success:.*Protections applied/.test(x))) { fail('no success notice after applying'); }

	console.log('== check now');
	let status = await check(page);
	console.log(status);
	recommended.forEach((id) => { if (status[id] !== 'protected') { fail(id + ' is ' + status[id] + ' after applying'); } });
	const probe = await context.request.get(base + '/wp-content/uploads/facheiro-ui-probe.php', { maxRedirects: 0 });
	console.log('PHP request in uploads -> HTTP', probe.status());
	if (probe.status() !== 403) { fail('PHP in uploads not refused'); }

	console.log('== Nginx download');
	await page.click('label.facheiro-choice:has-text("Nginx")');
	const [download] = await Promise.all([page.waitForEvent('download'), page.click('button[value="download"]')]);
	const conf = require('fs').readFileSync(await download.path(), 'utf8');
	console.log('nginx file:', conf.split('\n').filter((l) => /^location|^autoindex/.test(l)).length, 'rules');
	if (!/location ~\* \^\/wp\\-content\/uploads\//.test(conf)) { fail('nginx file lacks the uploads rule'); }

	console.log('== remove');
	await page.goto(tabUrl);
	await page.click('label.facheiro-choice:has-text("Apache")');
	await Promise.all([page.waitForURL(/tab=hardening/), page.click('button[value="remove"]')]);
	n = await notices(page);
	console.log(n);
	if (!n.some((x) => /^success:.*rules removed/.test(x))) { fail('no success notice after removing'); }
	status = await check(page);
	if (status.uploads_php !== 'exposed') { fail('uploads still protected after removing: ' + status.uploads_php); }

	console.log('page errors:', errors.length ? errors : 'none');
	if (errors.length) { process.exitCode = 1; }
	console.log(process.exitCode ? 'FAILED' : 'all good');
	await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
