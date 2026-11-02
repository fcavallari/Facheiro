/*
 * Playwright check of the runner setting and the scan schedule.
 *
 *   ELDERWARD_URL=http://127.0.0.1:8089 ELDERWARD_USER=admin ELDERWARD_PASS=adminpass \
 *   node tests/background-ui.js [--stale]
 *
 * 1. Saves the settings (background runner, weekly schedule) and checks the
 *    notice and the "Next scan" text.
 * 2. Starts a scan in background mode, leaves the page at once, comes back
 *    later and expects the scan to have finished without this tab sending
 *    a single elderward_step request.
 * 3. Switches to the browser runner and expects the tab to do the stepping.
 * 4. With --stale (and elderward_test_no_loopback set on the site): starts a
 *    background scan that WP-Cron can never pick up and expects the page to
 *    take over after the stale timeout and finish the scan.
 */
const { chromium } = require('playwright');

const base = process.env.ELDERWARD_URL || 'http://127.0.0.1:8089';
const user = process.env.ELDERWARD_USER || 'admin';
const pass = process.env.ELDERWARD_PASS || 'adminpass';
const stale = process.argv.includes('--stale');
const pageUrl = base + '/wp-admin/admin.php?page=elderward';

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

async function saveSettings(page, values) {
	await page.goto(pageUrl + '&tab=settings');
	await page.check('input[name="elderward[runner]"][value="' + values.runner + '"]');
	await page.selectOption('#elderward-schedule', values.schedule);
	if (values.schedule !== 'off') {
		await page.fill('#elderward-time', values.time);
		if (values.schedule === 'weekly') {
			await page.selectOption('#elderward-day', String(values.day));
		}
	}
	await page.fill('#elderward-settings-log', values.log || '');
	await page.click('.elderward-settings #submit');
	await page.waitForURL(/page=elderward&tab=settings/);
	const notices = await page.$$eval('.notice', (els) => els.map((el) => el.className.replace(/\s+/g, ' ') + ': ' + el.textContent.trim()));
	return notices;
}

async function waitForEnd(page, timeout) {
	await page.waitForFunction(() => {
		const el = document.getElementById('elderward-status-text');
		return el && /complete|failed|cancelled/i.test(el.textContent);
	}, null, { timeout: timeout });
	await page.waitForLoadState('load');
	await page.waitForTimeout(1500);
}

(async () => {
	const browser = await chromium.launch();
	const page = await browser.newPage();
	const errors = [];
	const ajax = { step: 0, status: 0, kick: 0 };
	page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
	page.on('console', (m) => { if (m.type() === 'error' && /elderward/.test(m.text())) { errors.push('console: ' + m.text()); } });
	page.on('request', (r) => {
		if (r.method() !== 'POST' || !/admin-ajax\.php/.test(r.url())) { return; }
		const body = r.postData() || '';
		if (/elderward_step/.test(body)) { ajax.step++; }
		if (/elderward_status/.test(body)) { ajax.status++; }
		if (/elderward_kick/.test(body)) { ajax.kick++; }
	});

	await page.goto(base + '/wp-login.php');
	await page.fill('#user_login', user);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
	await page.waitForURL(/wp-admin/);

	if (stale) {
		console.log('== stale background runner (loopback blocked): start, wait for the takeover');
		const staleNotices = await saveSettings(page, { runner: 'background', schedule: 'off' });
		console.log('notices:', staleNotices);
		if (!staleNotices.some((n) => /notice-warning/.test(n) && /could not reach its own wp-cron\.php/.test(n))) { fail('no loopback warning when saving with the loopback blocked'); }
		await page.goto(pageUrl);
		await page.click('#elderward-start');
		await page.waitForSelector('#elderward-progress:not([hidden])');
		const t0 = Date.now();
		await page.waitForFunction(() => /continues from this tab/.test(document.getElementById('elderward-runner-note').textContent), null, { timeout: 300000 });
		console.log('takeover after', Math.round((Date.now() - t0) / 1000), 's; kicks sent:', ajax.kick);
		await waitForEnd(page, 600000);
		await page.goto(pageUrl);
		console.log('status line:', (await page.textContent('.elderward-last')).trim().replace(/\s+/g, ' '));
		if (ajax.kick < 1) { fail('no kick request was sent'); }
		if (ajax.step < 1) { fail('the page never took over stepping'); }
		console.log('page errors:', errors.length ? errors : 'none');
		await browser.close();
		return;
	}

	console.log('== settings: background runner, weekly schedule');
	const notices = await saveSettings(page, { runner: 'background', schedule: 'weekly', time: '03:30', day: 1, log: process.env.ELDERWARD_LOG || '' });
	console.log('notices:', notices);
	if (!notices.some((n) => /notice-success/.test(n) && /Settings saved/.test(n))) { fail('no success notice after saving'); }
	if (notices.some((n) => /notice-warning/.test(n))) { fail('unexpected warning after saving'); }
	const schedText = await page.textContent('#elderward-schedule + .elderward-schedule-when + .description');
	console.log('schedule text:', schedText.trim().replace(/\s+/g, ' '));
	if (!/Next scan:/.test(schedText)) { fail('no "Next scan" after enabling the schedule'); }
	const dayHidden = await page.$eval('.elderward-schedule-day', (el) => el.hidden);
	if (dayHidden) { fail('weekday field hidden for a weekly schedule'); }

	console.log('== background scan: start, leave the page, come back');
	ajax.step = 0; ajax.status = 0;
	await page.goto(pageUrl);
	await page.click('#elderward-start');
	await page.waitForSelector('#elderward-progress:not([hidden])');
	await page.waitForFunction(() => document.getElementById('elderward-runner-note').textContent.trim() !== '');
	const note = await page.textContent('#elderward-runner-note');
	console.log('runner note:', note.trim());
	if (!/background/.test(note)) { fail('background note missing'); }
	await page.goto(base + '/wp-admin/index.php');
	const stepsWhileOnPage = ajax.step;
	for (let i = 0; i < 60; i++) {
		await page.waitForTimeout(3000);
		// Read the page over fetch: no Elderward script runs, so nothing
		// here can step the job.
		const done = await page.evaluate(async (u) => {
			const html = await (await fetch(u, { credentials: 'same-origin' })).text();
			return /Last scan: <strong>(complete|failed|cancelled)/.test(html);
		}, pageUrl);
		if (done) { console.log('finished while away after ~' + ((i + 1) * 3) + ' s'); break; }
	}
	await page.goto(pageUrl);
	const line = (await page.textContent('.elderward-last')).trim().replace(/\s+/g, ' ');
	console.log('status line:', line);
	if (!/complete/.test(line)) { fail('background scan did not complete while the page was closed'); }
	if (stepsWhileOnPage > 0 || ajax.step > 0) { fail('the page sent elderward_step requests in background mode (' + ajax.step + ')'); }
	console.log('elderward_step requests from the tab:', ajax.step, '| status polls:', ajax.status);

	console.log('== browser runner: the tab steps the job');
	await saveSettings(page, { runner: 'browser', schedule: 'off' });
	const schedHidden = await page.$eval('.elderward-schedule-when', (el) => el.hidden);
	if (!schedHidden) { fail('time field shown with the schedule off'); }
	ajax.step = 0;
	await page.goto(pageUrl);
	await page.click('#elderward-start');
	await page.waitForSelector('#elderward-progress:not([hidden])');
	await page.waitForFunction(() => document.getElementById('elderward-runner-note').textContent.trim() !== '');
	const note2 = await page.textContent('#elderward-runner-note');
	console.log('runner note:', note2.trim());
	if (!/Keep this page open/.test(note2)) { fail('browser-mode note missing'); }
	await waitForEnd(page, 600000);
	await page.goto(pageUrl);
	console.log('status line:', (await page.textContent('.elderward-last')).trim().replace(/\s+/g, ' '));
	console.log('elderward_step requests from the tab:', ajax.step);
	if (ajax.step < 1) { fail('browser mode sent no step requests'); }

	await saveSettings(page, { runner: 'background', schedule: 'off' });
	console.log('page errors:', errors.length ? errors : 'none');
	await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
