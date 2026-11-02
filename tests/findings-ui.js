/*
 * Playwright check of the false-positive buttons and the sample download.
 * Needs a finished scan with at least one file finding (for example the
 * UPLOADS_PHP fixture from TESTPLAN F).
 *
 *   ELDERWARD_URL=http://127.0.0.1:8089 ELDERWARD_USER=admin ELDERWARD_PASS=adminpass \
 *   node tests/findings-ui.js /path/to/save/downloads
 *
 * 1. Marks the first finding with a sample link as a false positive (with a
 *    note), expects the row to collapse, and after a reload expects it under
 *    the "False positives" view with the note, and gone from "All".
 * 2. Undoes it from the false-positive view.
 * 3. Downloads that finding's sample and saves the zip for the caller to
 *    inspect; a sample link with a broken nonce must get 403.
 */
const { chromium } = require('playwright');
const path = require('path');

const base = process.env.ELDERWARD_URL || 'http://127.0.0.1:8089';
const user = process.env.ELDERWARD_USER || 'admin';
const pass = process.env.ELDERWARD_PASS || 'adminpass';
const outDir = process.argv[2] || '.';
const pageUrl = base + '/wp-admin/tools.php?page=elderward';
const NOTE = 'Reviewed: test fixture <script>alert(1)</script>';

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

async function count(page, label) {
	const text = await page.textContent('.elderward-filters a:has-text("' + label + '") .count');
	return Number(text.replace(/[^0-9]/g, ''));
}

(async () => {
	const browser = await chromium.launch();
	const context = await browser.newContext({ acceptDownloads: true });
	const page = await context.newPage();
	const errors = [];
	page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
	page.on('dialog', async (d) => {
		if (d.type() === 'prompt') { await d.accept(NOTE); } else { await d.accept(); }
	});

	await page.goto(base + '/wp-login.php');
	await page.fill('#user_login', user);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
	await page.waitForURL(/wp-admin/);

	await page.goto(pageUrl);
	const allBefore = await count(page, 'All');
	const fpBefore = await count(page, 'False positives');
	const row = page.locator('.elderward-table tbody tr:has(a:has-text("Download sample"))').first();
	if (await row.count() === 0) { fail('no finding with a sample link'); await browser.close(); return; }
	const id = await row.getAttribute('data-id');
	const fingerprint = await row.getAttribute('data-fingerprint');
	const hash = (await row.locator('.elderward-hash code').textContent()).trim();
	console.log('finding', id, 'sha256', hash, '| All', allBefore, '| FP', fpBefore);

	console.log('== download the sample');
	const [download] = await Promise.all([
		page.waitForEvent('download'),
		row.locator('a:has-text("Download sample")').click(),
	]);
	const zipPath = path.join(outDir, 'sample-' + id + '.zip');
	await download.saveAs(zipPath);
	console.log('saved', zipPath, '(' + download.suggestedFilename() + ')');
	if (!/^elderward-sample-\d+-/.test(download.suggestedFilename())) { fail('unexpected download name'); }
	const href = await row.locator('a:has-text("Download sample")').getAttribute('href');
	const bad = await page.request.get(href.replace(/_wpnonce=[0-9a-f]+/, '_wpnonce=0000000000'));
	console.log('sample link with a bad nonce ->', bad.status());
	if (bad.status() !== 403) { fail('sample with a bad nonce was not refused'); }

	console.log('== mark as false positive');
	await row.locator('[data-fp-action="mark"]').click();
	await page.waitForSelector('tr[data-id="' + id + '"] .elderward-row-message');
	console.log('row:', (await page.textContent('tr[data-id="' + id + '"]')).trim());

	await page.goto(pageUrl);
	const allAfter = await count(page, 'All');
	const fpAfter = await count(page, 'False positives');
	console.log('All', allAfter, '| FP', fpAfter);
	if (allAfter !== allBefore - 1 || fpAfter !== fpBefore + 1) { fail('counts did not move by one'); }
	if (await page.locator('tr[data-id="' + id + '"]').count() !== 0) { fail('marked finding still listed under All'); }

	await page.click('.elderward-filters a:has-text("False positives")');
	// The buttons work once admin.js (in the footer) has run.
	await page.waitForLoadState('load');
	const fpRow = page.locator('.elderward-table tbody tr[data-id="' + id + '"]');
	const why = await fpRow.locator('.elderward-fp-why').textContent();
	console.log('reason shown:', why.trim());
	if (!why.includes('Reviewed: test fixture')) { fail('note not shown'); }
	// The note is sanitized on save and escaped on output: never markup.
	if ((await page.content()).includes('<script>alert(1)')) { fail('note rendered as markup'); }
	const ruleRows = await page.locator('.elderward-fp-rules tbody tr[data-fingerprint="' + fingerprint + '"]').count();
	if (ruleRows !== 1) { fail('rule missing from the saved list'); }

	console.log('== undo from the false-positive view');
	await fpRow.locator('[data-fp-action="unmark"]').click();
	await page.waitForSelector('tr[data-id="' + id + '"] .elderward-row-message');
	await page.goto(pageUrl);
	const allFinal = await count(page, 'All');
	console.log('All', allFinal, '| FP', await count(page, 'False positives'));
	if (allFinal !== allBefore) { fail('finding did not come back after undo'); }

	console.log('page errors:', errors.length ? errors : 'none');
	if (errors.length) { process.exitCode = 1; }
	await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
