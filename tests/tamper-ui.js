/*
 * Playwright check of the tamper notices and their review buttons.
 *
 *   ELDERWARD_URL=http://127.0.0.1:8089 ELDERWARD_USER=admin ELDERWARD_PASS=adminpass \
 *   WP_PATH=/path/to/wordpress WP_CLI="wp --allow-root" node tests/tamper-ui.js
 *
 * Sets up, with WP-CLI: a false positive and two custom signatures saved
 * through Elderward, then (as a database-only attacker would) a false
 * positive injected into the option, one signature disabled, the other
 * deleted, and the scan settings changed. Expects:
 *
 * 1. The Scan tab's error notice lists the three kinds of change.
 * 2. The false-positive list badges the injected rule; Keep trusts it.
 * 3. The Signatures tab badges the disabled one (Keep) and names the
 *    deleted one (Acknowledge).
 * 4. "The scan settings are correct" clears the last item, and with it the
 *    notice.
 * 5. With a self-check summary reporting a changed file, the "own files were
 *    changed" banner shows on every tab.
 *
 * Leaves the site's false positives, signatures and settings as it found them.
 */
const { chromium } = require('playwright');
const { execSync } = require('child_process');

const base = process.env.ELDERWARD_URL || 'http://127.0.0.1:8089';
const user = process.env.ELDERWARD_USER || 'admin';
const pass = process.env.ELDERWARD_PASS || 'adminpass';
const wpPath = process.env.WP_PATH;
const wpCli = process.env.WP_CLI || 'wp';
const pageUrl = base + '/wp-admin/admin.php?page=elderward';
const FP = 'fe' + '0'.repeat(37) + '1'; // a fingerprint is a SHA-1 in hex

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

function wpEval(code) {
	return execSync(wpCli + ' eval "$T_CODE"', { cwd: wpPath, env: Object.assign({}, process.env, { T_CODE: code }), encoding: 'utf8' });
}

const BACKUP = 'echo base64_encode(serialize(array(get_option("elderward_false_positives", null), get_option("elderward_signatures", null), get_option("elderward_settings", null), Elderward_Job::current())));';
function restore(backup) {
	wpEval('$b = unserialize(base64_decode("' + backup + '"));'
		+ 'foreach (array("elderward_false_positives", "elderward_signatures", "elderward_settings") as $i => $o) { if (null === $b[$i]) { delete_option($o); } else { update_option($o, $b[$i], false); } }'
		+ 'if (null !== $b[3]) { update_option("elderward_job", $b[3], false); }'
		+ 'Elderward_Seal::accept();');
}

(async () => {
	if (!wpPath) { fail('set WP_PATH'); return; }
	const backup = wpEval(BACKUP).trim();
	const browser = await chromium.launch();
	const page = await (await browser.newContext()).newPage();
	const errors = [];
	page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
	page.on('dialog', (d) => { if (process.env.DEBUG) { console.log('dialog:', d.type(), d.message()); } d.accept(); });
	try {
		wpEval('Elderward_Seal::accept();'
			+ 'Elderward_Signatures::save(array("id" => "ui-kept", "target" => "file", "severity" => "HIGH", "match" => array(array("string" => "ui_kept_marker"))));'
			+ 'Elderward_Signatures::save(array("id" => "ui-gone", "target" => "file", "severity" => "HIGH", "match" => array(array("string" => "ui_gone_marker"))));'
			+ '$r = get_option("elderward_false_positives"); $r = is_array($r) ? $r : array();'
			+ '$r["' + FP + '"] = array("type" => "UPLOADS_PHP", "severity" => "HIGH", "path" => ABSPATH . "wp-content/uploads/shell.php", "detail" => "PHP file in uploads", "sha256" => null, "note" => "", "user" => 1, "via" => "admin", "time" => time());'
			+ 'update_option("elderward_false_positives", $r, false);'
			+ '$d = array(); foreach (get_option("elderward_signatures") as $s) { if ("ui-gone" === $s["id"]) { continue; } if ("ui-kept" === $s["id"]) { $s["enabled"] = false; } $d[] = $s; } update_option("elderward_signatures", $d, false);'
			+ '$s = get_option("elderward_settings"); $s = is_array($s) ? $s : array(); $s["log"] = "/tmp/ui-attacker"; update_option("elderward_settings", $s, false);');

		await page.goto(base + '/wp-login.php');
		await page.fill('#user_login', user);
		await page.fill('#user_pass', pass);
		await page.click('#wp-submit');
		await page.waitForURL(/wp-admin/);

		// 1. The summary notice.
		await page.goto(pageUrl);
		const items = await page.locator('.notice-error.elderward-tamper .elderward-tamper-list li').count();
		if (items !== 3) { fail('expected 3 tamper items, got ' + items); }

		// 2. The injected false positive.
		await page.goto(pageUrl + '&view=fp');
		const fpRow = page.locator('#elderward-fp-rules tr[data-fingerprint="' + FP + '"]');
		if (!(await fpRow.getAttribute('class') || '').includes('elderward-tampered')) { fail('injected false positive not badged'); }
		await Promise.all([page.waitForNavigation(), fpRow.locator('[data-fp-action="keep"]').click()]);
		if ((await page.locator('#elderward-fp-rules tr[data-fingerprint="' + FP + '"]').getAttribute('class') || '').includes('elderward-tampered')) { fail('kept false positive still badged'); }
		if (await page.locator('.elderward-tamper-list li').count() !== 2) { fail('false-positive item still listed after Keep'); }

		// 3. Signatures.
		await page.goto(pageUrl + '&tab=signatures');
		if (!(await page.textContent('.elderward-tamper.inline')).includes('ui-gone')) { fail('removed signature not named'); }
		const sigRow = page.locator('.elderward-sig-table tr.elderward-tampered:has(code:text-is("ui-kept"))');
		if (await sigRow.count() !== 1) { fail('disabled signature not badged'); }
		await Promise.all([page.waitForNavigation(), sigRow.locator('button:has-text("Keep")').click()]);
		if (await page.locator('.elderward-sig-table tr.elderward-tampered').count() !== 0) { fail('kept signature still badged'); }
		await Promise.all([page.waitForNavigation(), page.locator('.elderward-tamper.inline button:has-text("Acknowledge")').click()]);
		if (await page.locator('.elderward-tamper.inline').count() !== 0) { fail('removed-signature notice still shown'); }

		// 4. Settings.
		await page.goto(pageUrl);
		await Promise.all([page.waitForNavigation(), page.locator('.elderward-tamper-list button:has-text("The scan settings are correct")').click()]);
		if (await page.locator('.notice-error.elderward-tamper:has(.elderward-tamper-list)').count() !== 0) { fail('tamper notice still shown after reviewing everything'); }

		// 5. The self-check banner.
		wpEval('$j = Elderward_Job::current(); if (null === $j) { echo "no job"; } else { $j["summaries"]["self"] = array("MODIFIED" => 1, "MISSING" => 0, "EXTRA" => 0); update_option("elderward_job", $j, false); }');
		for (const tab of ['', '&tab=signatures', '&tab=hardening']) {
			await page.goto(pageUrl + tab);
			const banner = await page.locator('.notice-error.elderward-tamper:has-text("own files were changed")').count();
			if (banner !== 1) { fail('self-check banner missing on tab "' + tab + '"'); }
		}
	} finally {
		await browser.close();
		restore(backup);
	}
	if (errors.length) { fail(errors.join('; ')); }
	console.log(process.exitCode ? 'tamper-ui: failed' : 'tamper-ui: all checks passed');
})();
