/*
 * Playwright check of the tamper notices and their review buttons.
 *
 *   FACHEIRO_URL=http://127.0.0.1:8089 FACHEIRO_USER=admin FACHEIRO_PASS=adminpass \
 *   WP_PATH=/path/to/wordpress WP_CLI="wp --allow-root" node tests/tamper-ui.js
 *
 * Sets up, with WP-CLI: a false positive and two custom signatures saved
 * through Facheiro, then (as a database-only attacker would) a false
 * positive injected into the option, one signature disabled, the other
 * deleted, and the scan settings changed. Expects:
 *
 * 1. The Scan tab's error notice lists the three kinds of change.
 * 2. The false-positive list badges the injected rule; Keep trusts it.
 * 3. The Signatures tab badges the disabled one (Keep) and names the
 *    deleted one (Acknowledge).
 * 4. "The scan settings are correct" clears the last item, and with it the
 *    notice.
 * 5. With a HIGH self-check finding in the current job, the "own files were
 *    changed" banner shows on every tab, and goes once it is marked as a
 *    false positive.
 *
 * Leaves the site's false positives, signatures and settings as it found them.
 */
const { chromium } = require('playwright');
const { execSync } = require('child_process');

const base = process.env.FACHEIRO_URL || 'http://127.0.0.1:8089';
const user = process.env.FACHEIRO_USER || 'admin';
const pass = process.env.FACHEIRO_PASS || 'adminpass';
const wpPath = process.env.WP_PATH;
const wpCli = process.env.WP_CLI || 'wp';
const pageUrl = base + '/wp-admin/admin.php?page=facheiro';
const FP = 'fe' + '0'.repeat(37) + '1'; // a fingerprint is a SHA-1 in hex

function fail(msg) {
	console.error('FAIL: ' + msg);
	process.exitCode = 1;
}

function wpEval(code) {
	return execSync(wpCli + ' eval "$T_CODE"', { cwd: wpPath, env: Object.assign({}, process.env, { T_CODE: code }), encoding: 'utf8' });
}

const BACKUP = 'echo base64_encode(serialize(array(get_option("facheiro_false_positives", null), get_option("facheiro_signatures", null), get_option("facheiro_settings", null), Facheiro_Job::current())));';
function restore(backup) {
	wpEval('$b = unserialize(base64_decode("' + backup + '"));'
		+ 'foreach (array("facheiro_false_positives", "facheiro_signatures", "facheiro_settings") as $i => $o) { if (null === $b[$i]) { delete_option($o); } else { update_option($o, $b[$i], false); } }'
		+ 'if (null !== $b[3]) { update_option("facheiro_job", $b[3], false); }'
		+ 'Facheiro_Seal::accept();');
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
		wpEval('Facheiro_Seal::accept();'
			+ 'Facheiro_Signatures::save(array("id" => "ui-kept", "target" => "file", "severity" => "HIGH", "match" => array(array("string" => "ui_kept_marker"))));'
			+ 'Facheiro_Signatures::save(array("id" => "ui-gone", "target" => "file", "severity" => "HIGH", "match" => array(array("string" => "ui_gone_marker"))));'
			+ '$r = get_option("facheiro_false_positives"); $r = is_array($r) ? $r : array();'
			+ '$r["' + FP + '"] = array("type" => "UPLOADS_PHP", "severity" => "HIGH", "path" => ABSPATH . "wp-content/uploads/shell.php", "detail" => "PHP file in uploads", "sha256" => null, "note" => "", "user" => 1, "via" => "admin", "time" => time());'
			+ 'update_option("facheiro_false_positives", $r, false);'
			+ '$d = array(); foreach (get_option("facheiro_signatures") as $s) { if ("ui-gone" === $s["id"]) { continue; } if ("ui-kept" === $s["id"]) { $s["enabled"] = false; } $d[] = $s; } update_option("facheiro_signatures", $d, false);'
			+ '$s = get_option("facheiro_settings"); $s = is_array($s) ? $s : array(); $s["log"] = "/tmp/ui-attacker"; update_option("facheiro_settings", $s, false);');

		await page.goto(base + '/wp-login.php');
		await page.fill('#user_login', user);
		await page.fill('#user_pass', pass);
		await page.click('#wp-submit');
		await page.waitForURL(/wp-admin/);

		// 1. The summary notice.
		await page.goto(pageUrl);
		const items = await page.locator('.notice-error.facheiro-tamper .facheiro-tamper-list li').count();
		if (items !== 3) { fail('expected 3 tamper items, got ' + items); }

		// 2. The injected false positive.
		await page.goto(pageUrl + '&view=fp');
		const fpRow = page.locator('#facheiro-fp-rules tr[data-fingerprint="' + FP + '"]');
		if (!(await fpRow.getAttribute('class') || '').includes('facheiro-tampered')) { fail('injected false positive not badged'); }
		await Promise.all([page.waitForNavigation(), fpRow.locator('[data-fp-action="keep"]').click()]);
		if ((await page.locator('#facheiro-fp-rules tr[data-fingerprint="' + FP + '"]').getAttribute('class') || '').includes('facheiro-tampered')) { fail('kept false positive still badged'); }
		if (await page.locator('.facheiro-tamper-list li').count() !== 2) { fail('false-positive item still listed after Keep'); }

		// 3. Signatures.
		await page.goto(pageUrl + '&tab=signatures');
		if (!(await page.textContent('.facheiro-tamper.inline')).includes('ui-gone')) { fail('removed signature not named'); }
		const sigRow = page.locator('.facheiro-sig-table tr.facheiro-tampered:has(code:text-is("ui-kept"))');
		if (await sigRow.count() !== 1) { fail('disabled signature not badged'); }
		await Promise.all([page.waitForNavigation(), sigRow.locator('button:has-text("Keep")').click()]);
		if (await page.locator('.facheiro-sig-table tr.facheiro-tampered').count() !== 0) { fail('kept signature still badged'); }
		await Promise.all([page.waitForNavigation(), page.locator('.facheiro-tamper.inline button:has-text("Acknowledge")').click()]);
		if (await page.locator('.facheiro-tamper.inline').count() !== 0) { fail('removed-signature notice still shown'); }

		// 4. Settings.
		await page.goto(pageUrl);
		await Promise.all([page.waitForNavigation(), page.locator('.facheiro-tamper-list button:has-text("The scan settings are correct")').click()]);
		if (await page.locator('.notice-error.facheiro-tamper:has(.facheiro-tamper-list)').count() !== 0) { fail('tamper notice still shown after reviewing everything'); }

		// 5. The self-check banner.
		// A HIGH self-check finding in the current job shows the banner;
		// marked as a false positive, it no longer does.
		wpEval('global $wpdb; $j = Facheiro_Job::current(); if (null === $j) { echo "no job"; return; }'
			+ '$j["summaries"]["self"] = array("MODIFIED" => 1, "MISSING" => 0, "EXTRA" => 0); update_option("facheiro_job", $j, false);'
			+ '$wpdb->insert(Facheiro_Plugin::findings_table(), array("job_id" => $j["id"], "severity" => "HIGH", "type" => "INTEGRITY_MODIFIED", "path" => realpath(FACHEIRO_DIR) . "/includes/ui-test.php", "detail" => "ui test", "fingerprint" => "ui-test", "fp" => 0, "created" => gmdate("Y-m-d H:i:s")));');
		for (const tab of ['', '&tab=signatures', '&tab=hardening']) {
			await page.goto(pageUrl + tab);
			const banner = await page.locator('.notice-error.facheiro-tamper:has-text("own files were changed")').count();
			if (banner !== 1) { fail('self-check banner missing on tab "' + tab + '"'); }
		}
		wpEval('global $wpdb; $wpdb->update(Facheiro_Plugin::findings_table(), array("fp" => Facheiro_False_Positives::MATCHED), array("fingerprint" => "ui-test"));');
		await page.goto(pageUrl);
		if (await page.locator('.notice-error.facheiro-tamper:has-text("own files were changed")').count() !== 0) { fail('banner still shown after the finding was marked as a false positive'); }
	} finally {
		await browser.close();
		wpEval('global $wpdb; $wpdb->delete(Facheiro_Plugin::findings_table(), array("fingerprint" => "ui-test"));');
		restore(backup);
	}
	if (errors.length) { fail(errors.join('; ')); }
	console.log(process.exitCode ? 'tamper-ui: failed' : 'tamper-ui: all checks passed');
})();
