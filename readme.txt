=== Elderward ===
Contributors: fioa8c
Tags: malware, security, scanner, integrity, incident response
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Malware scanner and incident-response toolkit: file signatures, core/plugin/theme integrity, database, crontab and access-log checks.

== Description ==

Elderward helps you find out whether a WordPress site has been compromised, how, and what to do about it. It was written for incident responders and runs entirely on your own server: there is no account, no external service and no data leaves the site.

**One report-only scan from Tools > Elderward** runs every check and lists the findings worst-first:

* **Quick checks** - executable PHP inside `wp-content/uploads`, `auto_prepend_file`/`auto_append_file` directives in `.user.ini`, `php.ini` and `.htaccess` (code that runs on every request), an inventory of must-use plugins, hidden dotfile PHP.
* **Integrity** - WordPress core, every plugin and every theme compared with the official wordpress.org packages for the installed version: modified files, missing files, and extra files that the package does not contain (extra PHP inside core or a plugin is the classic dropped webshell). Packages that cannot be verified, such as premium plugins or child themes, are reported as such so a clean report never silently means "unchecked".
* **Timestamps** - files modified apart from the rest of their package, and files whose modification time looks back-dated. Report-only leads, never proof.
* **Crontab** - the current user's crontab checked for known persistence patterns.
* **Database** - read-only: an inventory of administrator accounts with recently created ones highlighted, non-administrator roles that were granted takeover capabilities, PHP or hidden iframes or obfuscated JavaScript in options and posts, `siteurl`/`home` hijacks, and `active_plugins` tampering. Values are pattern-matched only and never unserialized.
* **Access logs** (optional) - point it at an access log file or directory (rotated `.log.N` and `.gz` files included) to see known attack traffic: webshell requests, exploit attempts against known-vulnerable plugins, `.env` probes, code injection, brute force floods. Files modified within minutes of flagged requests are linked to that traffic.
* **Malware signatures** - signature-based detection of known injections such as the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns, run in dry-run mode from the admin page.

Anything that blocks a check - an unreadable file, a failed query, a missing PHP extension - is itself reported as an `ERROR` finding, never skipped. A clean report means every scanner actually looked.

**Scans run in the background** through WP-Cron, so you can start one and close the tab; the page shows the progress whenever you come back. A setting switches to running the steps from the browser tab instead, for hosts where WP-Cron is unreliable. **Scheduled scans** (daily, twice daily or weekly at a time you choose) run the same report-only scan automatically.

**Review the findings in place.** Mark a finding as a **false positive** with a note and later scans hide it, while still keeping it in the record. For a file, the mark only holds while the file is byte-for-byte the one you reviewed, so an attacker cannot hide behind a file you once cleared. **Download sample** packs a flagged file into a zip encrypted with the password `infected`, with a manifest, for you to send to a malware analyst or sandbox. Elderward never uploads anything itself.

**Write your own signatures** on the Signatures tab: exact text or regular expressions for files, option values or post content. Test them against a pasted sample or a file of the site before saving, and export them as JSON for other sites or the standalone scanner. Custom signatures only detect; they never clean.

**Work with an AI assistant.** On WordPress 6.9 or later, Elderward registers its scan, findings, signature and false-positive tools as WordPress abilities. With the official MCP Adapter plugin, Claude, ChatGPT, Antigravity, Cursor or any other MCP client can run scans, explain the findings, read flagged files, and draft and test signatures with you. Everything scanned is labelled as untrusted data for the assistant, and it has no tool that cleans or changes files. Without MCP, the AI assistants tab gives you a ready-made brief to paste into any chatbot.

**Cleanup and restore run from the command line**, where you can take a backup first and preview with a dry run:

* `wp elderward scan --dryrun` then `wp elderward scan` removes known malware from infected files (atomic write, never truncates the original).
* `wp elderward integrity --restore --dryrun` then `wp elderward integrity --restore --quarantine-dir=/path/outside/webroot` restores modified or missing core, plugin and theme files from the official packages. Every file is byte-verified against the reference checksum before it is written; extra files are never deleted.

The same scanners are available as WP-CLI commands (`wp elderward scanall`, `quick`, `integrity`, `times`, `db`, `cron`, `log`) with text or NDJSON output and exit codes that CI and cron jobs can alert on, and as a standalone PHP script (`php bin/elderward.php`, inside the plugin folder) for a site too broken to load WordPress.

Development happens at [github.com/fioa8c/elderward](https://github.com/fioa8c/elderward); the source in this directory is the complete, unminified source.

== Installation ==

1. Upload the `elderward` folder to `/wp-content/plugins/`, or install it from the Plugins screen.
2. Activate the plugin. It creates one database table (`{prefix}elderward_findings`) to hold the latest report.
3. Open **Tools > Elderward** (Network Admin > Settings > Elderward on multisite) and click **Start scan**. The scan continues in the background; the page shows its progress and reloads with the findings when it ends.
4. Under **Settings** on the same page, choose how scans run (background through WP-Cron, or from the browser tab) and, if you want, a schedule.
5. To act on the findings, use the WP-CLI commands shown under the results, after taking a backup.
6. Optional: to use an AI assistant, install the MCP Adapter plugin and follow the steps on the **AI assistants** tab.

== Frequently Asked Questions ==

= Does the scan keep running if I close the page? =

Yes, with the default setting. The scan is a chain of short WP-Cron jobs; the page only watches it. WP-Cron needs the site to be able to request its own `wp-cron.php` (Site Health reports a failing "loopback request" when it cannot) or a server cron job that calls it. When the page notices that no progress is being made, it asks WP-Cron again and then runs the steps itself for as long as it stays open, so a scan never gets stuck; the **In this browser tab** setting makes that the normal mode. With `DISABLE_WP_CRON` set, background and scheduled scans advance only when your server's cron job runs `wp-cron.php`.

= Can I schedule scans? =

Yes: daily, twice daily or weekly at a time of day (and weekday) in the site's timezone, from the Settings section of the Elderward page. A scheduled scan runs in the background, uses the access log path saved in the settings, and is skipped when another scan is already running. The results replace the previous report on the page.

= What does marking a false positive do? =

The finding is still recorded by later scans, but it moves out of the counts and the default view into the **False positives** filter and the JSON export, which flags it. The text export leaves it out. For a finding about a file, the mark stores the file's SHA-256. If the file changes, the finding comes back with a note saying it was marked before. Marks can be removed one by one or all at once.

= How do I send a suspicious file for analysis? =

Click **Download sample** next to the finding. You get a zip with the file, named by its SHA-256 and encrypted with the password `infected`, which is the usual convention for sharing malware samples, plus a manifest of where and why it was flagged. Submit it to the analyst or sandbox of your choice. Elderward never uploads files, and never packages `wp-config.php` or files outside the WordPress folder. The **Look up on VirusTotal** link opens VirusTotal in your browser with the file's hash only.

= Can a custom signature break my site? =

No. Custom signatures only report matches, as `SIGNATURE_MATCH` findings for files. They never clean or delete anything, even in a command-line cleanup run. A regular expression that does not compile, or that would match an empty file, is refused when you save it.

= Which AI assistants work, and what can they do? =

Any assistant that can use an MCP server: Claude (Desktop and Code), Antigravity, Cursor, and ChatGPT where your plan allows custom MCP connectors. It needs WordPress 6.9 or later and the MCP Adapter plugin. The assistant acts as the user you connect it with, and only administrators get access. It can start and follow scans, read findings and flagged files, write and test custom signatures, and record false positives. It cannot clean, restore or change files. The **AI assistants** tab shows the exact configuration for this site, and a brief you can paste into any chatbot without MCP. Whatever you share with an assistant goes to its provider, so choose one you trust with your site's file paths and code.

= Does the plugin send data anywhere? =

No. There is no telemetry, no account and no remote service. The only outbound requests are made during the integrity check, to `api.wordpress.org` (core and plugin checksum manifests) and `downloads.wordpress.org` (official plugin/theme/core packages, needed to verify themes and to restore files). The requests carry only the WordPress version, the plugin or theme slug and its version. Findings are stored in your own database and shown only to administrators.

= Will the scan modify my site? =

The admin page is report-only: it never writes, deletes or restores files and never changes the database. Cleanup (`wp elderward scan`) and restore (`wp elderward integrity --restore`) are separate, explicit commands with a `--dryrun` preview. Take a backup before running them.

= Why does the plugin use shell_exec? =

Only for the crontab check, which runs the fixed, read-only command `crontab -l` to read the current user's cron entries. No user input ever reaches a shell. When `shell_exec` is disabled by the host, the check reports `CRONTAB_UNAVAILABLE` instead of silently passing.

= Why does the plugin write files directly instead of using WP_Filesystem? =

Cleanup and restore have to write files atomically (temporary file plus rename, so a failed write can never truncate the original) and copy originals to a quarantine folder before overwriting them, which the FTP and SSH transports of WP_Filesystem cannot do. Those writes only happen from the command line, never from the admin page. The admin scan writes nothing but its own work files under `wp-content/uploads/elderward/` (a file list and downloaded official packages), which are removed when the scan ends.

= Can I run it on a site that no longer loads? =

Yes. `php bin/elderward.php scanall=1 scandirectory=/path/to/wp-root` runs the same scanners without WordPress, reading the database credentials from `wp-config.php` without executing it. Run `php bin/elderward.php help=1` for the options.

= Is a clean scan proof that the site is clean? =

No. The signatures find known malware, the integrity check only covers packages that exist on wordpress.org, and the timestamp and log checks are leads, not proof. Treat the report as a starting point for an investigation.

= Are the finding texts translated? =

The admin interface is translatable. The finding details themselves (the technical description of each issue) are in English, because they are also written to exports and tickets that other tools and people read.

== Screenshots ==

1. Tools > Elderward: start a scan and watch it progress.
2. The findings table, sorted worst-first, with severity filters, false-positive marks, sample downloads and export.
3. The signature editor and tester.
4. Connecting an AI assistant.

== External services ==

This plugin connects to two WordPress.org services, only while an integrity check or a restore is running:

* `https://api.wordpress.org/core/checksums/` - the official checksum manifest for the installed WordPress version and locale. Sent: the version number and locale.
* `https://downloads.wordpress.org/` - the plugin checksum manifests and the official plugin, theme and core packages. Sent: the plugin or theme slug and version.

Both are operated by the WordPress Foundation; see the [WordPress.org privacy policy](https://wordpress.org/about/privacy/). No other hosts are contacted by the plugin.

The findings page shows a **Look up on VirusTotal** link next to file findings. It is an ordinary link: only when you click it, your browser opens `https://www.virustotal.com/gui/file/<sha256>` with the file's SHA-256 hash in the address. The site itself makes no request and sends no file. VirusTotal is operated by Google; see its [terms](https://docs.virustotal.com/docs/terms-of-service) and [privacy policy](https://docs.virustotal.com/docs/privacy-policy).

AI assistants connect to your site through the separate MCP Adapter plugin, using your own credentials; Elderward makes no requests to any AI provider.

== Changelog ==

= 1.0.0 =
* First release as a WordPress plugin: admin page with a report-only scan that runs in the background through WP-Cron (or from the browser tab), scheduled scans, WP-CLI commands, and the standalone CLI.
* False-positive marks bound to the reviewed file content, and encrypted sample downloads for manual analysis.
* Signature editor for custom, detection-only signatures, with a tester and JSON import/export (also usable by the standalone CLI through `signatures=`).
* WordPress abilities for AI assistants over MCP (WordPress 6.9+ with the MCP Adapter plugin), a triage prompt, and a copyable brief for chatbots without MCP.
