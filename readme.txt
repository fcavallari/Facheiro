=== Elderward ===
Contributors: fioa8c
Tags: malware, security, scanner, hardening, incident response
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Malware scanner and incident response: integrity, database and log checks, server hardening, and a recovery mode for sites that no longer load.

== Description ==

Elderward helps you find out whether a WordPress site has been compromised, how, and what to do about it. It was written for incident responders and runs entirely on your own server: there is no account, no external service and no data leaves the site.

**One report-only scan from the Elderward menu** runs every check and lists the findings worst-first:

* **Quick checks** - executable PHP inside `wp-content/uploads`, `auto_prepend_file`/`auto_append_file` directives in `.user.ini`, `php.ini` and `.htaccess` (code that runs on every request), an inventory of must-use plugins, hidden dotfile PHP.
* **Integrity** - WordPress core, every plugin and every theme compared with the official wordpress.org packages for the installed version: modified files, missing files, and extra files that the package does not contain (extra PHP inside core or a plugin is the classic dropped webshell). Packages that cannot be verified, such as premium plugins or child themes, are reported as such so a clean report never silently means "unchecked".
* **Timestamps** - files modified apart from the rest of their package, and files whose modification time looks back-dated. Report-only leads, never proof.
* **Crontab** - the current user's crontab checked for known persistence patterns.
* **Database** - read-only: an inventory of administrator accounts with recently created ones highlighted, non-administrator roles that were granted takeover capabilities, PHP or hidden iframes or obfuscated JavaScript in options and posts, `siteurl`/`home` hijacks, and `active_plugins` tampering. Values are pattern-matched only and never unserialized.
* **Access logs** (optional) - point it at an access log file or directory (rotated `.log.N` and `.gz` files included) to see known attack traffic: webshell requests, exploit attempts against known-vulnerable plugins, `.env` probes, code injection, brute force floods. Files modified within minutes of flagged requests are linked to that traffic.
* **Malware signatures** - signature-based detection of known injections such as the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns, plus about 30 report-only rules for common webshell and backdoor shapes (code or commands from the request, password-gated shells, known shell families, obfuscated eval, PHP hidden behind image headers), run in dry-run mode from the admin page.

Anything that blocks a check - an unreadable file, a failed query, a missing PHP extension - is itself reported as an `ERROR` finding, never skipped. A clean report means every scanner actually looked.

**Scans run in the background** through WP-Cron, so you can start one and close the tab; the page shows the progress whenever you come back. A setting switches to running the steps from the browser tab instead, for hosts where WP-Cron is unreliable. **Scheduled scans** (daily, twice daily or weekly at a time you choose) run the same report-only scan automatically.

**Review the findings in place.** Mark a finding as a **false positive** with a note and later scans hide it, while still keeping it in the record. For a file or a database value, the mark only holds while it is byte-for-byte the one you reviewed, so an attacker cannot hide behind a file or an option you once cleared. **Download sample** packs a flagged file into a zip encrypted with the password `infected`, with a manifest, for you to send to a malware analyst or sandbox. Elderward never uploads anything itself.

**Write your own signatures** on the Signatures tab: exact text or regular expressions for files, option values or post content. Test them against a pasted sample or a file of the site before saving, and export them as JSON for other sites or the standalone scanner. Custom signatures only detect; they never clean.

**Work with an AI assistant.** On WordPress 6.9 or later, Elderward registers its scan, findings, signature and false-positive tools as WordPress abilities. With the official MCP Adapter plugin, Claude, ChatGPT, Antigravity, Cursor or any other MCP client can run scans, explain the findings, read flagged files, and draft and test signatures with you. Everything scanned is labelled as untrusted data for the assistant, and it has no tool that cleans or changes files. Without MCP, the AI assistants tab gives you a ready-made brief to paste into any chatbot.

**Harden the server.** The Hardening tab adds web server rules that refuse what should never be served: PHP dropped into uploads, copies of `wp-config.php`, `.git` and other hidden files, backups and logs, WordPress internals, folder listings. Choose Apache/LiteSpeed or Nginx, start from the Recommended or Strict template or pick each protection yourself (each one says what it could break), and review the exact rules before applying. On Apache and LiteSpeed, Elderward writes them into `.htaccess` files between its own markers, checks the site afterwards and undoes the change automatically if the site stops working. On Nginx, download the configuration file and include it in the server block. **Check now** confirms what the live site enforces, whoever added the rules.

**Recovery mode for a site that no longer loads.** When malware or a broken update causes a white screen or a critical error, the admin pages stop working too. Recovery mode is a separate, key-protected page that does not load WordPress: it shows the PHP errors that broke the site and the plugin or theme they come from, and runs the full report-only scan, database included. Create the key on the Recovery tab while the site works, with WP-CLI, or - if the site is already down - by uploading a key file. Without a key the page answers "not found".

**Cleanup and restore run from the command line**, where you can take a backup first and preview with a dry run:

* `wp elderward scan --dryrun` then `wp elderward scan` removes known malware from infected files (atomic write, never truncates the original).
* `wp elderward integrity --restore --dryrun` then `wp elderward integrity --restore --quarantine-dir=/path/outside/webroot` restores modified or missing core, plugin and theme files from the official packages. Every file is byte-verified against the reference checksum before it is written; extra files are never deleted.

The same scanners are available as WP-CLI commands (`wp elderward scanall`, `quick`, `integrity`, `times`, `db`, `cron`, `log`) with text or NDJSON output and exit codes that CI and cron jobs can alert on, and as a standalone PHP script (`php bin/elderward.php`, inside the plugin folder) for a site too broken to load WordPress.

Development happens at [github.com/fioa8c/elderward](https://github.com/fioa8c/elderward); the source in this directory is the complete, unminified source.

== Installation ==

1. Upload the `elderward` folder to `/wp-content/plugins/`, or install it from the Plugins screen.
2. Activate the plugin. It creates one database table (`{prefix}elderward_findings`) to hold the latest report.
3. Open **Elderward** in the admin menu (in the Network Admin on multisite) and click **Start scan**. The scan continues in the background; the page shows its progress and reloads with the findings when it ends.
4. On the **Settings** tab, optionally give the location of the web server's access logs, choose how scans run (in the background through WP-Cron, or only while the page is open) and, if you want, automatic scans.
5. To act on the findings, use the WP-CLI commands shown under the results, after taking a backup.
6. Recommended: apply the Recommended template on the **Hardening** tab, and create a recovery key on the **Recovery** tab so recovery mode is ready if the site ever breaks.
7. Optional: to use an AI assistant, install the MCP Adapter plugin and follow the steps on the **AI assistants** tab.

== Frequently Asked Questions ==

= Does the scan keep running if I close the page? =

Yes, with the default setting. The scan is a chain of short WP-Cron jobs; the page only watches it. WP-Cron needs the site to be able to request its own `wp-cron.php` (Site Health reports a failing "loopback request" when it cannot) or a server cron job that calls it. When the page notices that no progress is being made, it asks WP-Cron again and then runs the steps itself for as long as it stays open, so a scan never gets stuck; the **In this browser tab** setting makes that the normal mode. With `DISABLE_WP_CRON` set, background and scheduled scans advance only when your server's cron job runs `wp-cron.php`.

= Can I schedule scans? =

Yes: daily, twice daily or weekly at a time of day (and weekday) in the site's timezone, from the Settings tab of the Elderward page. An automatic scan runs in the background, checks the access logs set in the settings, and is skipped when another scan is already running. The results replace the previous report on the page.

= What does marking a false positive do? =

The finding is still recorded by later scans, but it moves out of the counts and the default view into the **False positives** filter and the JSON export, which flags it. The text export leaves it out. For a finding about a file, the mark stores the file's SHA-256; for a finding about a database value (an option or a post), the SHA-256 of that value. If either changes, the finding comes back with a note saying it was marked before. Marks can be removed one by one or all at once.

= How do I send a suspicious file for analysis? =

Click **Download sample** next to the finding. You get a zip with the file, named by its SHA-256 and encrypted with the password `infected`, which is the usual convention for sharing malware samples, plus a manifest of where and why it was flagged. Submit it to the analyst or sandbox of your choice. Elderward never uploads files, and never packages `wp-config.php` or files outside the WordPress folder. The **Look up on VirusTotal** link opens VirusTotal in your browser with the file's hash only.

= Can a custom signature break my site? =

No. Custom signatures only report matches, as `SIGNATURE_MATCH` findings for files. They never clean or delete anything, even in a command-line cleanup run. A regular expression that does not compile, or that would match an empty file, is refused when you save it. The guide [Writing malware signatures](https://github.com/fioa8c/elderward/blob/main/docs/writing-signatures.md) explains how to write rules that catch the threat without flagging clean code, and how to test them.

= Which AI assistants work, and what can they do? =

Any assistant that can use an MCP server: Claude (Desktop and Code), Antigravity, Cursor, and ChatGPT where your plan allows custom MCP connectors. It needs WordPress 6.9 or later and the MCP Adapter plugin. The assistant acts as the user you connect it with, and only administrators get access. It can start and follow scans, read findings and flagged files, write and test custom signatures, and record false positives. It cannot clean, restore or change files. The **AI assistants** tab shows the exact configuration for this site, and a brief you can paste into any chatbot without MCP. Whatever you share with an assistant goes to its provider, so choose one you trust with your site's file paths and code.

= Does the plugin send data anywhere? =

No. There is no telemetry, no account and no remote service. The only outbound requests are made during the integrity check, to `api.wordpress.org` (core and plugin checksum manifests) and `downloads.wordpress.org` (official plugin/theme/core packages, needed to verify themes and to restore files). The requests carry only the WordPress version, the plugin or theme slug and its version. The hardening check and the safety check after applying hardening rules request your own site only. Findings are stored in your own database and shown only to administrators.

= Will the scan modify my site? =

Scans are report-only: they never write, delete or restore files and never change the database. The only files the admin pages ever change are `.htaccess` files, when you apply protections on the Hardening tab, and the recovery key file, when you create one. Cleanup (`wp elderward scan`) and restore (`wp elderward integrity --restore`) are separate, explicit commands with a `--dryrun` preview. Take a backup before running them.

= Why does the plugin use shell_exec? =

Only for the crontab check, which runs the fixed, read-only command `crontab -l` to read the current user's cron entries. No user input ever reaches a shell. When `shell_exec` is disabled by the host, the check reports `CRONTAB_UNAVAILABLE` instead of silently passing.

= Why does the plugin write files directly instead of using WP_Filesystem? =

Cleanup and restore have to write files atomically (temporary file plus rename, so a failed write can never truncate the original) and copy originals to a quarantine folder before overwriting them, which the FTP and SSH transports of WP_Filesystem cannot do. Those writes only happen from the command line, never from the admin page. The admin scan writes nothing but its own work files under `wp-content/uploads/elderward/` (a file list and downloaded official packages), which are removed when the scan ends. The Hardening tab writes `.htaccess` through WordPress's own `insert_with_markers()`, and removes its block in place; the recovery key and recovery mode's state are small plain files, because recovery mode must read them without WordPress.

= What if hardening breaks my site? =

Before writing anything, Elderward checks that every file it needs can be written. After writing, it loads the home page, the login page and an admin request; if any of them starts failing (most often because the host does not allow one of the rules in `.htaccess`), it puts every file back exactly as it was and tells you which protections to leave out. Rules live only between `# BEGIN Elderward` and `# END Elderward`, and **Remove Elderward rules** takes them out again. If a protection breaks a feature without breaking the whole site, switch it off and apply again. If you cannot reach the admin at all, delete the lines between those markers in the `.htaccess` files over FTP.

= Is the recovery page a security risk? =

It does nothing without a recovery key: no valid, unexpired key file means a plain 404. Keys created by Elderward are 32 random characters, impossible to guess, and only their SHA-256 is stored, and a wrong key is simply refused. A key you type into the file by hand may be weaker, so each wrong try costs a second and a client is locked out for 15 minutes after 10 wrong tries (generated keys never lock anyone out, so nobody can block you from recovery mode); a sign-in lasts one hour and ends when the key is revoked or replaced. The page only reads files and the database, never changes anything, and reads `wp-config.php` without executing it. Use it over HTTPS and revoke the key when you are done.

= Can I run it on a site that no longer loads? =

Yes: use recovery mode (see the Recovery tab), or, with shell access, `php bin/elderward.php scanall=1 scandirectory=/path/to/wp-root` runs the same scanners without WordPress, reading the database credentials from `wp-config.php` without executing it. Run `php bin/elderward.php help=1` for the options.

= Can malware switch Elderward off or hide from it? =

Malware that runs PHP on your site has the same rights as any plugin, so no plugin can stop it. Elderward makes it visible instead. Every scan starts by checking Elderward's own files against the official checksums (or the list shipped with the plugin), and warns you when they were changed. Saved false positives, custom signatures and scan settings are sealed in a file next to the plugins folder: if someone changes them directly in the database, which is how an attacker would hide a backdoor from the scan, the change is reported, and a false positive added that way is ignored until you review it. An attacker who can write files can still rewrite the seal, so this is detection, not prevention.

= Is a clean scan proof that the site is clean? =

No. The signatures find known malware, the integrity check only covers packages that exist on wordpress.org, and the timestamp and log checks are leads, not proof. Treat the report as a starting point for an investigation.

= Is Elderward available in my language? =

The admin pages are available in English and Brazilian Portuguese (pt_BR), and follow each user's language setting (Users > Profile > Language). The recovery page, which runs without WordPress, has its own Portuguese strings: it follows the browser's language, and a link in its header switches between English and Portuguese. Other languages can be added through translate.wordpress.org once the plugin is in the directory.

The finding details themselves (the technical description of each issue) stay in English, because they are also written to exports and tickets that other tools and people read, and the command-line tools print them the same way.

== Screenshots ==

1. The Elderward page: start a scan and watch it progress.
2. The findings table, sorted worst-first, with severity filters, false-positive marks, sample downloads and export.
3. The signature editor and tester.
4. Hardening: server choice, templates and protections.
5. Recovery mode, working while WordPress itself shows a critical error.
6. Connecting an AI assistant.

== External services ==

This plugin connects to two WordPress.org services, only while an integrity check or a restore is running:

* `https://api.wordpress.org/core/checksums/` - the official checksum manifest for the installed WordPress version and locale. Sent: the version number and locale.
* `https://downloads.wordpress.org/` - the plugin checksum manifests and the official plugin, theme and core packages. Sent: the plugin or theme slug and version.

Both are operated by the WordPress Foundation; see the [WordPress.org privacy policy](https://wordpress.org/about/privacy/). No other hosts are contacted by the plugin. The **Check now** button on the Hardening tab and the safety check after applying hardening rules send requests to your own site only.

The findings page shows a **Look up on VirusTotal** link next to file findings. It is an ordinary link: only when you click it, your browser opens `https://www.virustotal.com/gui/file/<sha256>` with the file's SHA-256 hash in the address. The site itself makes no request and sends no file. VirusTotal is operated by Google; see its [terms](https://docs.virustotal.com/docs/terms-of-service) and [privacy policy](https://docs.virustotal.com/docs/privacy-policy).

AI assistants connect to your site through the separate MCP Adapter plugin, using your own credentials; Elderward makes no requests to any AI provider.

== Changelog ==

= 1.0.0 =
* First release as a WordPress plugin: admin page with a report-only scan that runs in the background through WP-Cron (or from the browser tab), scheduled scans, WP-CLI commands, and the standalone CLI.
* False-positive marks bound to the reviewed file content, and encrypted sample downloads for manual analysis.
* Built-in detection of common webshell and backdoor shapes (report only), and files the signature scan cannot read or that exceed its 2 MB limit reported instead of skipped.
* Signature editor for custom, detection-only signatures, with a tester and JSON import/export (also usable by the standalone CLI through `signatures=`).
* Hardening for Apache/LiteSpeed (`.htaccess`, applied with an automatic health check and rollback) and Nginx (downloadable configuration), with Recommended and Strict templates and a live check.
* Recovery mode: a key-protected page that shows what broke the site and runs the full scan without loading WordPress.
* Brazilian Portuguese translation of the admin pages and the recovery page.
* Tamper detection: every scan verifies Elderward's own files first, and saved false positives, custom signatures and scan settings changed outside Elderward (directly in the database) are reported, with tampered false positives ignored until reviewed.
* A guide to writing custom signatures (docs/writing-signatures.md), with tested examples, linked from the Signatures tab.
* Custom post-content signatures now see every live post, not only posts containing code-like markers.
* WordPress abilities for AI assistants over MCP (WordPress 6.9+ with the MCP Adapter plugin), a triage prompt, and a copyable brief for chatbots without MCP.
