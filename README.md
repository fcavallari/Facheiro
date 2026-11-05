<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/img/elderward-logo.svg">
    <img src="assets/img/elderward-logo-on-light.svg" alt="Elderward" width="400">
  </picture>
</p>


Elderward is a free malware scanner and incident-response toolkit for WordPress sites. It checks files for signs of compromise and can remove known malware, verifies core, plugins and themes against the official wordpress.org packages, scans the database for rogue administrators and injected content, and reads access logs for known indicators of compromise (IoCs) so you can understand how the attack happened — not just clean up after it.

What you get:

- **A report-only scan of everything** from its own **Elderward** admin menu, in the background through WP-Cron or on a schedule, with findings worst-first, false-positive marks bound to the reviewed file, encrypted sample downloads and NDJSON export.
- **Custom signatures** written and tested in the admin (detection-only), shared as JSON with the CLI.
- **Server hardening** for Apache/LiteSpeed (`.htaccess`, applied with a health check and automatic rollback) and Nginx (a configuration file to include), from a Recommended or Strict template or protection by protection, and a live check of what the server enforces.
- **Recovery mode**: a key-protected page that works when WordPress itself does not load (white screen, critical error), shows what broke the site and runs the full scan.
- **AI assistant tools** over MCP (WordPress 6.9+ with the MCP Adapter plugin), so Claude, ChatGPT, Antigravity or Cursor can run scans, explain the findings and draft signatures with you, and never clean or change files.
- **Cleanup and restore** from WP-CLI or the standalone CLI, with a dry run first.
- **English and Brazilian Portuguese** admin pages and recovery page.

It runs four ways, all on the same engine:

- **WordPress plugin** — the admin pages above.
- **WP-CLI** — `wp elderward ...` runs every scanner, cleanup, restore and hardening command, with text or NDJSON output and alerting exit codes.
- **Recovery mode** — `recovery.php` in the plugin folder, when WordPress no longer loads but the web server still runs PHP.
- **Standalone CLI** — `php bin/elderward.php ...` needs no working WordPress at all: upload the folder to a dead site and scan it from a shell.

Nothing leaves the server on its own. The only outbound requests go to wordpress.org during the integrity check (checksum manifests and official packages); hardening checks only request the site itself.

It started as a variation of the Jetpack Cleanup Util, packaged so anyone can run it on their own host.

The project homepage (English and Brazilian Portuguese) lives in `site/`.

## Requirements

- WordPress 6.0+ and PHP 7.2+ for the plugin; the standalone CLI and recovery mode run on PHP 5.6+
- Shell access (WP-CLI or `php`) to clean or restore files; the admin pages need no shell
- WordPress 6.9+ and the [MCP Adapter](https://github.com/WordPress/mcp-adapter) plugin for the AI assistant tools
- Apache or LiteSpeed with `AllowOverride` for hardening rules Elderward writes itself; on Nginx you include the generated file in the server configuration

The signature scan, quick checks and timestamp checks need nothing else. The other scanners use PHP extensions that locked-down hosts sometimes lack; a missing one is reported as an `ERROR` finding rather than skipped:

| Needed for | Requirement |
|---|---|
| `.gz` rotated logs | zlib extension |
| Online integrity checks (standalone CLI) | curl extension, or `allow_url_fopen=On` (the plugin uses the WordPress HTTP API) |
| Theme verification and every restore | zip extension |
| Database scan (standalone CLI) | mysqli extension (the plugin uses WordPress' connection) |
| Crontab scan | `shell_exec` not in `disable_functions` |

## The plugin

Elderward is not on WordPress.org yet. Install it from this repository; the folder must be named `elderward`:

```
cd wp-content/plugins
git clone https://github.com/fioa8c/elderward.git elderward
wp plugin activate elderward
```

(or download the repository as a zip, unpack it as `wp-content/plugins/elderward/`, and activate it on the Plugins screen). Activation creates one table, `{prefix}elderward_findings`. Then:

1. **Elderward (admin menu) → Start scan.** The scan runs in the background through WP-Cron, so you can close the tab and come back; it changes nothing on the site. Findings appear worst-first with severity filters and can be exported as text or NDJSON. The **Settings** tab sets the access log file or directory that every scan checks, switch scans to run only while the page is open (for hosts where WP-Cron is unreliable), and set up daily, twice-daily or weekly automatic scans. Each setting has a **?** with more detail, and the screen's **Help** tab explains the whole page.
2. **Review the findings.** *False positive* records a reviewed, benign finding with a note: later scans keep it in the record (and in the JSON export, flagged `"false_positive": true`) but out of the counts and the default view. A mark on a file stores the file's SHA-256 and stops applying as soon as the file changes, so the finding comes back. A mark on a database finding (an option, a post, `siteurl`/`home`, role definitions) does the same with the SHA-256 of the value the scan read, so a payload swapped inside a cleared option row comes back even while the same signature matches. Database marks saved before values were hashed come back once; mark them again. *Download sample* packs a flagged file into a zip encrypted with the password `infected` (AES-256), with a `manifest.json`, for you to submit to an analyst or sandbox; Elderward never uploads anything, and never packages `wp-config.php` or files outside the WordPress root. File findings also show the SHA-256 with a VirusTotal lookup link (hash only, opened by your browser).
3. **Signatures tab.** Add custom signatures for files, option values or post content, test them against a pasted sample or a file of the site, and import/export them as JSON (see [Custom signatures](#custom-signatures)). Custom signatures only detect.
4. **Hardening tab.** Server rules that refuse what should never be served (see [Hardening](#hardening)).
5. **Recovery tab.** A key for recovery mode, the page that scans the site when WordPress no longer loads (see [Recovery mode](#recovery-mode)).
6. **Act on the results from WP-CLI**, after taking a backup:

```
wp elderward scan --dryrun                        # preview the signature cleanup
wp elderward scan                                 # remove known malware from infected files
wp elderward scan --allfiles                      # ... scanning every file, not just risky extensions
wp elderward integrity --restore --dryrun         # preview restoring modified/missing core, plugin, theme files
wp elderward integrity --restore --quarantine-dir=/path/outside/webroot
```

Every scanner is also a WP-CLI command, with `--format=json` for NDJSON and the exit codes described below:

```
wp elderward scanall [--log=/var/log/apache2] [--format=json]   # every scanner, report-only
wp elderward quick                                # PHP in uploads, prepend hooks, mu-plugins, hidden PHP
wp elderward integrity [--checksum-dir=/path] [--locale=pt_BR]
wp elderward times                                # timestamp anomaly report
wp elderward db                                   # read-only database scan
wp elderward cron                                 # current user's crontab
wp elderward log /var/log/apache2 [--correlate] [--window=300]
```

```
wp elderward harden [--server=apache|nginx] [--preset=recommended|strict] [--features=a,b] [--print|--apply [--unverified]|--remove|--check]
wp elderward recovery-key create|status|revoke [--expires=<days>|never]
```

`wp help elderward <command>` lists each command's options. On multisite the menu is in the Network Admin and limited to super admins.

### Hardening

The Hardening tab (and `wp elderward harden`) writes web server rules for a template (**Recommended** or **Strict**) or any mix of protections:

| Protection | Template | Apache/LiteSpeed (`.htaccess`) | Nginx |
|---|---|---|---|
| Block PHP in uploads | Recommended | `uploads/.htaccess` `FilesMatch` deny | `location ~* ^/wp-content/uploads/.*\.php` deny |
| Block WordPress internals | Recommended | `wp-includes/.htaccess` (allows `wp-tinymce.php`, `ms-files.php`), `wp-admin/includes/.htaccess` | regex location with the same exceptions, `^~ /wp-admin/includes/` |
| Protect wp-config files | Recommended | `^wp-config` (also `.bak`, `.old` copies) | `^/wp-config` |
| Block backups, logs, server settings | Recommended | `.bak .old .orig .save .swp .sql .log .ini .sh ~`, `readme.html`, `license.txt` | same |
| Block hidden files and folders | Recommended | dotfiles plus a rewrite for dot-folders, `.well-known` allowed | `location ~ /\.(?!well-known)` |
| Turn off folder listings | Recommended | `Options -Indexes` | `autoindex off` |
| Block direct PHP in themes | Strict | `themes/.htaccess` | regex location |
| Security headers | Strict | `nosniff`, `X-Frame-Options SAMEORIGIN`, `Referrer-Policy` | `add_header ... always` |
| Turn off XML-RPC | Strict | `xmlrpc.php` deny | `location = /xmlrpc.php` |
| Block direct PHP in plugins | custom only | rewrite rule, `elderward/recovery.php` allowed | regex location, same exception |

On Apache/LiteSpeed the rules go between `# BEGIN Elderward` and `# END Elderward` (`insert_with_markers()`). Before writing, every needed file must be writable and the site must be able to reach itself over HTTP: the home page, login, admin-ajax and one address inside every other folder being written (a stylesheet in `wp-includes`, the active theme's `style.css`…) are requested before and after, and if any starts failing (a 5xx because `Options` is not allowed by `AllowOverride`, no answer, or a page that was served and is now refused) every file is restored byte-for-byte. A rule the server rejects answers every request with a 500, the admin included, so when the site cannot reach itself (loopback requests blocked by the host) nothing is written unless you tick **Apply without the safety check** (`--unverified`); removing rules never needs it. Removing takes the blocks out and deletes files Elderward created. Nginx configuration is downloaded (or printed with `--print`) and included in the `server { }` block above the PHP location. **Check now** / `--check` requests files that do not exist (a PHP file in uploads, a `.sql` dump, a dot-folder…) and reports a protection as active only when the server refuses them, so it verifies hand-made rules too and creates nothing.

### Recovery mode

`wp-content/plugins/elderward/recovery.php` scans the site **without loading WordPress**, for when a fatal error or malware takes the site (and its admin) down. It shows the latest PHP fatal errors from the logs with the plugin or theme they point at, the WordPress version and `.maintenance` state, and runs the same report-only scan as the admin page, database included (credentials parsed from `wp-config.php`, never executed), stepping it in short requests.

It is inert unless a key exists: without `wp-content/elderward-recovery-key.php` (or with an expired one) it answers 404. Create the key on the Recovery tab or with `wp elderward recovery-key create --expires=7`; Elderward stores only its SHA-256. If the site is already broken, create the file by hand:

```
<?php exit; ?>
{"key":"at-least-24-random-characters-of-your-own"}
```

Sign-in sets an HMAC-signed, HttpOnly, SameSite=Strict cookie for one hour, bound to the key (replacing or revoking the key ends every session); actions carry a session-bound token; a wrong generated key is simply refused (at ~190 bits a delay adds nothing and would only let anyone tie up PHP workers), and for hand-written keys each wrong try costs a second and a client is locked out for 15 minutes after 10 wrong tries (behind a proxy, the forwarded client address counts; at most 500 clients are tracked). Generated keys never lock anyone out, so an attacker cannot block the owner. The state folder must be owned by the PHP user and closed to everyone else (a shared `/tmp` folder created by another account is ignored), and every step rebuilds the scan options, so a tampered state file cannot turn the scan into a cleanup. The page keeps its state in exit-guarded files in the system temp folder (or `wp-content/elderward-recovery/`). Revoke the key when you are done.

### Tamper detection

Malware that runs PHP on a site has the same rights as Elderward, so no plugin can stop it from changing Elderward. Elderward makes the change visible instead, in two ways, and reports both in every scan (admin page, WP-Cron, WP-CLI, assistants and the recovery page):

- **Self-check.** Every other check skips Elderward's own folder (its signatures would match themselves), so the scan starts with the *Elderward self-check* stage: each file of the plugin is compared with the wordpress.org checksums for this version, or, when wordpress.org has none (or cannot be reached), with the `checksums.json` the plugin ships with. Modified or added PHP files are HIGH, and the admin pages then warn that the results may not be trustworthy (until the scan is clean or you mark those findings as false positives). Nothing in the folder is skipped: in a git checkout the development files (tests, build tools) are verified against the same list, a PHP file inside `.git` is reported, and a `vendor/` or `node_modules/` folder is reported as unverified, since no list covers installed dependencies. The shipped list catches mass injectors and dropped files, but an attacker who can write files can rewrite it too; only the wordpress.org reference (or a fresh download, run as the standalone CLI) covers that. `selfcheck=1` / `wp elderward selfcheck` runs it alone; `noselfcheck=1` skips it.
- **Sealed settings.** Saved false positives, custom signatures and the scan settings live in the database, where SQL injection alone could add a false positive for a backdoor or delete the signature that catches it. Every change made through Elderward also writes the SHA-256 of each entry to `wp-content/elderward-seal.php` (guarded like the recovery key file), which a database-only attacker cannot rewrite. A false positive that does not match the seal is ignored, so its finding comes back (`TAMPER_FALSE_POSITIVE`); custom signatures and settings changed outside Elderward are reported (`TAMPER_SIGNATURE`, `TAMPER_SETTINGS`), and a deleted or garbled seal is recreated and reported (`TAMPER_SEAL_MISSING`). The admin pages list each change with **Keep** (after review) or **Remove**; `wp elderward seal status` and `wp elderward seal accept [--collection=<name>]` do the same from the command line. After restoring the database from a backup or moving the site without the seal file, review and accept.

This is detection, not prevention: an attacker who can write files can rewrite the seal and the shipped checksum list as well.

### AI assistants (MCP)

On WordPress 6.9+ Elderward registers WordPress abilities (category `elderward`) that the official [MCP Adapter](https://github.com/WordPress/mcp-adapter) plugin exposes to any MCP client: Claude Desktop and Claude Code, Antigravity, Cursor, and ChatGPT where custom MCP connectors are available. The **AI assistants** tab shows the client configuration for the site, either STDIO through WP-CLI (`wp mcp-adapter serve --user=<admin>`) or HTTP through `@automattic/mcp-wordpress-remote` with an application password.

| Ability | What it does |
|---|---|
| `elderward/get-status`, `start-scan`, `advance-scan`, `cancel-scan` | Run a report-only background scan and follow it; `advance-scan` steps it from the request when WP-Cron is stalled |
| `elderward/list-findings`, `get-finding`, `read-flagged-file` | Read results and the first 64 KB of a flagged file (inside the root, never `wp-config.php`) |
| `elderward/mark-false-positive`, `unmark-false-positive`, `list-false-positives` | Review decisions, with a mandatory note |
| `elderward/list-signatures`, `test-signature`, `save-signature`, `delete-signature` | Draft, prove and save detection-only signatures |
| `elderward/triage` (MCP prompt) | A guided investigation: verdict, evidence, cleanup plan the user runs |

Only administrators (`Elderward_Plugin::can_manage()`) can call them. There is no ability that cleans, restores or writes site files. Every output that carries scanned data has an `untrusted_data_notice`, and the triage prompt tells the assistant to treat file names, paths, details and file contents as attacker-controlled data, never as instructions. Without MCP, the tab offers a brief (instructions plus the top 100 findings as JSON lines between untrusted-data markers) to paste into any chatbot. `tests/mcp-stdio.js` drives a whole session over STDIO.

The plugin stores the latest report in one table (`{prefix}elderward_findings`) and its scan state in an option; uninstalling removes both, the work folder under `wp-content/uploads/elderward/`, Elderward's `.htaccess` blocks, the recovery key and state, and the tamper seal.

## The standalone CLI

For a site that no longer loads, or a host without WP-CLI, run the same scanners straight from the plugin folder. Options are `key=value` arguments:

Keep Elderward in a folder of its own: the plugin folder, or any folder that holds only its `bin/` and `includes/`. Its own folder is never scanned (the signatures in its source would match themselves), so a scan directory that is that folder or sits inside it is refused with an error instead of being reported clean. Uploading `bin/` and `includes/` straight into the home folder above `public_html` is the usual way to run into this.

```
php bin/elderward.php scanall=1 scandirectory=/path/to/wp-root         # every scanner, report-only
php bin/elderward.php scanall=1 scanlog=/var/log/apache2 scandirectory=/path/to/wp-root  # ... incl. logs
php bin/elderward.php scanall=1 format=json scandirectory=/path/to/wp-root               # machine-readable
```

`scanall=1` runs the quick checks, integrity, timestamp, crontab, database and (with `scanlog=`) access log scanners, then the malware signature scan, and **changes nothing**. In text mode the findings are collected and printed once at the end, sorted worst-first; with `format=json` they stream as each scanner produces them. Only one scan mode is accepted per invocation.

Fixing what was found:

```
php bin/elderward.php dryrun=1 scandirectory=/path/to/site   # preview the signature cleanup, write nothing
php bin/elderward.php scandirectory=/path/to/site            # remove known malware from infected files
php bin/elderward.php allfiles=1 scandirectory=/path/to/site # ... scanning every file, not just risky extensions
php bin/elderward.php scanintegrity=1 restore=1 dryrun=1 scandirectory=/path/to/wp-root  # preview restore
php bin/elderward.php scanintegrity=1 restore=1 quarantinedir=/safe/place scandirectory=/path/to/wp-root
```

The signature cleanup is the default mode, so with no mode option the script modifies files; `dryrun=1` is the switch that makes it report-only. (`allfiles=1` was called `scan_all=1` in earlier versions; the old name now stops with an error because it was too easy to confuse with `scanall=1`.)

Running one scanner at a time:

```
php bin/elderward.php scancron=1               # check the current user's crontab for malware
php bin/elderward.php scanlog=/var/log/apache2/access.log   # scan one access log for IoCs
php bin/elderward.php scanlog=/var/log/apache2 # scan every access log in a directory (.gz included)
php bin/elderward.php scanlog=/var/log/apache2 correlate=1 scandirectory=/path/to/wp-root  # link traffic to files
php bin/elderward.php scanintegrity=1 scandirectory=/path/to/wp-root   # verify core, plugins and themes
php bin/elderward.php scanintegrity=1 checksumdir=/path/to/manifests   # ... without network access
php bin/elderward.php scanintegrity=1 locale=pt_BR scandirectory=/path/to/wp-root  # non-English core
php bin/elderward.php scantimes=1 scandirectory=/path/to/wp-root       # timestamp anomaly report
php bin/elderward.php scandb=1 scandirectory=/path/to/wp-root          # scan the database (read-only)
php bin/elderward.php quickscan=1 scandirectory=/path/to/wp-root       # uploads PHP, prepend hooks, mu-plugins
php bin/elderward.php help=1                   # show usage
```

**Moved content folder.** Plugins, themes, uploads and mu-plugins are looked for where WordPress loads them, not only in `<root>/wp-content`. Inside WordPress (admin page, WP-CLI, assistants) the plugin passes `WP_CONTENT_DIR` and `WP_PLUGIN_DIR`, and the recovery page passes the plugin folder it runs from. The standalone CLI reads `WP_CONTENT_DIR` and `WP_PLUGIN_DIR` out of `wp-config.php` when they are a plain string or `__DIR__`, `dirname(__FILE__)` or `ABSPATH` followed by a string; anything else (Bedrock's `Config::define()`, variables, `getenv()`) needs `contentdir=/path` (and `plugindir=/path` when plugins live elsewhere). A folder outside the root is walked by every scanner, and `<root>/wp-content` is scanned too whenever it exists. A relocated folder that was found reports `CONTENT_DIR` (INFO), so the report says where it looked. One that can't be found, a define that can't be evaluated, or a define pointing at `/`, the root or one of its parents (a tampered `wp-config.php` can point anywhere) reports `CONTENT_DIR_UNKNOWN` (ERROR). A cleanup or restore run never follows a `wp-config.php` define out of the root (the file is attacker-writable and the operator may run with more privileges than the web user): it reports `CONTENT_DIR_UNKNOWN` until `contentdir=` confirms the folder, or `dryrun=1` makes the run report-only.

`scandirectory=` defaults to the current directory. The signature scan and `correlate=1` accept any directory; `scanintegrity`, `scantimes`, `quickscan`, `scandb` and `scanall` need the WordPress root (the directory holding `wp-includes/`) and stop with an error otherwise. Arguments are parsed like a URL query string, so quote paths that contain spaces or `&`, and write `+` as `%2B` and `%` as `%25` (a literal `+` would be read as a space). The database scan reads the credentials out of `wp-config.php` with regular expressions and never executes it.

**Always take a backup before cleaning.** `dryrun=1` is the safe way to see what would change first.

## Output

Every scanner reports findings in one shared format, so results are easy to grep, sort, and paste into a ticket:

```
SEVERITY,TYPE,path,detail
```

The first three fields never contain commas; everything after the third comma is free-form detail. Because paths and log content come from a compromised host, `%`, control characters, and (in the path field) commas are percent-encoded, so a crafted filename can't shift fields or inject fake finding lines. Severities are `HIGH`, `MEDIUM`, `LOW`, `INFO`, and `ERROR`. Indented lines under a finding are supporting context (example log lines, top source IPs). For example:

```
HIGH,MALWARE_CLEANED,/path/to/file.js,javascript_ndsw
HIGH,MALWARE_FOUND,/path/to/file.js,javascript_ndsw (dry run: file not modified)
HIGH,MALWARE_FOUND,/path/to/link.js,javascript_ndsw (symbolic link to /shared/file.js: never modified, clean the file it points to)
HIGH,CRONTAB_IOC,crontab,crontab.tmp.006: * * * * * echo ... | base64 --decode > /tmp/x
MEDIUM,LOG_IOC,/var/log/apache2/access.log,access.xmlrpc.flood: 4182 hit(s) - High volume of xmlrpc.php POSTs, ...
```

Log IoCs report as `MEDIUM` (attack attempts, including failed ones) except traffic to a shell already on disk, which is `HIGH`. Noisy-by-nature signatures (e.g. `wp-login.php` POSTs) only fire above a volume threshold, so normal traffic doesn't raise alarms.

### JSON output and exit codes

`format=json` (CLI) or `--format=json` (WP-CLI) switches stdout to NDJSON — one event object per line, with raw (JSON-escaped) values:

```
{"event":"finding","severity":"HIGH","type":"LOG_IOC","path":"...","detail":"...","context":["e.g. ..."]}
{"event":"summary","scan":"integrity","MODIFIED":1,"MISSING":0,...}
```

Bytes that are not valid UTF-8 (a file name, a log line, a database value cut in the middle of a character) cannot be JSON: they become U+FFFD in JSON output, in the admin page's table and in recovery mode, so the finding is still reported. Text output prints the raw bytes.

Progress and informational text moves to stderr, so stdout is pure machine-readable events for pipelines. A usage/fatal error (bad arguments, unreadable target, DB unreachable in `scandb=1`) is emitted as `{"event":"error","detail":"..."}` before exiting 1, so the stream never carries loose text. The admin page's JSON export uses the same finding events.

Anything that blocks a check is an `ERROR` finding (exit 2), never a silent skip: a content folder that can't be located reports `CONTENT_DIR_UNKNOWN`, inside `scanall` an unreachable database reports `DB_UNAVAILABLE`, a failed query reports `DB_QUERY_FAILED`, an unreadable file `INTEGRITY_UNREADABLE` (or, in the signature scan, `FILE_UNREADABLE`), a folder that can't be listed the same two types (it used to be skipped), a symbolic link to a folder that a run able to modify files did not follow `SYMLINK_NOT_FOLLOWED`, reference checksums that could not be fetched or read `INTEGRITY_NO_REFERENCE` as an `ERROR` (as `INFO` it means there is no official reference for that package, or none in `checksumdir=`), the unscanned sites of a multisite network `DB_MULTISITE_PARTIAL`, a PHP file over the 2 MB signature-scan limit `FILE_TOO_LARGE` (larger non-PHP files report it as `INFO`), a signature whose regex the PCRE engine gave up on for one file (backtrack, recursion or JIT stack limit) `SIGNATURE_ERROR`, a log that can't be opened or decompressed `LOG_UNREADABLE`, and a crontab that can't be read (no `shell_exec`, no `crontab` binary) `CRONTAB_UNAVAILABLE`. A clean report means every scanner actually looked.

The exit code reflects the worst finding, so cron jobs and CI can alert on it: **0** clean (or INFO-only), **1** usage/fatal error, **2** LOW/MEDIUM/ERROR findings, **3** HIGH findings. Note that a successful cleanup also exits 3 — malware was found.

## What it checks

- **Files** — signature-based detection and cleanup of known malware injections (e.g. the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns), across common web extensions (`php`, `js`, `html`, ...). Cleaned files are written atomically (temp file + rename) so a failed write can never truncate the original. The plugin's own folder is never scanned. A built-in **detection set** of about 35 generic webshell and backdoor shapes reports `MALWARE_FOUND` and never cleans, not even in a real run: code or shell commands taken from the request (`eval($_POST[...])`, `system($_GET[...])`, request input used as a callback or include path), request-named file writes and uploaders that keep the client's file name (the looser forms, through a path or a variable, only in files with no WordPress capability, nonce or upload check), password-gated shells, known shell families (WSO/FilesMan, b374k, c99, r57, IndoXploit, Alfa), WP-VCD, NDSW with renamed variables, PHP behind an image header, includes of icons/images or of escape-coded paths, and obfuscation (`eval` of `base64_decode`/`gzinflate` output, `/e` regexes, reversed or rot13 function names, hex-escaped names, `chr()` chains, `$GLOBALS` array obfuscators, one-line dynamic calls). HIGH means a dangerous sink fed straight from the request, a password gate or a known family; MEDIUM is obfuscation that legitimate code almost never needs. A file nothing matched gets a second look with comments removed, `'ev'.'al'` fragments and `.=` appends joined, `${"_POST"}` read as `$_POST` and letter escapes decoded. The shapes are modelled on what php-malware-finder, AMWScan, signature-base, scr34m's scanner and Linux Malware Detect have in common, and are tested for false positives against WordPress core and about 2,200 popular plugins and 550 themes from wordpress.org: the remaining matches there are plugins that run PHP sent to them by design (Ad Inserter, VaultPress), a spam plugin's own scanner strings and one documentation comment.
- **Crontab** — runs `crontab -l` for the user PHP executes as and checks it for known persistence patterns (piped base64 decoders, pastebin downloads, tmp-dir droppers). Other users' crontabs and `/etc/cron.*` are not covered; if the command can't run, `CRONTAB_UNAVAILABLE` says so.
- **Access logs** — known attack traffic: webshell requests, PHP files served from `wp-content/uploads`, wp-file-manager / Slider Revolution / TimThumb exploit attempts, `.env` probes, directory traversal, code and PHP-CGI injection, user enumeration, and xmlrpc/wp-login brute-force floods. Correlation (`correlate=1` / `--correlate`, automatic in `scanall`) also reports files whose mtime falls within `window` seconds (default 300) of flagged traffic — `LOG_FILE_CORRELATION`, the "this request created that file" artifact. A hit is a strong lead; a miss clears nothing, since later edits or faked mtimes erase the link.
- **Integrity** — verifies WordPress core, every plugin, and every theme against official wordpress.org packages for the installed version. The core locale is the one the install names in `wp-includes/version.php` (a localized package sets `$wp_local_package` there, and its translated core files only match that locale's checksums); `locale=xx_XX` / `--locale` overrides it. Reports `INTEGRITY_MODIFIED` (checksum mismatch), `INTEGRITY_MISSING` (file from the package gone), and `INTEGRITY_EXTRA` (file on disk that the package doesn't contain — extra PHP inside core or a plugin is the classic dropped webshell and reports as `HIGH`; commonly legitimate extras like `error_log` and the Wordfence WAF bootstrap report as `INFO` with an explanation). Packages that can't be verified (custom/premium plugins and themes, child themes, versions not in the archive) report as `INTEGRITY_NO_REFERENCE`, so a clean report never silently means "unchecked". Core and plugins use the checksum APIs; themes have no checksum API, so the manifest is built by hashing the official theme zip (requires the PHP zip extension). Bundled themes/plugins under `wp-content` are skipped in the core pass, and `wp-config.php` is ignored.
- **Quick checks** — cheap, high-signal places attackers hide: executable PHP inside `wp-content/uploads` (`UPLOADS_PHP`, HIGH), `auto_prepend_file`/`auto_append_file` directives in `.user.ini`/`php.ini`/`.htaccess` that execute a file on every request (`PHP_PREPEND` — the Wordfence WAF bootstrap is recognized and reported as INFO), an inventory of mu-plugins, which load with no activation step (`MU_PLUGIN`, INFO), and hidden dotfile PHP (`HIDDEN_PHP`).
- **Database** — read-only (SELECT-only) scan. Reports an inventory of administrator accounts (`DB_ADMIN_USER`, INFO — confirm each) with admins created in the last 30 days escalated to `DB_NEW_ADMIN` (MEDIUM, the classic takeover artifact); non-administrator roles that were granted takeover capabilities such as `manage_options`/`edit_users` in the `user_roles` option (`DB_ROLE_CAPS`, MEDIUM — role-editor plugins and shop-manager roles do this legitimately, so verify rather than assume); injected option values (`DB_OPTION_IOC` — PHP/eval, hidden iframes, obfuscated JS, remote scripts), `siteurl`/`home` hijacks (`DB_SITE_URL`), and `active_plugins` tampering (`DB_ACTIVE_PLUGIN` — path traversal or entries missing on disk); and script/PHP injections in post content (`DB_POST_IOC`, found via a server-side `LIKE` prefilter so the posts table isn't pulled wholesale; revisions are skipped so each injected post reports once). Every value is pattern-matched only and **never `unserialize()`d** — hostile serialized data can trigger PHP object injection. In the standalone CLI, if mysqli is missing, credentials can't be read (`getenv()`-style configs can't be parsed without executing them), or the DB is unreachable, `scandb=1` exits 1 with an error while `scanall=1` reports `DB_UNAVAILABLE` (ERROR) and continues; a query that fails mid-scan reports `DB_QUERY_FAILED` for that table. On a multisite network only one site's tables are read (the main site's in the CLI, the tables of the site the scan runs on in WordPress): the scan says so with `DB_MULTISITE_PARTIAL` (ERROR) rather than letting "nothing found" cover the other sites.
- **Timestamps** — report-only heuristics for when files were touched apart from their package. Every check is an outlier *within* one package (core, a plugin, a theme), never a comparison against a site-wide date, which would drown in false positives after any migration. `TIMESTAMP_OUTLIER` flags a handful of files modified after the package's dominant install/update cluster (the classic backdoored `functions.php` or dropped loader); a large newer cluster is a legitimate update and doesn't flag. `TIMESTAMP_TIMESTOMP` flags PHP files whose mtime sits far behind their ctime — `touch -t` can back-date content time, but the inode change time can't be set without root — and only when few files in the package show it, since migrations and `rsync -a` do that to whole trees. Timestamps are leads, not proof: attackers fake them and updates rewrite them, so these findings never feed a cleanup action and a clean result does not clear a file.

### Restoring files

With `scanintegrity=1 restore=1` (CLI) or `wp elderward integrity --restore`, every `INTEGRITY_MODIFIED` and `INTEGRITY_MISSING` file is restored from the official package zip for the exact installed version. Safety properties:

- **Take a backup first**, and preview with `dryrun=1` / `--dryrun` (reports `INTEGRITY_RESTORABLE` without writing).
- Every file is **byte-verified against the reference checksum manifest before writing** — a tampered or mismatched zip is refused (`RESTORE_FAILED`), never written.
- `EXTRA` files are **never touched**: deleting unknown files is the operator's call.
- Every write **stays inside the package directory**: a manifest or zip entry that is not a plain relative path is refused, a target that is a symbolic link is refused, and a target folder that resolves (through a planted symlink) outside the plugin, theme or core tree is refused, each as `RESTORE_FAILED`. Version headers that are not plain version strings make the package `INTEGRITY_NO_REFERENCE` instead of reaching a URL or a file name.
- Overwriting a backdoored file destroys evidence. Set `quarantinedir=/path` / `--quarantine-dir` (outside the webroot) to copy each original aside as `*.quarantine` before it's overwritten; if quarantining fails, the file is left alone.
- Offline: with `checksumdir=` / `--checksum-dir`, package zips are read as `core-{version}.zip` / `plugin-{slug}-{version}.zip` / `theme-{slug}-{version}.zip` from the same directory. Non-`en_US` core restore isn't supported yet (plugin and theme restore are locale-independent).

### Integrity checks without network access

On hosts with no outbound network, download the reference data on another machine, put it in one directory, and pass `checksumdir=/path` (`--checksum-dir`). With that option set the tool never touches the network: anything missing from the directory reports as `INTEGRITY_NO_REFERENCE`.

```
core-{version}.json           from https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}
plugin-{slug}-{version}.json  from https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json
theme-{slug}-{version}.zip    from https://downloads.wordpress.org/theme/{slug}.{version}.zip
```

Themes have no checksum API, so verifying them offline needs the theme package zip itself (and the PHP zip extension). The core manifest is named by version only: for a non-English site, download it with your locale in the URL and still save it as `core-{version}.json`. For restores, add `core-{version}.zip` and `plugin-{slug}-{version}.zip` (from `https://wordpress.org/wordpress-{version}.zip` and `https://downloads.wordpress.org/plugin/{slug}.{version}.zip`); the theme zip already covers theme restores.

TLS verification stays on for all API requests — this tool runs on already-compromised hosts, and an "all clean" answer must not be attacker-supplied.

## Adding signatures

File cleanup signatures live in `Signatures::builtin_cleanup()` in `includes/engine/signatures.php`, keyed by a unique name (the report-only detection set is `Signatures::builtin_detection()`, with the action `array('detect' => SEVERITY, 'description' => ...)`; every one needs a `pos--<name>` fixture in `tests/fixtures/detection/`):

```php
'javascript_example' => array(
    // Cheap check run first on every file: array('string' => needle) for a
    // fast strpos lookup (preferred), or array('regex' => pattern).
    'prefilter' => array('string' => 'example-malware-marker'),
    // Zero or more further conditions that must ALL also match. The
    // prefilter already counts, so don't repeat it here.
    'triggers'  => array(
        array('regex' => '/eval\(example_\w+\(/'),
    ),
    // What to do with a confirmed file: remove every match of a pattern,
    // or delete the file outright.
    'action'    => array('remove_regex' => '/eval\(example_\w+\([^;]+;/s'),
    // 'action' => array('delete_file' => true),
),
```

### Custom signatures

Site-specific signatures do not need code changes. Write them in the plugin's Signatures tab or in a JSON file, the same format the tab exports. **[Writing malware signatures](docs/writing-signatures.md)** is the full guide: what each target sees, turning a sample into a rule, keeping it fast and free of false positives, testing, sharing, and worked examples ([`docs/examples/signatures.json`](docs/examples/signatures.json)).

```json
{"elderward_signatures": 1, "signatures": [
  {"id": "acme-loader", "target": "file", "severity": "HIGH", "description": "ACME loader backdoor",
   "match": [{"string": "acme_loader"}, {"regex": "/eval\\s*\\(\\s*\\$/"}]},
  {"id": "casino-spam", "target": "db_post", "severity": "LOW", "pattern": "@casino-bonus\\.example@i"}
]}
```

`target` is `file`, `db_option` or `db_post`. File signatures list 1 to 10 conditions that must all match, the first being the prefilter. Database signatures take one `pattern`; post signatures see the content of every live post (with a custom post signature installed, the scan reads all posts instead of only those with code-like markers). A custom signature always reports, as `SIGNATURE_MATCH` for files with its own severity, and never cleans, not even in a real `wp elderward scan` run. Built-in signatures are checked first. A regex that does not compile, or that matches an empty string, is refused. The standalone CLI takes the same file:

```
php bin/elderward.php scanall=1 scandirectory=/var/www/html signatures=/path/signatures.json
```

Regexes are full PCRE patterns with delimiters and flags. Every pattern (including the crontab, access log and database sets) is compile-checked before a scan starts, so a malformed regex stops the run and names the broken signature instead of silently never matching. `remove_regex` fails loudly if it matched nothing, and dry run covers both action types.

## Translations

The admin pages use the `elderward` text domain; translations ship in `languages/` (Brazilian Portuguese: `elderward-pt_BR.po`, compiled to `.mo` and `.l10n.php`) and follow each user's language. Language packs from translate.wordpress.org, once the plugin is in the directory, take precedence. The recovery page runs without WordPress, so it has its own table, `includes/recovery/i18n/pt_BR.php` (English text => translation); it picks the language from the browser and offers a switch in its header. Finding details from the engine stay in English everywhere, like the CLI output and exports.

After changing interface strings, refresh the template and the translations (WP-CLI 2.8+):

```
wp i18n make-pot . languages/elderward.pot --slug=elderward --domain=elderward \
    --exclude=tests,site,vendor,node_modules,includes/engine,includes/recovery,bin
wp i18n update-po languages/elderward.pot languages/elderward-pt_BR.po   # then translate the new entries
wp i18n make-mo languages && wp i18n make-php languages
```

A string added to the recovery page goes through `App::t()` / `App::e()` and needs its line in `includes/recovery/i18n/pt_BR.php`; keep the placeholders (`%s`, `%1$s`, `%d`) identical.

## Development

```
includes/engine/   the scanner engine (namespace Elderward\Engine, PHP 5.6 syntax, no WordPress dependency)
includes/plugin/   the WordPress side (PHP 7.2+): admin page, WP-CLI, $wpdb and HTTP API adapters
bin/elderward.php  the standalone CLI entry
tests/regress.sh   old-vs-new output diff over synthetic fixtures (needs the MariaDB fixture for the DB cases)
tests/chunking.php proves a scan run one unit per request yields the same findings as one uninterrupted run
tests/admin-ui.js  Playwright run through the admin page
tests/background-ui.js, findings-ui.js, signatures-ui.js   Playwright: runner/schedule, false positives and samples, signature editor
tests/hardening-ui.js   Playwright: Hardening tab on an Apache site (apply, check, Nginx download, remove)
tests/recovery.js  Playwright: recovery key, recovery page on a broken site, scan, export, revoke
tests/mcp-stdio.js MCP client session over STDIO through the MCP Adapter
tests/checksums.sh checksums.json is current; the self-check on a release-like copy
tests/tamper.sh    sealed settings on a test site (WP-CLI); tests/tamper-ui.js: the review notices
build/make-checksums.php   writes checksums.json (run it after changing any shipped file)
recovery.php, includes/recovery/   recovery mode (runs without WordPress; PHP 5.6 syntax)
site/              the project homepage (static HTML, not part of the plugin zip)
```

`.distignore` lists what stays out of the WordPress.org package (tests, tooling, docs for contributors, the homepage).

`composer install` brings PHPCS with the WordPress and PHPCompatibility standards; `composer phpcs` must come back clean before a release. `TESTPLAN.md` lists the fixtures and the live wordpress.org tests that need a networked site.

## Limitations

- Signature-based: it finds and removes *known* malware and reports common backdoor shapes. Multi-stage loaders, mailers and file managers without an obvious sink still get through. A clean scan is not proof of a clean site.
- Log IoC checks show attack *attempts*, including plenty that failed (status 403/404). Treat them as awareness and a starting point for investigation, not confirmation of compromise.
- A signature regex the PCRE engine gives up on for a file (`pcre.backtrack_limit`, `pcre.recursion_limit`, the JIT stack) is reported as `SIGNATURE_ERROR` naming the signature, never taken as "no match". The built-in set is written so this does not happen; a custom signature with nested repeats (`(a+)+`) can.
- The file scanner does not read files larger than 2 MB. Each one is reported as `FILE_TOO_LARGE`: `INFO` for JavaScript, CSS and other non-PHP files (WordPress core ships several bundles that size), `ERROR` for PHP, where a file that large is unusual. Review those by hand or with `scanintegrity=1`.
- Uploads and mu-plugins are expected inside the content folder. A site that moves them separately (the `UPLOADS` constant, the `upload_path` option, `WPMU_PLUGIN_DIR`) still has them signature-scanned when they sit inside the root, but `UPLOADS_PHP` and `MU_PLUGIN` don't recognise them there.
- Report-only scans follow a symbolic link to a folder (a linked uploads folder, a release-style deploy), but never to a parent folder, to the filesystem root, or to the same folder twice. A run that can modify files (the signature scan without `dryrun`) does not follow them: each one is reported as `SYMLINK_NOT_FOLLOWED` and has to be scanned on its own.
- On a multisite network the database scan reads one site's tables. The other sites' options and posts, their administrators and the super admin list are not scanned yet; the scan reports that as `DB_MULTISITE_PARTIAL`.
- Scans are report-only in this release; cleanup and restore run from the command line. The admin pages change files only when you apply hardening rules (`.htaccess`) or create a recovery key.
- Hardening rules are written for Apache/LiteSpeed only; Nginx configuration has to be included by someone with server access. IIS is not supported.
- The hardening check cannot tell a refusal by the web server from one by a firewall or CDN in front of the site.
- AI assistant access needs WordPress 6.9+ and the MCP Adapter plugin. What you share with an assistant goes to its provider.
- Background and scheduled scans depend on WP-Cron: the site must be able to request its own `wp-cron.php`, or a server cron job must call it. The page falls back to stepping the scan itself when WP-Cron stops responding.

## License

GPLv2 or later. See `LICENSE`.
