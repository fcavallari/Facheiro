<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/img/elderward-logo.svg">
    <img src="assets/img/elderward-logo-on-light.svg" alt="Elderward" width="400">
  </picture>
</p>


Elderward is a free malware scanner and incident-response toolkit for WordPress sites. It checks files for signs of compromise and can remove known malware, verifies core, plugins and themes against the official wordpress.org packages, scans the database for rogue administrators and injected content, and reads access logs for known indicators of compromise (IoCs) so you can understand how the attack happened — not just clean up after it.

It runs three ways, all on the same engine:

- **WordPress plugin** — its own **Elderward** admin menu runs a report-only scan of everything and shows the findings; `wp elderward ...` runs every scanner, cleanup and restore from WP-CLI.
- **Standalone CLI** — `php bin/elderward.php ...` needs no working WordPress: upload the folder to a dead site and scan it.
- Nothing leaves the server. The only outbound requests go to wordpress.org, during the integrity check, for checksum manifests and official packages.

It started as a variation of the Jetpack Cleanup Util, packaged so anyone can run it on their own host.

## Requirements

- WordPress 6.0+ and PHP 7.2+ for the plugin; the standalone CLI runs on PHP 5.6+
- Shell access (WP-CLI or `php`) to clean or restore files; the admin page needs no shell

The signature scan, quick checks and timestamp checks need nothing else. The other scanners use PHP extensions that locked-down hosts sometimes lack; a missing one is reported as an `ERROR` finding rather than skipped:

| Needed for | Requirement |
|---|---|
| `.gz` rotated logs | zlib extension |
| Online integrity checks (standalone CLI) | curl extension, or `allow_url_fopen=On` (the plugin uses the WordPress HTTP API) |
| Theme verification and every restore | zip extension |
| Database scan (standalone CLI) | mysqli extension (the plugin uses WordPress' connection) |
| Crontab scan | `shell_exec` not in `disable_functions` |

## The plugin

Install the `elderward` folder under `wp-content/plugins/` and activate it. Then:

1. **Elderward (admin menu) → Start scan.** The scan runs in the background through WP-Cron, so you can close the tab and come back; it changes nothing on the site. Findings appear worst-first with severity filters and can be exported as text or NDJSON. **Settings** on the same page set the access log file or directory that every scan checks, switch scans to run only while the page is open (for hosts where WP-Cron is unreliable), and set up daily, twice-daily or weekly automatic scans. Each setting has a **?** with more detail, and the screen's **Help** tab explains the whole page.
2. **Review the findings.** *False positive* records a reviewed, benign finding with a note: later scans keep it in the record (and in the JSON export, flagged `"false_positive": true`) but out of the counts and the default view. A mark on a file stores the file's SHA-256 and stops applying as soon as the file changes, so the finding comes back. *Download sample* packs a flagged file into a zip encrypted with the password `infected` (AES-256), with a `manifest.json`, for you to submit to an analyst or sandbox; Elderward never uploads anything, and never packages `wp-config.php` or files outside the WordPress root. File findings also show the SHA-256 with a VirusTotal lookup link (hash only, opened by your browser).
3. **Signatures tab.** Add custom signatures for files, option values or post content, test them against a pasted sample or a file of the site, and import/export them as JSON (see [Custom signatures](#custom-signatures)). Custom signatures only detect.
4. **Act on the results from WP-CLI**, after taking a backup:

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

`wp help elderward <command>` lists each command's options. On multisite the page lives under Network Admin > Settings and is limited to super admins.

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

The plugin stores the latest report in one table (`{prefix}elderward_findings`) and its scan state in an option; uninstalling removes both and the work folder under `wp-content/uploads/elderward/`.

## The standalone CLI

For a site that no longer loads, or a host without WP-CLI, run the same scanners straight from the plugin folder. Options are `key=value` arguments:

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

Progress and informational text moves to stderr, so stdout is pure machine-readable events for pipelines. A usage/fatal error (bad arguments, unreadable target, DB unreachable in `scandb=1`) is emitted as `{"event":"error","detail":"..."}` before exiting 1, so the stream never carries loose text. The admin page's JSON export uses the same finding events.

Anything that blocks a check is an `ERROR` finding (exit 2), never a silent skip: inside `scanall` an unreachable database reports `DB_UNAVAILABLE`, a failed query reports `DB_QUERY_FAILED`, an unreadable file `INTEGRITY_UNREADABLE`, a log that can't be opened or decompressed `LOG_UNREADABLE`, and a crontab that can't be read (no `shell_exec`, no `crontab` binary) `CRONTAB_UNAVAILABLE`. A clean report means every scanner actually looked.

The exit code reflects the worst finding, so cron jobs and CI can alert on it: **0** clean (or INFO-only), **1** usage/fatal error, **2** LOW/MEDIUM/ERROR findings, **3** HIGH findings. Note that a successful cleanup also exits 3 — malware was found.

## What it checks

- **Files** — signature-based detection and cleanup of known malware injections (e.g. the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns), across common web extensions (`php`, `js`, `html`, ...). Cleaned files are written atomically (temp file + rename) so a failed write can never truncate the original. The plugin's own folder is never scanned.
- **Crontab** — runs `crontab -l` for the user PHP executes as and checks it for known persistence patterns (piped base64 decoders, pastebin downloads, tmp-dir droppers). Other users' crontabs and `/etc/cron.*` are not covered; if the command can't run, `CRONTAB_UNAVAILABLE` says so.
- **Access logs** — known attack traffic: webshell requests, PHP files served from `wp-content/uploads`, wp-file-manager / Slider Revolution / TimThumb exploit attempts, `.env` probes, directory traversal, code and PHP-CGI injection, user enumeration, and xmlrpc/wp-login brute-force floods. Correlation (`correlate=1` / `--correlate`, automatic in `scanall`) also reports files whose mtime falls within `window` seconds (default 300) of flagged traffic — `LOG_FILE_CORRELATION`, the "this request created that file" artifact. A hit is a strong lead; a miss clears nothing, since later edits or faked mtimes erase the link.
- **Integrity** — verifies WordPress core, every plugin, and every theme against official wordpress.org packages for the installed version (pass `locale=xx_XX` / `--locale` for a non-English core, otherwise its translated files show as modified). Reports `INTEGRITY_MODIFIED` (checksum mismatch), `INTEGRITY_MISSING` (file from the package gone), and `INTEGRITY_EXTRA` (file on disk that the package doesn't contain — extra PHP inside core or a plugin is the classic dropped webshell and reports as `HIGH`; commonly legitimate extras like `error_log` and the Wordfence WAF bootstrap report as `INFO` with an explanation). Packages that can't be verified (custom/premium plugins and themes, child themes, versions not in the archive) report as `INTEGRITY_NO_REFERENCE`, so a clean report never silently means "unchecked". Core and plugins use the checksum APIs; themes have no checksum API, so the manifest is built by hashing the official theme zip (requires the PHP zip extension). Bundled themes/plugins under `wp-content` are skipped in the core pass, and `wp-config.php` is ignored.
- **Quick checks** — cheap, high-signal places attackers hide: executable PHP inside `wp-content/uploads` (`UPLOADS_PHP`, HIGH), `auto_prepend_file`/`auto_append_file` directives in `.user.ini`/`php.ini`/`.htaccess` that execute a file on every request (`PHP_PREPEND` — the Wordfence WAF bootstrap is recognized and reported as INFO), an inventory of mu-plugins, which load with no activation step (`MU_PLUGIN`, INFO), and hidden dotfile PHP (`HIDDEN_PHP`).
- **Database** — read-only (SELECT-only) scan. Reports an inventory of administrator accounts (`DB_ADMIN_USER`, INFO — confirm each) with admins created in the last 30 days escalated to `DB_NEW_ADMIN` (MEDIUM, the classic takeover artifact); non-administrator roles that were granted takeover capabilities such as `manage_options`/`edit_users` in the `user_roles` option (`DB_ROLE_CAPS`, MEDIUM — role-editor plugins and shop-manager roles do this legitimately, so verify rather than assume); injected option values (`DB_OPTION_IOC` — PHP/eval, hidden iframes, obfuscated JS, remote scripts), `siteurl`/`home` hijacks (`DB_SITE_URL`), and `active_plugins` tampering (`DB_ACTIVE_PLUGIN` — path traversal or entries missing on disk); and script/PHP injections in post content (`DB_POST_IOC`, found via a server-side `LIKE` prefilter so the posts table isn't pulled wholesale; revisions are skipped so each injected post reports once). Every value is pattern-matched only and **never `unserialize()`d** — hostile serialized data can trigger PHP object injection. In the standalone CLI, if mysqli is missing, credentials can't be read (`getenv()`-style configs can't be parsed without executing them), or the DB is unreachable, `scandb=1` exits 1 with an error while `scanall=1` reports `DB_UNAVAILABLE` (ERROR) and continues; a query that fails mid-scan reports `DB_QUERY_FAILED` for that table.
- **Timestamps** — report-only heuristics for when files were touched apart from their package. Every check is an outlier *within* one package (core, a plugin, a theme), never a comparison against a site-wide date, which would drown in false positives after any migration. `TIMESTAMP_OUTLIER` flags a handful of files modified after the package's dominant install/update cluster (the classic backdoored `functions.php` or dropped loader); a large newer cluster is a legitimate update and doesn't flag. `TIMESTAMP_TIMESTOMP` flags PHP files whose mtime sits far behind their ctime — `touch -t` can back-date content time, but the inode change time can't be set without root — and only when few files in the package show it, since migrations and `rsync -a` do that to whole trees. Timestamps are leads, not proof: attackers fake them and updates rewrite them, so these findings never feed a cleanup action and a clean result does not clear a file.

### Restoring files

With `scanintegrity=1 restore=1` (CLI) or `wp elderward integrity --restore`, every `INTEGRITY_MODIFIED` and `INTEGRITY_MISSING` file is restored from the official package zip for the exact installed version. Safety properties:

- **Take a backup first**, and preview with `dryrun=1` / `--dryrun` (reports `INTEGRITY_RESTORABLE` without writing).
- Every file is **byte-verified against the reference checksum manifest before writing** — a tampered or mismatched zip is refused (`RESTORE_FAILED`), never written.
- `EXTRA` files are **never touched**: deleting unknown files is the operator's call.
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

File cleanup signatures live in `Signatures::cleanup()` in `includes/engine/signatures.php`, keyed by a unique name:

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

Site-specific signatures do not need code changes. Write them in the plugin's Signatures tab or in a JSON file, the same format the tab exports:

```json
{"elderward_signatures": 1, "signatures": [
  {"id": "acme-loader", "target": "file", "severity": "HIGH", "description": "ACME loader backdoor",
   "match": [{"string": "acme_loader"}, {"regex": "/eval\\s*\\(\\s*\\$/"}]},
  {"id": "casino-spam", "target": "db_post", "severity": "LOW", "pattern": "@casino-bonus\\.example@i"}
]}
```

`target` is `file`, `db_option` or `db_post`. File signatures list 1 to 10 conditions that must all match, the first being the prefilter. Database signatures take one `pattern`. A custom signature always reports, as `SIGNATURE_MATCH` for files with its own severity, and never cleans, not even in a real `wp elderward scan` run. Built-in signatures are checked first. A regex that does not compile, or that matches an empty string, is refused. The standalone CLI takes the same file:

```
php bin/elderward.php scanall=1 scandirectory=/var/www/html signatures=/path/signatures.json
```

Regexes are full PCRE patterns with delimiters and flags. Every pattern (including the crontab, access log and database sets) is compile-checked before a scan starts, so a malformed regex stops the run and names the broken signature instead of silently never matching. `remove_regex` fails loudly if it matched nothing, and dry run covers both action types.

## Development

```
includes/engine/   the scanner engine (namespace Elderward\Engine, PHP 5.6 syntax, no WordPress dependency)
includes/plugin/   the WordPress side (PHP 7.2+): admin page, WP-CLI, $wpdb and HTTP API adapters
bin/elderward.php  the standalone CLI entry
tests/regress.sh   old-vs-new output diff over synthetic fixtures (needs the MariaDB fixture for the DB cases)
tests/chunking.php proves a scan run one unit per request yields the same findings as one uninterrupted run
tests/admin-ui.js  Playwright run through the admin page
tests/background-ui.js, findings-ui.js, signatures-ui.js   Playwright: runner/schedule, false positives and samples, signature editor
tests/mcp-stdio.js MCP client session over STDIO through the MCP Adapter
```

`composer install` brings PHPCS with the WordPress and PHPCompatibility standards; `composer phpcs` must come back clean before a release. `TESTPLAN.md` lists the fixtures and the live wordpress.org tests that need a networked site.

## Limitations

- Signature-based: it finds and removes *known* malware. A clean scan is not proof of a clean site.
- Log IoC checks show attack *attempts*, including plenty that failed (status 403/404). Treat them as awareness and a starting point for investigation, not confirmation of compromise.
- Files larger than 2 MB are skipped by the file scanner.
- The admin page is report-only in this release; cleanup and restore run from the command line.
- AI assistant access needs WordPress 6.9+ and the MCP Adapter plugin. What you share with an assistant goes to its provider.
- Background and scheduled scans depend on WP-Cron: the site must be able to request its own `wp-cron.php`, or a server cron job must call it. The page falls back to stepping the scan itself when WP-Cron stops responding.

## License

GPLv2 or later. See `LICENSE`.
