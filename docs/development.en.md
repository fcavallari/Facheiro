# Development

<p><a href="development.md">Leia em português</a></p>

This document is for people working on Facheiro's code. To use the plugin, start with the [README](../README.en.md) and the guides on the [wiki](https://github.com/fcavallari/Facheiro/wiki).

## Where each document lives

| Document | What it covers | When to update it |
|---|---|---|
| `README.md`, `README.en.md` | overview, install, first steps, links | when those change |
| [Wiki](https://github.com/fcavallari/Facheiro/wiki) | the user guides: plugin and WP-CLI, hardening, recovery mode, tamper detection, AI assistants, standalone CLI, restoring files, custom signatures, limitations | after the merge (the wiki is a separate repository, `Facheiro.wiki.git`, and does not follow branches) |
| `site/referencia/`, `site/en/reference/` | the reference: output format, JSON events, exit codes, `ERROR` findings, what each scanner checks, PHP extensions | in the same commit as the code: it is the output contract `tests/regress.sh` protects (publishing the site is a separate step) |
| `docs/writing-signatures.md` | the custom signature guide (English) | when the signature format changes |
| `docs/development.md`, `docs/development.en.md` | this document | in the same commit as the code |
| `readme.txt` | the plugin's WordPress.org page | when what users see changes |

Everything except `docs/writing-signatures.md` and `readme.txt` exists in Portuguese and English: when you change one, change the other. On the wiki each Portuguese page has an English counterpart, linked at the top.

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

## Translations

The plugin's own text is Brazilian Portuguese: that is the language of the strings in the source, under the `facheiro` text domain. English ships in `languages/` (`facheiro-en_US.po`, compiled to `.mo` and `.l10n.php`) and is shown to every user whose language is an English one; any other language sees the Portuguese text. Language packs from translate.wordpress.org, once the plugin is in the directory, take precedence. The recovery page runs without WordPress, so it has its own table, `includes/recovery/i18n/en.php` (Portuguese text => English); it picks the language from the browser and offers a switch in its header. Finding details from the engine stay in English everywhere, like the CLI output and exports; `includes/recovery/i18n/pt_BR.php` only translates the engine's stage names for the recovery page.

After changing interface strings, refresh the template and the English translation (WP-CLI 2.8+):

```
wp i18n make-pot . languages/facheiro.pot --slug=facheiro --domain=facheiro \
    --exclude=tests,site,vendor,node_modules,includes/engine,includes/recovery,bin
wp i18n update-po languages/facheiro.pot languages/facheiro-en_US.po   # then translate the new entries into English
wp i18n make-mo languages && wp i18n make-php languages
```

A string added to the recovery page is written in Portuguese, goes through `App::t()` / `App::e()` and needs its English line in `includes/recovery/i18n/en.php`; keep the placeholders (`%s`, `%1$s`, `%d`) identical.

## Development

```
includes/engine/   the scanner engine (namespace Facheiro\Engine, PHP 5.6 syntax, no WordPress dependency)
includes/plugin/   the WordPress side (PHP 7.2+): admin page, WP-CLI, $wpdb and HTTP API adapters
bin/facheiro.php  the standalone CLI entry
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
build/make-zip.php         builds dist/facheiro.zip, the release package
.claude/skills/pre-share-check/   Claude Code skill: checks a branch's changes before they are shared (runs the checks above, reviews the diff, changes nothing)
recovery.php, includes/recovery/   recovery mode (runs without WordPress; PHP 5.6 syntax)
site/              the project homepage and the reference (static HTML, not part of the plugin zip)
```

`.distignore` lists what stays out of the WordPress.org package (tests, tooling, docs for contributors, the homepage); `.gitattributes` leaves the same files out of `git archive` and GitHub's Download ZIP, and `build/make-checksums.php` refuses when the two lists disagree. Build the package with `php build/make-zip.php`: it writes `dist/facheiro.zip` with exactly the files listed under `files` in `checksums.json`, each checked against its checksum, and refuses when `checksums.json` is out of date. That zip is what to upload to WordPress.org, install on a test site and run Plugin Check on. A git checkout is not a release: Plugin Check reports its `tests/`, `build/`, `.claude/`, `CLAUDE.md` and the like as `application_detected`, `hidden_files`, `ai_instruction_directory`, `unexpected_markdown_file` and unguarded PHP.

`composer install` brings PHPCS with the WordPress and PHPCompatibility standards; `composer phpcs` must come back clean before a release. `TESTPLAN.md` lists the fixtures and the live wordpress.org tests that need a networked site.
