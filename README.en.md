<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/img/facheiro-logo.svg">
    <img src="assets/img/facheiro-logo-on-light.svg" alt="Facheiro" width="400">
  </picture>
</p>

<p align="center"><a href="README.md">Leia em português</a></p>

Facheiro is a free malware scanner and incident-response toolkit for WordPress sites. It checks files for signs of compromise and can remove known malware, verifies core, plugins and themes against the official wordpress.org packages, scans the database for rogue administrators and injected content, and reads access logs for known indicators of compromise (IoCs) so you can understand how the attack happened — not just clean up after it.

What you get:

- **A report-only scan of everything** from its own **Facheiro** admin menu, in the background through WP-Cron or on a schedule, with findings worst-first, false-positive marks bound to the reviewed file, encrypted sample downloads and NDJSON export.
- **Custom signatures** written and tested in the admin (detection-only), shared as JSON with the CLI.
- **Server hardening** for Apache/LiteSpeed (`.htaccess`, applied with a health check and automatic rollback) and Nginx (a configuration file to include), from a Recommended or Strict template or protection by protection, and a live check of what the server enforces.
- **Recovery mode**: a key-protected page that works when WordPress itself does not load (white screen, critical error), shows what broke the site and runs the full scan.
- **AI assistant tools** over MCP (WordPress 6.9+ with the MCP Adapter plugin), so Claude, ChatGPT, Antigravity or Cursor can run scans, explain the findings and draft signatures with you, and never clean or change files.
- **Cleanup and restore** from WP-CLI or the standalone CLI, with a dry run first.
- **Brazilian Portuguese and English** admin pages and recovery page: the plugin is written in Portuguese and ships with an English translation.

It runs four ways, all on the same engine:

- **WordPress plugin** — the admin pages above.
- **WP-CLI** — `wp facheiro ...` runs every scanner, cleanup, restore and hardening command, with text or NDJSON output and alerting exit codes.
- **Recovery mode** — `recovery.php` in the plugin folder, when WordPress no longer loads but the web server still runs PHP.
- **Standalone CLI** — `php bin/facheiro.php ...` needs no working WordPress at all: upload the folder to a dead site and scan it from a shell.

Nothing leaves the server on its own. The only outbound requests go to wordpress.org during the integrity check (checksum manifests and official packages); hardening checks only request the site itself.

It started as a variation of the Jetpack Cleanup Util, packaged so anyone can run it on their own host. The name comes from the facheiro, a cactus of the Brazilian caatinga: in the dry season the sertanejo burns its thorns off, and what is left is water and feed.

## Documentation

- **[Wiki](https://github.com/fcavallari/Facheiro/wiki)**, the user guides: [the plugin and WP-CLI](https://github.com/fcavallari/Facheiro/wiki/Plugin-and-WP-CLI), [hardening](https://github.com/fcavallari/Facheiro/wiki/Hardening), [recovery mode](https://github.com/fcavallari/Facheiro/wiki/Recovery-mode), [tamper detection](https://github.com/fcavallari/Facheiro/wiki/Tamper-detection), [AI assistants](https://github.com/fcavallari/Facheiro/wiki/AI-assistants), [the standalone CLI](https://github.com/fcavallari/Facheiro/wiki/Standalone-CLI), [restoring files and offline checks](https://github.com/fcavallari/Facheiro/wiki/Restoring-files-and-offline-checks), [custom signatures](https://github.com/fcavallari/Facheiro/wiki/Custom-signatures) and [limitations](https://github.com/fcavallari/Facheiro/wiki/Limitations).
- **[Reference](https://facheiro.space.fast/en/reference/)**: the output format, JSON events, exit codes, what each scanner checks and the PHP extensions each one needs.
- **[Writing malware signatures](docs/writing-signatures.md)**: how to write and test custom signatures.
- **[Development](docs/development.en.md)**: built-in signatures, translations, tests and the release package.
- **[facheiro.space.fast](https://facheiro.space.fast/)**: the project homepage, in Portuguese with English at `/en/` (the source is in `site/`).

## Requirements

- WordPress 6.0+ and PHP 7.2+ for the plugin; the standalone CLI and recovery mode run on PHP 5.6+
- Shell access (WP-CLI or `php`) to clean or restore files; the admin pages need no shell
- WordPress 6.9+ and the [MCP Adapter](https://github.com/WordPress/mcp-adapter) plugin for the AI assistant tools
- Apache or LiteSpeed with `AllowOverride` for hardening rules Facheiro writes itself; on Nginx you include the generated file in the server configuration

Some scanners use PHP extensions (zlib, curl, zip, mysqli) or `shell_exec`; a missing one is reported as an `ERROR` finding rather than skipped. The [reference](https://facheiro.space.fast/en/reference/#php-extensions) says which scanner needs which.

## Installation

Facheiro is not on WordPress.org yet. Install it from this repository; the folder must be named `facheiro`:

```
cd wp-content/plugins
git clone https://github.com/fcavallari/Facheiro.git facheiro
wp plugin activate facheiro
```

(or download the repository as a zip, unpack it as `wp-content/plugins/facheiro/`, and activate it on the Plugins screen).

## First steps

1. **Facheiro (admin menu) → Start scan.** The scan runs in the background through WP-Cron and changes nothing on the site. Findings appear worst-first.
2. **Review the findings**: mark false positives, download samples for analysis and export the report (see [the plugin and WP-CLI](https://github.com/fcavallari/Facheiro/wiki/Plugin-and-WP-CLI)).
3. **Act on the results from WP-CLI**, after taking a backup:

```
wp facheiro scan --dryrun                        # preview the signature cleanup
wp facheiro scan                                 # remove known malware from infected files
wp facheiro integrity --restore --dryrun         # preview restoring modified/missing core, plugin, theme files
wp facheiro integrity --restore --quarantine-dir=/path/outside/webroot
```

If the site no longer loads, use [recovery mode](https://github.com/fcavallari/Facheiro/wiki/Recovery-mode) or [the standalone CLI](https://github.com/fcavallari/Facheiro/wiki/Standalone-CLI):

```
php bin/facheiro.php scanall=1 scandirectory=/path/to/wp-root   # every scanner, report-only
php bin/facheiro.php dryrun=1 scandirectory=/path/to/site        # preview the signature cleanup, write nothing
```

In the standalone CLI the signature cleanup is the default mode: with no mode option the script modifies files, and `dryrun=1` is the switch that makes it report-only. **Always back up before cleaning.**

A clean scan is not proof of a clean site: Facheiro finds and removes *known* malware and reports common backdoor shapes. See the [limitations](https://github.com/fcavallari/Facheiro/wiki/Limitations).

## License

GPLv2 or later. See `LICENSE`.
