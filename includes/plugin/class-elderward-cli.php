<?php
/**
 * WP-CLI commands: the same scanners as the standalone CLI, same output
 * format and exit codes, run inside WordPress ($wpdb, WordPress HTTP API).
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Scans a WordPress install for malware and signs of compromise.
 *
 * Findings print as SEVERITY,TYPE,path,detail (or NDJSON with
 * --format=json). Exit codes: 0 clean or INFO-only, 1 usage/fatal error,
 * 2 LOW/MEDIUM/ERROR findings, 3 HIGH findings.
 */
class Elderward_CLI
{
    /**
     * Runs every scanner report-only and prints one severity-sorted report.
     *
     * ## OPTIONS
     *
     * [--log=<path>]
     * : Access log file or directory to scan for IoCs and correlate with file mtimes.
     *
     * [--window=<seconds>]
     * : Correlation window around flagged requests (default 300, minimum 60).
     *
     * [--checksum-dir=<path>]
     * : Pre-downloaded manifests/packages instead of the network (offline integrity check).
     *
     * [--locale=<locale>]
     * : Core locale for the checksum lookup (default en_US).
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward scanall
     *     wp elderward scanall --log=/var/log/apache2 --format=json
     *
     * @when after_wp_load
     */
    public function scanall($args, $assoc_args)
    {
        $options = array('scanall' => 1);
        $this->copy_option($assoc_args, 'log', $options, 'scanlog');
        $this->copy_option($assoc_args, 'window', $options, 'window');
        $this->copy_option($assoc_args, 'checksum-dir', $options, 'checksumdir');
        $this->copy_option($assoc_args, 'locale', $options, 'locale');
        $this->run($options, 'scanall', $assoc_args);
    }

    /**
     * Signature scan and cleanup of known malware (modifies files unless --dryrun).
     *
     * ## OPTIONS
     *
     * [<directory>]
     * : Directory to scan. Default: the WordPress root.
     *
     * [--dryrun]
     * : Report what would be cleaned without writing any file.
     *
     * [--allfiles]
     * : Scan every file, not just known-risky extensions.
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward scan --dryrun
     *     wp elderward scan
     *
     * @when after_wp_load
     */
    public function scan($args, $assoc_args)
    {
        $options = array();
        if (isset($args[0])) {
            $options['scandirectory'] = $args[0];
        }
        $this->copy_flag($assoc_args, 'dryrun', $options, 'dryrun');
        $this->copy_flag($assoc_args, 'allfiles', $options, 'allfiles');
        $this->run($options, 'signatures', $assoc_args);
    }

    /**
     * Quick high-signal checks: PHP in uploads, prepend directives, mu-plugins, hidden PHP.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function quick($args, $assoc_args)
    {
        $this->run(array('quickscan' => 1), 'quickscan', $assoc_args);
    }

    /**
     * Verifies core, plugins and themes against the official wordpress.org packages.
     *
     * ## OPTIONS
     *
     * [--restore]
     * : Restore MODIFIED and MISSING files from the official package zips (byte-verified first). Take a backup.
     *
     * [--dryrun]
     * : With --restore: report what would be restored without writing.
     *
     * [--quarantine-dir=<path>]
     * : With --restore: copy each original aside (as *.quarantine) before overwriting. Keep it outside the webroot.
     *
     * [--checksum-dir=<path>]
     * : Pre-downloaded manifests/packages instead of the network.
     *
     * [--locale=<locale>]
     * : Core locale for the checksum lookup (default en_US).
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward integrity
     *     wp elderward integrity --restore --dryrun
     *     wp elderward integrity --restore --quarantine-dir=/safe/place
     *
     * @when after_wp_load
     */
    public function integrity($args, $assoc_args)
    {
        $options = array('scanintegrity' => 1);
        $this->copy_flag($assoc_args, 'restore', $options, 'restore');
        $this->copy_flag($assoc_args, 'dryrun', $options, 'dryrun');
        $this->copy_option($assoc_args, 'quarantine-dir', $options, 'quarantinedir');
        $this->copy_option($assoc_args, 'checksum-dir', $options, 'checksumdir');
        $this->copy_option($assoc_args, 'locale', $options, 'locale');
        $this->run($options, 'scanintegrity', $assoc_args);
    }

    /**
     * Timestamp anomaly report (files modified apart from their package). Report-only.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function times($args, $assoc_args)
    {
        $this->run(array('scantimes' => 1), 'scantimes', $assoc_args);
    }

    /**
     * Read-only database scan: administrators, injected options, siteurl/home, active_plugins, posts.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function db($args, $assoc_args)
    {
        $this->run(array('scandb' => 1), 'scandb', $assoc_args);
    }

    /**
     * Checks the current user's crontab for known persistence patterns.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function cron($args, $assoc_args)
    {
        $this->run(array('scancron' => 1), 'scancron', $assoc_args);
    }

    /**
     * Scans an access log (file or directory, .gz supported) for indicators of compromise.
     *
     * ## OPTIONS
     *
     * <path>
     * : Access log file or directory of logs.
     *
     * [--correlate]
     * : Also report files whose mtime falls within --window seconds of flagged traffic.
     *
     * [--window=<seconds>]
     * : Correlation window (default 300, minimum 60).
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward log /var/log/apache2/access.log
     *     wp elderward log /var/log/apache2 --correlate
     *
     * @when after_wp_load
     */
    public function log($args, $assoc_args)
    {
        $options = array('scanlog' => $args[0]);
        $this->copy_flag($assoc_args, 'correlate', $options, 'correlate');
        $this->copy_option($assoc_args, 'window', $options, 'window');
        $this->run($options, 'scanlog', $assoc_args);
    }

    private function copy_option(array $assoc_args, $from, array &$options, $to)
    {
        if (isset($assoc_args[$from]) && '' !== $assoc_args[$from]) {
            $options[$to] = $assoc_args[$from];
        }
    }

    private function copy_flag(array $assoc_args, $from, array &$options, $to)
    {
        if (!empty($assoc_args[$from])) {
            $options[$to] = 1;
        }
    }

    /**
     * Hardens the web server: prints, applies, removes or checks the rules.
     *
     * Apache/LiteSpeed rules are written into .htaccess files between
     * "# BEGIN Elderward" and "# END Elderward"; the site is checked before
     * and after, and every file is put back if it stops answering. For
     * Nginx, --print outputs the file to include in the server block.
     *
     * ## OPTIONS
     *
     * [--server=<server>]
     * : apache (also LiteSpeed) or nginx. Default: detected, else apache.
     *
     * [--preset=<preset>]
     * : recommended (default) or strict.
     *
     * [--features=<list>]
     * : Comma-separated protections instead of a preset: uploads_php,
     * core_includes, config, sensitive, dotfiles, indexes, themes_php,
     * headers, xmlrpc, plugins_php.
     *
     * [--print]
     * : Print the rules (the default when nothing else is asked).
     *
     * [--apply]
     * : Write the .htaccess rules (Apache/LiteSpeed only).
     *
     * [--unverified]
     * : With --apply: write the rules even when the site cannot reach
     * itself over HTTP, so nothing can be checked or undone automatically.
     *
     * [--remove]
     * : Remove every Elderward rule from the .htaccess files.
     *
     * [--check]
     * : Send test requests to the live site and report what it enforces.
     *
     * ## EXAMPLES
     *
     *     wp elderward harden --server=nginx --print > /etc/nginx/snippets/elderward.conf
     *     wp elderward harden --apply
     *     wp elderward harden --preset=strict --apply
     *     wp elderward harden --check
     *
     * @when after_wp_load
     */
    public function harden($args, $assoc_args)
    {
        $detected = Elderward_Hardening::detect_server();
        $server = isset($assoc_args['server']) ? strtolower($assoc_args['server']) : (null === $detected ? 'apache' : $detected);
        if (!array_key_exists($server, Elderward_Hardening::servers())) {
            WP_CLI::error('--server must be apache or nginx.');
        }
        $preset = isset($assoc_args['preset']) ? strtolower($assoc_args['preset']) : 'recommended';
        if (isset($assoc_args['features'])) {
            $features = Elderward_Hardening::clean_features(explode(',', $assoc_args['features']));
            $unknown = array_diff(array_map('trim', explode(',', $assoc_args['features'])), $features, array(''));
            if (!empty($unknown)) {
                WP_CLI::error('Unknown protection: ' . implode(', ', $unknown));
            }
            $preset = 'custom';
        } elseif (in_array($preset, array('recommended', 'strict'), true)) {
            $features = Elderward_Hardening::preset_features($preset);
        } else {
            WP_CLI::error('--preset must be recommended or strict.');
        }

        if (isset($assoc_args['check'])) {
            $failed = false;
            foreach (Elderward_Hardening::check() as $id => $result) {
                WP_CLI::line(sprintf('%-9s %-14s %s', strtoupper($result['status']), $id, $result['detail']));
                $failed = $failed || ('exposed' === $result['status'] && in_array($id, $features, true));
            }
            WP_CLI::halt($failed ? 2 : 0);
        }
        if (isset($assoc_args['apply']) || isset($assoc_args['remove'])) {
            if ('apache' !== $server) {
                WP_CLI::error('Elderward writes rules only for Apache/LiteSpeed. For Nginx, use --print and include the file.');
            }
            Elderward_Hardening::remember($server, $preset, $features);
            $report = isset($assoc_args['remove']) ? Elderward_Hardening::remove() : Elderward_Hardening::apply($features, isset($assoc_args['unverified']));
            foreach ($report['files'] as $file) {
                WP_CLI::line(sprintf('%-8s %s', $file['action'], $file['file']));
            }
            if (!empty($report['unverifiable'])) {
                WP_CLI::error('This site cannot reach itself over HTTP, so the change could not be checked or undone. Nothing was changed. Run again with --unverified to write the rules anyway, and open the site in a browser right after.');
            }
            if (!$report['ok']) {
                WP_CLI::error('' !== $report['message'] ? $report['message'] : 'The rules could not be written.');
            }
            if (empty($report['files'])) {
                WP_CLI::success('Nothing to change.');
                return;
            }
            if (empty($report['verified'])) {
                WP_CLI::warning('This site cannot reach itself over HTTP, so Elderward could not check that it still works. Open it in a browser now; if it fails, run: wp elderward harden --remove');
                WP_CLI::success(isset($assoc_args['remove']) ? 'Elderward rules removed (not verified).' : 'Protections written (not verified).');
                return;
            }
            WP_CLI::success(isset($assoc_args['remove']) ? 'Elderward rules removed.' : 'Protections applied; the site still answers normally.');
            return;
        }
        if ('nginx' === $server) {
            WP_CLI::line(rtrim(Elderward_Hardening::nginx_rules($features)));
            return;
        }
        foreach (Elderward_Hardening::apache_preview($features) as $file => $lines) {
            WP_CLI::line('# ' . $file);
            WP_CLI::line("# BEGIN Elderward\n" . implode("\n", $lines) . "\n# END Elderward\n");
        }
    }

    /**
     * Creates, shows or revokes the key for the recovery page.
     *
     * The recovery page (wp-content/plugins/elderward/recovery.php) scans
     * the site without loading WordPress. It answers 404 unless a key
     * exists.
     *
     * ## OPTIONS
     *
     * <action>
     * : create, status or revoke.
     *
     * [--expires=<days>]
     * : For create: 1 to 365 days, or "never". Default 7.
     *
     * ## EXAMPLES
     *
     *     wp elderward recovery-key create --expires=7
     *     wp elderward recovery-key revoke
     *
     * @subcommand recovery-key
     * @when after_wp_load
     */
    public function recovery_key($args, $assoc_args)
    {
        $action = isset($args[0]) ? $args[0] : 'status';
        if ('create' === $action) {
            $expires = isset($assoc_args['expires']) ? (string) $assoc_args['expires'] : '7';
            if ('never' !== $expires && (!ctype_digit($expires) || (int) $expires < 1 || (int) $expires > 365)) {
                WP_CLI::error('--expires must be 1 to 365 days, or never.');
            }
            $key = Elderward_Recovery_Key::create($expires, 'wp-cli');
            if (is_wp_error($key)) {
                WP_CLI::error($key->get_error_message());
            }
            WP_CLI::line('Recovery page: ' . Elderward_Recovery_Key::url());
            WP_CLI::line('Recovery key:  ' . $key);
            WP_CLI::success('Store the key somewhere safe: it is not shown again.');
            return;
        }
        if ('revoke' === $action) {
            if (!Elderward_Recovery_Key::revoke()) {
                WP_CLI::error('Could not delete ' . Elderward_Recovery_Key::path());
            }
            WP_CLI::success('Recovery key revoked.');
            return;
        }
        if ('status' !== $action) {
            WP_CLI::error('Action must be create, status or revoke.');
        }
        $status = Elderward_Recovery_Key::status();
        if (null === $status) {
            WP_CLI::line('Recovery mode is off (no key).');
            return;
        }
        WP_CLI::line('Recovery mode is ' . (Elderward_Recovery_Key::active() ? 'on' : 'off (key invalid or expired)') . '.');
        WP_CLI::line('Key file: ' . Elderward_Recovery_Key::path() . ($status['manual'] ? ' (added by hand)' : ''));
        WP_CLI::line('Expires:  ' . (0 === $status['expires'] ? 'never' : gmdate('Y-m-d H:i', $status['expires']) . ' UTC'));
        WP_CLI::line('Page:     ' . Elderward_Recovery_Key::url());
    }

    /**
     * Verify Elderward's own files, then the saved settings against the tamper seal. Report-only.
     *
     * Files are checked against the wordpress.org checksums for this version
     * when they exist, otherwise against the checksums.json shipped with the
     * plugin. scanall and integrity run this check first.
     *
     * ## OPTIONS
     *
     * [--checksum-dir=<path>]
     * : Read plugin-elderward-<version>.json from here instead of the network.
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function selfcheck($args, $assoc_args)
    {
        $options = array('selfcheck' => 1);
        $this->copy_option($assoc_args, 'checksum-dir', $options, 'checksumdir');
        $this->run($options, 'selfcheck', $assoc_args);
    }

    /**
     * Tamper seal of the saved settings (false positives, custom signatures, scan settings).
     *
     * The seal file records a hash of every entry Elderward saved, so changes
     * made directly in the database are reported and tampered false positives
     * are ignored.
     *
     * ## OPTIONS
     *
     * <action>
     * : status, or accept (trust the current settings after you reviewed them).
     *
     * [--collection=<name>]
     * : For accept: false_positives, signatures or settings. Default: all of them.
     *
     * ## EXAMPLES
     *
     *     wp elderward seal status
     *     wp elderward seal accept --collection=signatures
     *
     * @when after_wp_load
     */
    public function seal($args, $assoc_args)
    {
        $action = isset($args[0]) ? $args[0] : 'status';
        if ('accept' === $action) {
            $collection = isset($assoc_args['collection']) ? (string) $assoc_args['collection'] : null;
            if (null !== $collection && !in_array($collection, Elderward_Seal::collections(), true)) {
                WP_CLI::error('Collection must be one of: ' . implode(', ', Elderward_Seal::collections()) . '.');
            }
            if (!Elderward_Seal::accept($collection)) {
                WP_CLI::error('Could not write the seal file ' . Elderward_Seal::path());
            }
            WP_CLI::success(null === $collection ? 'The current saved settings are trusted again.' : 'The current ' . $collection . ' are trusted again.');
            return;
        }
        if ('status' !== $action) {
            WP_CLI::error('Action must be status or accept.');
        }
        $status = Elderward_Seal::status();
        if (!$status['available']) {
            WP_CLI::warning('Tamper detection is off: PHP cannot write ' . Elderward_Seal::path());
            return;
        }
        WP_CLI::line('Seal file: ' . $status['path']);
        if ($status['lost'] > 0) {
            WP_CLI::warning('The seal was missing on ' . gmdate('Y-m-d H:i', $status['lost']) . ' UTC and was recreated from the current settings.');
        }
        foreach ($status['diff'] as $collection => $diff) {
            $parts = array();
            foreach (array('added', 'changed', 'removed') as $kind) {
                if (!empty($diff[$kind])) {
                    $parts[] = $kind . ': ' . implode(', ', $diff[$kind]);
                }
            }
            WP_CLI::line(str_pad($collection, 16) . (empty($parts) ? 'matches the seal' : 'CHANGED OUTSIDE ELDERWARD (' . implode('; ', $parts) . ')'));
        }
        if (Elderward_Seal::tampered_count($status) > 0) {
            WP_CLI::halt(3);
        }
    }

    private function run(array $options, $mode, array $assoc_args)
    {
        $json = isset($assoc_args['format']) && 'json' === strtolower($assoc_args['format']);
        if ($json) {
            $options['format'] = 'json';
        }
        $reporter = $json ? new Elderward\Engine\JsonReporter() : new Elderward\Engine\TextReporter();
        $ctx = Elderward_Plugin::make_context($options, $reporter);

        try {
            Elderward\Engine\Runner::run_mode($ctx, $mode);
        } catch (Elderward\Engine\Fatal $e) {
            if ($reporter instanceof Elderward\Engine\TextReporter) {
                $reporter->flush_buffered();
            }
            $reporter->fatal($e->getMessage());
            WP_CLI::halt(1);
        }
        WP_CLI::halt($reporter->exit_code());
    }
}
