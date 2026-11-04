<?php
/**
 * Plugin bootstrap: activation, shared helpers, wiring of the admin page.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Plugin
{
    const DB_VERSION = '3';
    const OPTION_DB_VERSION = 'elderward_db_version';

    public static function init()
    {
        add_action('init', array(__CLASS__, 'load_textdomain'));
        if (get_option(self::OPTION_DB_VERSION) !== self::DB_VERSION) {
            // Covers installs activated before a schema change and
            // network-wide activations that skipped the hook.
            self::create_table();
        }
        Elderward_Cron::init();
        Elderward_Abilities::init();
        if (is_admin()) {
            Elderward_Admin::init();
        }
    }

    /**
     * Translations shipped in languages/ (pt_BR for now). Language packs
     * from translate.wordpress.org, once the plugin is in the directory,
     * load from wp-content/languages/plugins and take precedence.
     */
    public static function load_textdomain()
    {
        load_plugin_textdomain('elderward', false, dirname(plugin_basename(ELDERWARD_FILE)) . '/languages');
    }

    /**
     * Scan stage names from the engine (English there, since the CLI
     * prints them), translated for the admin pages.
     */
    public static function stage_label($stage)
    {
        $labels = array(
            'self'       => __('Elderward self-check', 'elderward'),
            'quick'      => __('Quick checks', 'elderward'),
            'integrity'  => __('Integrity', 'elderward'),
            'timestamps' => __('Timestamps', 'elderward'),
            'crontab'    => __('Crontab', 'elderward'),
            'database'   => __('Database', 'elderward'),
            'logs'       => __('Access logs', 'elderward'),
            'correlate'  => __('Access logs', 'elderward'),
            'signatures' => __('Malware signatures (dry run)', 'elderward'),
        );
        return isset($labels[$stage]) ? $labels[$stage] : Elderward\Engine\Runner::stage_label($stage);
    }

    public static function activate()
    {
        self::create_table();
        Elderward_Cron::sync_schedule();
    }

    public static function deactivate()
    {
        Elderward_Cron::deactivate();
    }

    /**
     * Only administrators may run scans or read results; on multisite the
     * scan covers the whole install, so only super admins qualify.
     */
    public static function can_manage()
    {
        if (!current_user_can('manage_options')) {
            return false;
        }
        if (is_multisite() && !is_super_admin()) {
            return false;
        }
        return true;
    }

    /**
     * The folder that holds the plugins folder (wp-content on almost every
     * site): where the recovery key and the tamper seal live, outside the
     * database and outside the plugin folder an update replaces.
     */
    public static function content_dir()
    {
        return dirname(untrailingslashit(WP_PLUGIN_DIR));
    }

    /**
     * Read a file in the "<?php exit; ?>" + JSON format (recovery key, tamper
     * seal): requesting it over the web shows nothing. Null when the file is
     * missing or its JSON is not an object.
     */
    public static function read_guarded_json($file)
    {
        if (!is_file($file)) {
            return null;
        }
        $raw = (string) @file_get_contents($file); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- local file; unreadable means null.
        $data = json_decode(trim(preg_replace('/^\s*<\?php.*?\?>/s', '', $raw, 1)), true);
        return is_array($data) ? $data : null;
    }

    /**
     * Write a guarded JSON file atomically (temp file + rename), so a reader
     * never sees half of it.
     */
    public static function write_guarded_json($file, array $data)
    {
        $content = '<?php exit; ?>' . "\n" . wp_json_encode($data) . "\n";
        $tmp = $file . '.' . wp_generate_password(8, false, false) . '.tmp';
        if (false === @file_put_contents($tmp, $content)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- must be a plain file readable without WordPress or the database; failure is returned.
            return false;
        }
        if (!@rename($tmp, $file)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename, WordPress.PHP.NoSilencedErrors.Discouraged -- atomic replace; failure is returned.
            wp_delete_file($tmp);
            return false;
        }
        return true;
    }

    /**
     * One findings table per install (base prefix on multisite).
     */
    public static function findings_table()
    {
        global $wpdb;
        return $wpdb->base_prefix . 'elderward_findings';
    }

    /**
     * A path relative to the WordPress root (or $root), unchanged when it
     * lies outside.
     */
    public static function relative_path($path, $root = null)
    {
        $path = (string) $path;
        $root = untrailingslashit(null === $root ? ABSPATH : $root);
        return (0 === strpos($path, $root . '/')) ? substr($path, strlen($root) + 1) : $path;
    }

    public static function create_table()
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = self::findings_table();
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            job_id varchar(32) NOT NULL,
            severity varchar(8) NOT NULL,
            type varchar(40) NOT NULL,
            path text NOT NULL,
            detail text NOT NULL,
            context longtext NULL,
            sha256 char(64) NULL,
            value_sha256 char(64) NULL,
            fingerprint char(40) NOT NULL DEFAULT '',
            fp tinyint(1) NOT NULL DEFAULT 0,
            created datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY job_severity (job_id, severity),
            KEY fingerprint (fingerprint)
        ) {$charset_collate};";
        dbDelta($sql);
        update_option(self::OPTION_DB_VERSION, self::DB_VERSION, false);
    }

    /**
     * Build an engine Context wired to WordPress: HTTP through the
     * WordPress HTTP API, database through $wpdb, the plugin's own folder
     * excluded from file scans.
     *
     * @param array                      $options  Engine options (key => value).
     * @param Elderward\Engine\Reporter  $reporter Where findings go.
     * @param string|null                $work_dir Directory for work files.
     */
    public static function make_context(array $options, Elderward\Engine\Reporter $reporter, $work_dir = null)
    {
        // Custom signatures from the editor apply to every scan on this site
        // (admin page, WP-Cron runner, WP-CLI, assistants), and every scan
        // builds its Context here, so they load here rather than on every
        // request.
        Elderward_Signatures::install();
        if (!isset($options['scandirectory'])) {
            $options['scandirectory'] = untrailingslashit(ABSPATH);
        }
        // WordPress already knows where its content and plugins live; the
        // engine would otherwise have to parse them out of wp-config.php.
        // Only for a scan of this site: WP-CLI can scan another folder.
        if (realpath($options['scandirectory']) === realpath(ABSPATH)) {
            if (!isset($options['contentdir'])) {
                $options['contentdir'] = untrailingslashit(WP_CONTENT_DIR);
            }
            if (!isset($options['plugindir'])) {
                $options['plugindir'] = untrailingslashit(WP_PLUGIN_DIR);
            }
        }
        $ctx = new Elderward\Engine\Context(
            $options,
            $reporter,
            new Elderward_WP_Http(),
            new Elderward_WP_Db(),
            ELDERWARD_DIR,
            null === $work_dir ? get_temp_dir() : $work_dir
        );
        // Run once per scan by the engine's self-check stage.
        $ctx->preflight[] = array('Elderward_Seal', 'report');
        return $ctx;
    }
}
