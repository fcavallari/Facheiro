<?php
/**
 * Removes everything Elderward stored: the findings table, its options,
 * the work directory under uploads, its hardening rules in .htaccess files,
 * the recovery key and recovery state, and the tamper seal.
 *
 * @package Elderward
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.DB.DirectDatabaseQuery -- uninstall removes the plugin's own table and its own work files.

global $wpdb;

$elderward_table = $wpdb->base_prefix . 'elderward_findings';
$wpdb->query('DROP TABLE IF EXISTS `' . $elderward_table . '`'); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from the base prefix, never user input.

wp_clear_scheduled_hook('elderward_scheduled_scan');
wp_clear_scheduled_hook('elderward_run_job');

// Hardening rules, the recovery key and the tamper seal live in files, not
// options. The plugin is inactive here, so its classes are loaded by hand.
require_once __DIR__ . '/includes/plugin/class-elderward-plugin.php';
require_once __DIR__ . '/includes/plugin/class-elderward-hardening.php';
require_once __DIR__ . '/includes/plugin/class-elderward-recovery-key.php';
require_once __DIR__ . '/includes/plugin/class-elderward-seal.php';
Elderward_Hardening::uninstall();
Elderward_Recovery_Key::uninstall();
Elderward_Seal::uninstall();
delete_option('elderward_hardening');

delete_option('elderward_db_version');
delete_option('elderward_job');
delete_option('elderward_job_lock');
delete_option('elderward_settings');
delete_option('elderward_false_positives');
delete_option('elderward_signatures');
if (is_multisite()) {
    delete_site_option('elderward_job');
}

$elderward_uploads = wp_upload_dir(null, false);
if (empty($elderward_uploads['error']) && !empty($elderward_uploads['basedir'])) {
    $elderward_work = trailingslashit($elderward_uploads['basedir']) . 'elderward';
    if (is_dir($elderward_work)) {
        $elderward_files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($elderward_work, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($elderward_files as $elderward_entry) {
            if ($elderward_entry->isDir()) {
                @rmdir($elderward_entry->getPathname());
            } else {
                @unlink($elderward_entry->getPathname());
            }
        }
        @rmdir($elderward_work);
    }
}
