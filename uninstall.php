<?php
/**
 * Removes everything Facheiro stored: the findings table, its options,
 * the work directory under uploads, its hardening rules in .htaccess files,
 * the recovery key and recovery state, and the tamper seal.
 *
 * @package Facheiro
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.DB.DirectDatabaseQuery -- uninstall removes the plugin's own table and its own work files.

global $wpdb;

$facheiro_table = $wpdb->base_prefix . 'facheiro_findings';
$wpdb->query('DROP TABLE IF EXISTS `' . $facheiro_table . '`'); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from the base prefix, never user input.

wp_clear_scheduled_hook('facheiro_scheduled_scan');
wp_clear_scheduled_hook('facheiro_run_job');

// Hardening rules, the recovery key and the tamper seal live in files, not
// options. The plugin is inactive here, so its classes are loaded by hand.
require_once __DIR__ . '/includes/plugin/class-facheiro-plugin.php';
require_once __DIR__ . '/includes/plugin/class-facheiro-hardening.php';
require_once __DIR__ . '/includes/plugin/class-facheiro-recovery-key.php';
require_once __DIR__ . '/includes/plugin/class-facheiro-seal.php';
Facheiro_Hardening::uninstall();
Facheiro_Recovery_Key::uninstall();
Facheiro_Seal::uninstall();
delete_option('facheiro_hardening');

delete_option('facheiro_db_version');
delete_option('facheiro_job');
delete_option('facheiro_job_lock');
delete_option('facheiro_settings');
delete_option('facheiro_false_positives');
delete_option('facheiro_signatures');
if (is_multisite()) {
    delete_site_option('facheiro_job');
}

$facheiro_uploads = wp_upload_dir(null, false);
if (empty($facheiro_uploads['error']) && !empty($facheiro_uploads['basedir'])) {
    $facheiro_work = trailingslashit($facheiro_uploads['basedir']) . 'facheiro';
    if (is_dir($facheiro_work)) {
        $facheiro_files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($facheiro_work, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($facheiro_files as $facheiro_entry) {
            if ($facheiro_entry->isDir()) {
                @rmdir($facheiro_entry->getPathname());
            } else {
                @unlink($facheiro_entry->getPathname());
            }
        }
        @rmdir($facheiro_work);
    }
}
