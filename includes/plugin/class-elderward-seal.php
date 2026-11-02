<?php
/**
 * Tamper seal for the settings that decide what a scan reports: saved false
 * positives, custom signatures and the scan settings.
 *
 * They live in the database, where an attacker with only database access
 * (SQL injection is the usual way in) could add a false positive for their
 * backdoor or delete the signature that catches it. Every change made
 * through Elderward also records the SHA-256 of each entry in a file next
 * to the plugins folder (elderward-seal.php, guarded like the recovery key
 * file). Writing that file takes file access, which a database-only
 * attacker does not have, so an entry whose hash does not match was changed
 * outside Elderward: scans report it, and a false positive that does not
 * match is ignored.
 *
 * This is detection, not prevention: an attacker who can write files can
 * rewrite the seal as well.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Seal
{
    const FILE = 'elderward-seal.php';
    const LOCK = 'elderward-seal.lock';
    const GUARD = '<?php exit; ?>';
    // Set once a seal file was written; if the file later disappears, that
    // is reported instead of silently starting over.
    const OPTION_CREATED = 'elderward_seal_created';
    // When the seal file was found missing; cleared when an administrator
    // accepts the current settings.
    const OPTION_LOST = 'elderward_seal_lost';

    private static $collections = array(
        'false_positives' => 'elderward_false_positives',
        'signatures'      => 'elderward_signatures',
        'settings'        => 'elderward_settings',
    );

    private static $cache = null;
    private static $lock = null;

    public static function collections()
    {
        return array_keys(self::$collections);
    }

    public static function path()
    {
        return Elderward_Plugin::content_dir() . '/' . self::FILE;
    }

    private static function lock_path()
    {
        return Elderward_Plugin::content_dir() . '/' . self::LOCK;
    }

    /**
     * Whether a seal can be kept: the file exists and is writable, or the
     * folder lets PHP create it.
     */
    public static function writable()
    {
        $file = self::path();
        return is_file($file) ? wp_is_writable($file) : wp_is_writable(Elderward_Plugin::content_dir());
    }

    /**
     * Entries of a collection, keyed: false positives by fingerprint,
     * signatures by id, settings as one entry.
     */
    public static function items($collection, $value)
    {
        if ('settings' === $collection) {
            return is_array($value) ? array('all' => $value) : array();
        }
        if (!is_array($value)) {
            return array();
        }
        if ('signatures' === $collection) {
            $items = array();
            foreach (array_values($value) as $i => $def) {
                $key = (is_array($def) && isset($def['id']) && is_string($def['id'])) ? $def['id'] : '#' . $i;
                $items[$key] = $def;
            }
            return $items;
        }
        $items = array();
        foreach ($value as $key => $entry) {
            $items[(string) $key] = $entry;
        }
        return $items;
    }

    public static function hash($entry)
    {
        return hash('sha256', (string) wp_json_encode(self::canonical($entry)));
    }

    private static function canonical($value)
    {
        if (!is_array($value)) {
            return $value;
        }
        ksort($value);
        foreach ($value as $key => $item) {
            $value[$key] = self::canonical($item);
        }
        return $value;
    }

    private static function fresh_option($collection)
    {
        $option = self::$collections[$collection];
        wp_cache_delete($option, 'options');
        return get_option($option, null);
    }

    private static function hashes($collection, $value)
    {
        $hashes = array();
        foreach (self::items($collection, $value) as $key => $entry) {
            $hashes[$key] = self::hash($entry);
        }
        return $hashes;
    }

    /**
     * The seal's data; creates the seal from the current settings when there
     * is none yet. Null when no seal can be kept (folder not writable).
     */
    public static function data()
    {
        if (null !== self::$cache) {
            return self::$cache;
        }
        $data = self::read_file();
        if (null === $data) {
            if (!self::writable()) {
                return null;
            }
            self::lock();
            $data = self::read_file();
            if (null === $data) {
                if (get_option(self::OPTION_CREATED)) {
                    update_option(self::OPTION_LOST, time(), false);
                }
                $data = array('v' => 1, 'collections' => array());
                foreach (self::collections() as $collection) {
                    $data['collections'][$collection] = self::hashes($collection, self::fresh_option($collection));
                }
                $data = self::write_file($data) ? $data : null;
            }
            self::unlock();
        }
        self::$cache = $data;
        return $data;
    }

    private static function read_file()
    {
        $file = self::path();
        if (!is_file($file)) {
            return null;
        }
        $raw = (string) @file_get_contents($file); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- local file; a missing or unreadable one is handled below.
        $data = json_decode(trim(preg_replace('/^\s*<\?php.*?\?>/s', '', $raw, 1)), true);
        if (!is_array($data) || !isset($data['collections']) || !is_array($data['collections'])) {
            // Unreadable or garbled: start again, reported as a lost seal.
            return null;
        }
        return $data;
    }

    private static function write_file(array $data)
    {
        $data['updated'] = time();
        $content = self::GUARD . "\n" . wp_json_encode($data) . "\n";
        $file = self::path();
        // Temp file + rename: a scan never reads a half-written seal.
        $tmp = $file . '.' . wp_generate_password(8, false, false) . '.tmp';
        if (false === @file_put_contents($tmp, $content)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- must be a plain file outside the database; failure is handled.
            return false;
        }
        if (!@rename($tmp, $file)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename, WordPress.PHP.NoSilencedErrors.Discouraged -- atomic replace; failure is handled.
            wp_delete_file($tmp);
            return false;
        }
        update_option(self::OPTION_CREATED, 1, false);
        self::$cache = $data;
        return true;
    }

    private static function lock()
    {
        if (null !== self::$lock) {
            return;
        }
        $handle = @fopen(self::lock_path(), 'c'); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.PHP.NoSilencedErrors.Discouraged -- a lock file; without it the update runs unlocked.
        if (false !== $handle && flock($handle, LOCK_EX)) {
            self::$lock = $handle;
        }
    }

    private static function unlock()
    {
        if (null !== self::$lock) {
            flock(self::$lock, LOCK_UN);
            fclose(self::$lock); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- the lock file.
            self::$lock = null;
        }
    }

    /**
     * The one way Elderward changes a sealed setting. Under the lock, reads
     * the option fresh, lets $mutate return the new value (or a WP_Error /
     * false to change nothing), saves it, and seals the entries $mutate
     * changed. Entries it left alone keep their old seal, so an entry
     * tampered with earlier stays reported.
     *
     * @return mixed The new value, or what $mutate returned when it refused.
     */
    public static function update($collection, callable $mutate)
    {
        $data = self::data();
        self::lock();
        $before = self::fresh_option($collection);
        $after = call_user_func($mutate, $before);
        if (false === $after || is_wp_error($after)) {
            self::unlock();
            return $after;
        }
        update_option(self::$collections[$collection], $after, false);
        if (null !== $data) {
            self::$cache = null;
            $data = self::read_file();
            if (null !== $data) {
                $old = self::hashes($collection, $before);
                $new = self::hashes($collection, $after);
                $sealed = isset($data['collections'][$collection]) ? (array) $data['collections'][$collection] : array();
                foreach ($new as $key => $hash) {
                    if (!isset($old[$key]) || $old[$key] !== $hash) {
                        $sealed[$key] = $hash;
                    }
                }
                foreach (array_keys($old) as $key) {
                    if (!isset($new[$key])) {
                        unset($sealed[$key]);
                    }
                }
                $data['collections'][$collection] = $sealed;
                self::write_file($data);
            }
        }
        self::unlock();
        return $after;
    }

    /**
     * What changed outside Elderward: keys added, changed, or removed
     * compared with the seal. Empty lists when no seal can be kept.
     */
    public static function diff($collection, $value = null)
    {
        $diff = array('added' => array(), 'changed' => array(), 'removed' => array());
        $data = self::data();
        if (null === $data) {
            return $diff;
        }
        if (null === $value) {
            $value = get_option(self::$collections[$collection], null);
        }
        $sealed = isset($data['collections'][$collection]) ? (array) $data['collections'][$collection] : array();
        $current = self::hashes($collection, $value);
        foreach ($current as $key => $hash) {
            if (!isset($sealed[$key])) {
                $diff['added'][] = (string) $key;
            } elseif (!hash_equals((string) $sealed[$key], $hash)) {
                $diff['changed'][] = (string) $key;
            }
        }
        foreach (array_keys($sealed) as $key) {
            if (!isset($current[$key])) {
                $diff['removed'][] = (string) $key;
            }
        }
        return $diff;
    }

    /**
     * Whether one entry matches the seal (true when no seal can be kept).
     */
    public static function matches($collection, $key, $entry)
    {
        $data = self::data();
        if (null === $data) {
            return true;
        }
        $sealed = isset($data['collections'][$collection]) ? (array) $data['collections'][$collection] : array();
        return isset($sealed[$key]) && hash_equals((string) $sealed[$key], self::hash($entry));
    }

    /**
     * After an administrator reviewed them: seal the current state of the
     * given keys (all of the collection when null; a removed key is
     * forgotten). Also clears the lost-seal notice.
     */
    public static function accept($collection = null, $keys = null)
    {
        if (null === self::data()) {
            return false;
        }
        self::lock();
        self::$cache = null;
        $data = self::read_file();
        $ok = false;
        if (null !== $data) {
            foreach (null === $collection ? self::collections() : array($collection) as $name) {
                $current = self::hashes($name, self::fresh_option($name));
                $sealed = isset($data['collections'][$name]) ? (array) $data['collections'][$name] : array();
                if (null === $keys) {
                    $sealed = $current;
                } else {
                    foreach ((array) $keys as $key) {
                        $key = (string) $key;
                        if (isset($current[$key])) {
                            $sealed[$key] = $current[$key];
                        } else {
                            unset($sealed[$key]);
                        }
                    }
                }
                $data['collections'][$name] = $sealed;
            }
            $ok = self::write_file($data);
        }
        self::unlock();
        if ($ok && null === $collection) {
            delete_option(self::OPTION_LOST);
        }
        return $ok;
    }

    /**
     * Summary for notices, WP-CLI and the scan: per collection diff, plus
     * whether the seal works and whether it was found missing.
     */
    public static function status()
    {
        $data = self::data();
        $status = array(
            'available' => null !== $data,
            'path'      => self::path(),
            'lost'      => (int) get_option(self::OPTION_LOST, 0),
            'diff'      => array(),
        );
        foreach (self::collections() as $collection) {
            $status['diff'][$collection] = self::diff($collection);
        }
        return $status;
    }

    public static function tampered_count($status = null)
    {
        $status = null === $status ? self::status() : $status;
        $count = 0;
        foreach ($status['diff'] as $collection => $diff) {
            $count += count($diff['changed']) + count($diff['added']);
            // Removed false positives only show more findings: harmless.
            if ('false_positives' !== $collection) {
                $count += count($diff['removed']);
            }
        }
        return $count;
    }

    /**
     * Preflight check for every scan (run by the engine's self-check stage):
     * report each setting changed outside Elderward.
     */
    public static function report(Elderward\Engine\Reporter $reporter)
    {
        self::$cache = null;
        $status = self::status();
        if (!$status['available']) {
            $reporter->finding('INFO', 'TAMPER_SEAL_UNAVAILABLE', Elderward_Plugin::content_dir(), 'PHP cannot write the tamper seal here, so changes made to the saved settings outside Elderward cannot be detected');
            return;
        }
        if ($status['lost'] > 0) {
            $reporter->finding('MEDIUM', 'TAMPER_SEAL_MISSING', $status['path'], 'the tamper seal disappeared and was recreated from the current settings on ' . gmdate('Y-m-d H:i', $status['lost']) . ' UTC; review the saved false positives and custom signatures');
        }
        $rules = get_option(self::$collections['false_positives'], array());
        $diff = $status['diff']['false_positives'];
        foreach (array('added' => 'added', 'changed' => 'changed') as $kind => $word) {
            foreach ($diff[$kind] as $key) {
                $rule = (is_array($rules) && isset($rules[$key]) && is_array($rules[$key])) ? $rules[$key] : array();
                $type = isset($rule['type']) ? (string) $rule['type'] : '?';
                $path = isset($rule['path']) ? (string) $rule['path'] : '';
                $reporter->finding('HIGH', 'TAMPER_FALSE_POSITIVE', $path, 'a false positive for ' . $type . ' was ' . $word . ' outside Elderward, so it is ignored');
            }
        }
        $diff = $status['diff']['signatures'];
        $words = array(
            'removed' => 'removed outside Elderward; re-import it from an export if it should exist',
            'changed' => 'changed outside Elderward',
            'added'   => 'added outside Elderward',
        );
        foreach ($words as $kind => $text) {
            foreach ($diff[$kind] as $key) {
                $reporter->finding('added' === $kind ? 'MEDIUM' : 'HIGH', 'TAMPER_SIGNATURE', 'custom signature ' . $key, 'the custom signature was ' . $text);
            }
        }
        $diff = $status['diff']['settings'];
        if (count($diff['changed']) + count($diff['added']) + count($diff['removed']) > 0) {
            $reporter->finding('MEDIUM', 'TAMPER_SETTINGS', 'Elderward settings', 'the scan settings (runner, schedule, access log path) were changed outside Elderward');
        }
    }

    public static function uninstall()
    {
        foreach (array(self::path(), self::lock_path()) as $file) {
            if (is_file($file)) {
                wp_delete_file($file);
            }
        }
        delete_option(self::OPTION_CREATED);
        delete_option(self::OPTION_LOST);
    }
}
