<?php
/**
 * Findings an administrator reviewed and marked as false positives.
 *
 * A rule remembers the finding (type, path, detail) and, for findings about
 * a file, the SHA-256 of that file when it was reviewed; for findings about
 * a database value (an option, a post), the SHA-256 of that value as the
 * scan read it. Later scans still
 * record a matching finding but flag it as a false positive, so it drops out
 * of the default view and the counts, yet stays in the table and in the JSON
 * export. If the file content changed since the review the rule no longer
 * applies: the finding comes back with a note saying so, because an attacker
 * can append to any file an administrator once cleared, or swap the payload
 * in an option row that still matches the same signature.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_False_Positives
{
    const OPTION = 'facheiro_false_positives';
    const MAX_RULES = 2000;
    const MAX_NOTE = 500;
    // Files above this size are not hashed (the rule then matches on the
    // finding alone); scans must not spend minutes hashing one huge file.
    const HASH_MAX_BYTES = 67108864;

    // Values of the findings table's fp column.
    const NONE = 0;
    const MATCHED = 1;
    const CHANGED = 2;

    // Who saved a rule: an administrator on the admin page, or an AI
    // assistant through the abilities (acting as that administrator).
    const VIA_ADMIN = 'admin';
    const VIA_ASSISTANT = 'assistant';

    /**
     * Finding types whose path is the file the finding is about, so the
     * file's content identifies the finding (and can be sent for analysis).
     */
    private static $file_types = array(
        'MALWARE_FOUND', 'MALWARE_CLEANED', 'CLEANUP_FAILED', 'HIDDEN_PHP', 'UPLOADS_PHP', 'MU_PLUGIN',
        'PHP_PREPEND', 'INTEGRITY_MODIFIED', 'INTEGRITY_EXTRA', 'INTEGRITY_RESTORABLE',
        'TIMESTAMP_OUTLIER', 'TIMESTAMP_TIMESTOMP', 'LOG_FILE_CORRELATION', 'SIGNATURE_MATCH',
        'FILE_TOO_LARGE', 'SIGNATURE_ERROR',
    );

    private static $cache = null;

    public static function is_file_type($type)
    {
        return in_array((string) $type, self::$file_types, true);
    }

    public static function fingerprint($type, $path, $detail)
    {
        return sha1((string) $type . "\0" . (string) $path . "\0" . (string) $detail);
    }

    /**
     * SHA-256 of the database value a finding is about, as the engine
     * scanned it; null for file findings and findings with no value.
     */
    public static function value_hash($type, $meta)
    {
        if (self::is_file_type($type) || !isset($meta['value_sha256'])) {
            return null;
        }
        $hash = (string) $meta['value_sha256'];
        return (1 === preg_match('/^[0-9a-f]{64}$/', $hash)) ? $hash : null;
    }

    /**
     * SHA-256 of the file a finding is about, or null when the finding is
     * not about a file or the file cannot be hashed.
     */
    public static function file_hash($type, $path)
    {
        if (!self::is_file_type($type)) {
            return null;
        }
        $path = (string) $path;
        if ('' === $path || !@is_file($path) || !@is_readable($path)) {
            return null;
        }
        $size = @filesize($path);
        if (false === $size || $size > self::HASH_MAX_BYTES) {
            return null;
        }
        $hash = hash_file('sha256', $path);
        return (false === $hash) ? null : $hash;
    }

    /**
     * The rules scans apply: only those that match the tamper seal. A rule
     * added or changed outside Facheiro (see Facheiro_Seal) is ignored,
     * so the finding it would hide is reported again.
     */
    public static function rules()
    {
        if (null === self::$cache) {
            $status = Facheiro_Seal::status();
            $diff = isset($status['diff']['false_positives']) ? $status['diff']['false_positives'] : array('added' => array(), 'changed' => array());
            self::$cache = array_diff_key(self::all_rules(), array_flip(array_merge($diff['added'], $diff['changed'])));
        }
        return self::$cache;
    }

    /**
     * Every stored rule, sealed or not (for the review list).
     */
    public static function all_rules()
    {
        $rules = get_option(self::OPTION, array());
        return is_array($rules) ? $rules : array();
    }

    public static function reset_cache()
    {
        self::$cache = null;
        Facheiro_Seal::reset_cache();
    }

    /**
     * Change the stored rules through the seal. $mutate gets the current
     * rules and returns the new ones (or a WP_Error).
     */
    private static function change_rules(callable $mutate)
    {
        $result = Facheiro_Seal::update('false_positives', function ($rules) use ($mutate) {
            return call_user_func($mutate, is_array($rules) ? $rules : array());
        });
        self::$cache = null;
        return $result;
    }

    /**
     * After review on the admin page: trust a rule changed outside
     * Facheiro.
     */
    public static function keep($fingerprint)
    {
        $ok = Facheiro_Seal::accept('false_positives', array((string) $fingerprint));
        self::$cache = null;
        self::reflag((string) $fingerprint);
        return $ok;
    }

    /**
     * How a new finding relates to the saved rules: NONE, MATCHED, or
     * CHANGED (marked before, but the file or the database value is not
     * the one reviewed). A database mark saved before values were hashed
     * has no value hash, so it comes back once as CHANGED: re-marking it
     * binds it to the current value.
     */
    public static function classify($fingerprint, $sha256, $value_sha256 = null)
    {
        $rules = self::rules();
        if (!isset($rules[$fingerprint])) {
            return self::NONE;
        }
        $reviewed = isset($rules[$fingerprint]['sha256']) ? $rules[$fingerprint]['sha256'] : null;
        $reviewed_value = isset($rules[$fingerprint]['value_sha256']) ? $rules[$fingerprint]['value_sha256'] : null;
        return ($reviewed === $sha256 && $reviewed_value === $value_sha256) ? self::MATCHED : self::CHANGED;
    }

    /**
     * One finding of the current job, by id; with its context column when
     * $with_context is true.
     */
    public static function finding($id, $with_context = false)
    {
        global $wpdb;
        $job = Facheiro_Job::current();
        if (null === $job) {
            return null;
        }
        $table = Facheiro_Plugin::findings_table();
        // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table (name from the base prefix); values go through prepare(); must not be cached.
        $row = $wpdb->get_row($wpdb->prepare("SELECT id, severity, type, path, detail, sha256, value_sha256, fp" . ($with_context ? ', context' : '') . " FROM `{$table}` WHERE id = %d AND job_id = %s", (int) $id, $job['id']));
        return $row ? $row : null;
    }

    /**
     * Mark a finding of the current job as a false positive.
     *
     * @return array|WP_Error The saved rule.
     */
    public static function mark($id, $note, $via = self::VIA_ADMIN)
    {
        global $wpdb;
        $row = self::finding($id);
        if (null === $row) {
            return new WP_Error('facheiro_fp_missing', __('Esse achado não faz parte dos resultados atuais.', 'facheiro'));
        }
        $fingerprint = self::fingerprint($row->type, $row->path, $row->detail);
        // The content the administrator reviewed is the one the scan saw;
        // rows from before hashes were stored fall back to the file now.
        $sha256 = (null !== $row->sha256 && '' !== $row->sha256) ? $row->sha256 : self::file_hash($row->type, $row->path);
        $value_sha256 = (null !== $row->value_sha256 && '' !== $row->value_sha256) ? $row->value_sha256 : null;
        $rule = array(
            'type'     => (string) $row->type,
            'severity' => (string) $row->severity,
            'path'     => (string) $row->path,
            'detail'   => (string) $row->detail,
            'sha256'   => $sha256,
            'value_sha256' => $value_sha256,
            'note'     => self::clean_note($note),
            'user'     => get_current_user_id(),
            'via'      => (self::VIA_ASSISTANT === $via) ? self::VIA_ASSISTANT : self::VIA_ADMIN,
            'time'     => time(),
        );
        $saved = self::change_rules(function ($rules) use ($fingerprint, $rule) {
            if (!isset($rules[$fingerprint]) && count($rules) >= self::MAX_RULES) {
                return new WP_Error('facheiro_fp_full', __('Há falsos positivos salvos demais. Remova alguns antes de adicionar outros.', 'facheiro'));
            }
            $rules[$fingerprint] = $rule;
            return $rules;
        });
        if (is_wp_error($saved)) {
            return $saved;
        }
        // Rows stored before the fingerprint column existed get it now.
        $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own findings table.
            Facheiro_Plugin::findings_table(),
            array('fingerprint' => $fingerprint, 'sha256' => $sha256),
            array('id' => (int) $row->id),
            array('%s', '%s'),
            array('%d')
        );
        self::reflag($fingerprint);
        return $rule;
    }

    public static function unmark($fingerprint)
    {
        $fingerprint = (string) $fingerprint;
        self::change_rules(function ($rules) use ($fingerprint) {
            if (!isset($rules[$fingerprint])) {
                return false;
            }
            unset($rules[$fingerprint]);
            return $rules;
        });
        self::reflag($fingerprint);
    }

    public static function forget_all()
    {
        global $wpdb;
        self::change_rules(function () {
            return array();
        });
        $table = Facheiro_Plugin::findings_table();
        // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table (name from the base prefix); no values.
        $wpdb->query("UPDATE `{$table}` SET fp = 0 WHERE fp <> 0");
    }

    /**
     * Recompute the fp flag of the stored findings with this fingerprint
     * after a rule was added or removed.
     */
    private static function reflag($fingerprint)
    {
        global $wpdb;
        $table = Facheiro_Plugin::findings_table();
        $rules = self::rules();
        // phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table (name from the base prefix); values go through prepare(); must not be cached.
        if (!isset($rules[$fingerprint])) {
            $wpdb->query($wpdb->prepare("UPDATE `{$table}` SET fp = 0 WHERE fingerprint = %s", $fingerprint));
            return;
        }
        $rows = $wpdb->get_results($wpdb->prepare("SELECT id, sha256, value_sha256 FROM `{$table}` WHERE fingerprint = %s", $fingerprint));
        foreach ((array) $rows as $row) {
            $sha256 = (null === $row->sha256 || '' === $row->sha256) ? null : $row->sha256;
            $value_sha256 = (null === $row->value_sha256 || '' === $row->value_sha256) ? null : $row->value_sha256;
            $wpdb->update($table, array('fp' => self::classify($fingerprint, $sha256, $value_sha256)), array('id' => (int) $row->id), array('%d'), array('%d'));
        }
        // phpcs:enable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    private static function clean_note($note)
    {
        $note = sanitize_text_field((string) $note);
        if (function_exists('mb_substr')) {
            return mb_substr($note, 0, self::MAX_NOTE);
        }
        return substr($note, 0, self::MAX_NOTE);
    }
}
