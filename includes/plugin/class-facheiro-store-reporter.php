<?php
/**
 * Engine Reporter that stores findings in the plugin's table and keeps
 * progress/summary text on the job, for scans run from the admin page.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

class Facheiro_Store_Reporter extends Facheiro\Engine\BaseReporter
{
    private $job_id;
    private $counts;
    private $summaries = array();
    private $last_progress = '';
    private $not_stored = 0;

    public function __construct($job_id, array $counts)
    {
        $this->job_id = $job_id;
        $this->counts = $counts;
    }

    public function finding($severity, $type, $path, $detail, $context = array(), $meta = array())
    {
        global $wpdb;
        $this->track($severity);
        // Findings are hostile data from the scanned host: stored as they
        // are (prepared statement) and escaped wherever they are rendered.
        // Two things would make $wpdb refuse the whole row, and a refused
        // row is a finding the administrator never sees: bytes that are not
        // valid UTF-8 (a file name, a log line, a database value cut in the
        // middle of a character) and a value longer than its column. Both
        // are dealt with here. The fingerprint is taken from the text as
        // stored, because a false-positive mark is made from the stored row
        // and has to match this finding again on the next scan; the file
        // hash needs the path as it is on disk.
        $clean = array('Facheiro\\Engine\\BaseReporter', 'clean_utf8');
        $stored_path = self::fit(call_user_func($clean, $path));
        $stored_detail = self::fit(call_user_func($clean, $detail));
        $sha256 = Facheiro_False_Positives::file_hash($type, $path);
        $value_sha256 = Facheiro_False_Positives::value_hash($type, $meta);
        $fingerprint = Facheiro_False_Positives::fingerprint($type, $stored_path, $stored_detail);
        $fp = Facheiro_False_Positives::classify($fingerprint, $sha256, $value_sha256);
        // A finding the administrator already cleared is stored but kept
        // out of the severity counts.
        $bucket = (Facheiro_False_Positives::MATCHED === $fp) ? 'FALSE_POSITIVE' : $severity;
        if (!isset($this->counts[$bucket])) {
            $this->counts[$bucket] = 0;
        }
        $this->counts[$bucket]++;

        $row = array(
            'job_id'       => $this->job_id,
            'severity'     => substr((string) $severity, 0, 8),
            'type'         => substr((string) $type, 0, 40),
            'path'         => $stored_path,
            'detail'       => $stored_detail,
            'context'      => empty($context) ? null : wp_json_encode(array_map($clean, array_values((array) $context))),
            'sha256'       => $sha256,
            'value_sha256' => $value_sha256,
            'fingerprint'  => $fingerprint,
            'fp'           => $fp,
            'created'      => gmdate('Y-m-d H:i:s'),
        );
        $formats = array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s');
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- the plugin's own findings table.
        if (false !== $wpdb->insert(Facheiro_Plugin::findings_table(), $row, $formats)) {
            return;
        }

        // Still refused: keep the fact that there was a finding, with the
        // parts that cannot be the problem, so the scan does not look
        // cleaner than it was.
        $error = (string) $wpdb->last_error;
        $row['severity'] = 'ERROR';
        $row['type'] = 'FINDING_NOT_STORED';
        $row['path'] = self::fit(preg_replace('/[^\x20-\x7E]/', '?', (string) $path), 2000);
        $row['detail'] = 'a ' . substr((string) $severity, 0, 8) . ' ' . substr((string) $type, 0, 40)
            . ' finding could not be saved to the findings table (' . ('' === $error ? 'the database refused the row' : self::fit(call_user_func($clean, $error), 300))
            . ') - run the scan from WP-CLI (wp facheiro scanall) to see it';
        $row['context'] = null;
        $row['sha256'] = null;
        $row['value_sha256'] = null;
        $row['fp'] = Facheiro_False_Positives::NONE;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- the plugin's own findings table.
        if (false === $wpdb->insert(Facheiro_Plugin::findings_table(), $row, $formats)) {
            $this->not_stored++;
        }
    }

    /**
     * Cut a value to fit a TEXT column (65,535 bytes) without leaving half
     * a character at the end.
     *
     * @param string $text  Valid UTF-8.
     * @param int    $bytes Maximum length in bytes.
     */
    private static function fit($text, $bytes = 60000)
    {
        $text = (string) $text;
        if (strlen($text) <= $bytes) {
            return $text;
        }
        return Facheiro\Engine\BaseReporter::clean_utf8(substr($text, 0, $bytes)) . ' [cut]';
    }

    /**
     * Findings the table refused even in their reduced form (the table is
     * missing or the database is failing): the job reports them.
     */
    public function not_stored()
    {
        return $this->not_stored;
    }

    public function summary($scan, $data, $text)
    {
        $this->summaries[$scan] = $data;
    }

    public function progress($text)
    {
        $text = trim((string) $text);
        if ('' !== $text) {
            $this->last_progress = $text;
        }
    }

    public function fatal($message)
    {
        $this->last_progress = 'Error: ' . $message;
    }

    public function counts()
    {
        return $this->counts;
    }

    public function summaries()
    {
        return $this->summaries;
    }

    public function last_progress()
    {
        return $this->last_progress;
    }
}
