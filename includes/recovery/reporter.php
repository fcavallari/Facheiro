<?php
////////////////
// Reporter for recovery mode: keeps findings in memory for the job file.
//////////////

namespace Elderward\Recovery;

use Elderward\Engine\BaseReporter;

// Outside WordPress only the recovery page, after sign-in, may load the file.
if (!defined('ABSPATH')) {
    if (!defined('ELDERWARD_RECOVERY')) {
        exit;
    }
}

class CollectReporter extends BaseReporter
{
    private $findings = array();
    private $counts;
    private $last = '';

    public function __construct(array $counts)
    {
        $this->counts = $counts;
    }

    public function finding($severity, $type, $path, $detail, $context = array(), $meta = array())
    {
        $this->track($severity);
        $this->counts[$severity] = isset($this->counts[$severity]) ? $this->counts[$severity] + 1 : 1;
        // The job file is JSON, which refuses a string that is not valid
        // UTF-8 (a file name, a log line, a database value cut in the
        // middle of a character): one such finding would lose the whole
        // scan state. Invalid bytes become U+FFFD.
        $finding = array('severity' => $severity, 'type' => $type, 'path' => self::clean_utf8($path), 'detail' => self::clean_utf8($detail));
        if (!empty($context)) {
            $finding['context'] = array_slice(array_map(array(__CLASS__, 'clean_utf8'), (array) $context), 0, 20);
        }
        $this->findings[] = $finding;
    }

    public function summary($scan, $data, $text)
    {
    }

    public function progress($text)
    {
        $this->last = self::clean_utf8(trim((string) $text, "= \n"));
    }

    public function fatal($message)
    {
        $this->last = self::clean_utf8($message);
    }

    /**
     * Findings since the last call.
     */
    public function take()
    {
        $out = $this->findings;
        $this->findings = array();
        return $out;
    }

    public function counts()
    {
        return $this->counts;
    }

    public function last_progress()
    {
        return $this->last;
    }
}
