<?php
////////////////
// Reporter for recovery mode: keeps findings in memory for the job file.
//////////////

namespace Elderward\Recovery;

use Elderward\Engine\BaseReporter;

if (!defined('ELDERWARD_RECOVERY')) {
    exit;
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
        $finding = array('severity' => $severity, 'type' => $type, 'path' => $path, 'detail' => $detail);
        if (!empty($context)) {
            $finding['context'] = array_slice(array_map('strval', (array) $context), 0, 20);
        }
        $this->findings[] = $finding;
    }

    public function summary($scan, $data, $text)
    {
    }

    public function progress($text)
    {
        $this->last = trim((string) $text, "= \n");
    }

    public function fatal($message)
    {
        $this->last = (string) $message;
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
