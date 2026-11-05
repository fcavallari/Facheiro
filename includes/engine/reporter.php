<?php
namespace Elderward\Engine;

////////////////
// Unified finding format, shared by every scanner. Text mode (default):
//
//   SEVERITY,TYPE,path,detail
//
// The first three fields never contain commas; everything after the third
// comma is free-form detail. Severities: HIGH, MEDIUM, LOW, INFO, ERROR.
// Indented lines under a finding are supporting context (log examples etc).
//
// Paths and details come from a compromised host, so the attacker chooses
// them: '%', control characters, and (in the path field) commas are
// percent-encoded so a crafted filename cannot shift fields or inject
// fake finding lines into the report.
//
// JSON mode prints NDJSON, one event object per line:
//   {"event":"finding","severity":...,"type":...,"path":...,"detail":...}
//   {"event":"summary","scan":...,...counts...}
//   {"event":"error","detail":...}
// Fields carry raw values (json_encode escapes them safely) and progress
// text moves to STDERR, so stdout is pure machine-readable events. A value
// that is not valid UTF-8 (a file name, a log line, a database value cut
// in the middle of a character) cannot be JSON: its invalid bytes become
// U+FFFD so the finding is still reported. Text mode prints the raw bytes.
//
// The exit code reflects the worst finding: 0 clean (or INFO only),
// 1 usage/fatal error, 2 LOW/MEDIUM/ERROR findings, 3 HIGH findings.
//////////////

// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- TextReporter and JsonReporter print a plain-text or JSON report on a terminal (standalone CLI, WP-CLI), never HTML: attacker-controlled fields are percent-encoded by sanitize_field() or encoded by json_encode().
// phpcs:disable WordPress.WP.AlternativeFunctions -- the engine also runs without WordPress (standalone CLI, recovery mode), where WP_Filesystem does not exist; it streams files and handles every failure itself.

///////////////
// $meta carries facts for the entry layer that are not part of the output
// contract (text and JSON ignore it): 'value_sha256' is the SHA-256 of the
// database value a DB finding is about, as scanned, so the plugin can bind
// a false-positive mark to that content the way file marks are bound to
// the file's hash.
//////////////
interface Reporter
{
    public function finding($severity, $type, $path, $detail, $context = array(), $meta = array());
    public function summary($scan, $data, $text);
    public function progress($text);
    public function fatal($message);
    public function exit_code();
}

abstract class BaseReporter implements Reporter
{
    protected $exit_code = 0;

    protected function track($severity)
    {
        if ('HIGH' === $severity) {
            $this->exit_code = max($this->exit_code, 3);
        } elseif ('INFO' !== $severity) {
            $this->exit_code = max($this->exit_code, 2);
        }
    }

    public function exit_code()
    {
        return ($this->exit_code);
    }

    public static function sanitize_field($text, $encode_commas)
    {
        $text = str_replace('%', '%25', (string) $text);
        if ($encode_commas) {
            $text = str_replace(',', '%2C', $text);
        }
        return preg_replace_callback('/[\x00-\x1F\x7F]/', function ($match) {
            return sprintf('%%%02X', ord($match[0]));
        }, $text);
    }

    ///////////////
    // Valid UTF-8 from any bytes: sequences that are well formed stay as
    // they are, every other byte becomes U+FFFD. JSON output and database
    // rows refuse invalid UTF-8 outright, and a finding must never be lost
    // because the attacker (or a multibyte value cut short) put one there.
    // No mbstring or iconv needed: locked-down hosts may have neither.
    //////////////
    public static function clean_utf8($text)
    {
        $text = (string) $text;
        if ('' === $text || preg_match('//u', $text) === 1) {
            return ($text);
        }
        $valid = '[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}'
            . '|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2}';
        $clean = preg_replace_callback('/((?:' . $valid . ')++)|./s', function ($match) {
            return (isset($match[1]) && '' !== $match[1]) ? $match[1] : "\xEF\xBF\xBD";
        }, $text);
        if (!is_string($clean)) {
            // PCRE gave up (limits): keep the ASCII, which is always valid.
            $clean = preg_replace('/[^\x00-\x7F]/', '?', $text);
        }
        return (is_string($clean) ? $clean : '');
    }

    // clean_utf8() for every string in a value, array keys included.
    public static function clean_utf8_deep($value)
    {
        if (is_string($value)) {
            return (self::clean_utf8($value));
        }
        if (!is_array($value)) {
            return ($value);
        }
        $clean = array();
        foreach ($value as $key => $item) {
            $clean[is_string($key) ? self::clean_utf8($key) : $key] = self::clean_utf8_deep($item);
        }
        return ($clean);
    }

    public static function format_text_finding($finding)
    {
        $text = $finding['severity'] . ',' . $finding['type'] . ','
            . self::sanitize_field($finding['path'], true) . ','
            . self::sanitize_field($finding['detail'], false) . "\n";
        foreach ($finding['context'] as $context_line) {
            $text .= '    ' . self::sanitize_field($context_line, false) . "\n";
        }
        return ($text);
    }
}

class TextReporter extends BaseReporter
{
    // When scanall runs in text mode, findings buffer here and print
    // severity-sorted at the end; null means report immediately.
    private $buffer = null;

    public function buffer_findings($enable)
    {
        $this->buffer = $enable ? array() : null;
    }

    public function finding($severity, $type, $path, $detail, $context = array(), $meta = array())
    {
        $this->track($severity);
        $finding = array('severity' => $severity, 'type' => $type, 'path' => $path, 'detail' => $detail, 'context' => $context);
        if (is_array($this->buffer)) {
            $this->buffer[] = $finding;
            return;
        }
        echo self::format_text_finding($finding);
    }

    public function summary($scan, $data, $text)
    {
        echo $text;
    }

    public function progress($text)
    {
        echo $text;
    }

    public function fatal($message)
    {
        echo 'Error: ' . $message . "\n";
    }

    public function flush_buffered()
    {
        ///////////////
        // Flush the buffered findings worst-first. ERROR sits right after
        // HIGH: something that blocked verification needs eyes too.
        //////////////
        if (!is_array($this->buffer)) {
            return;
        }
        $buffered = $this->buffer;
        $this->buffer = null;

        echo "\n== Findings by severity (" . count($buffered) . ") ==\n";
        foreach (array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO') as $severity_group) {
            foreach ($buffered as $finding) {
                if ($finding['severity'] === $severity_group) {
                    echo self::format_text_finding($finding);
                }
            }
        }
    }
}

class JsonReporter extends BaseReporter
{
    // One event as a JSON line. json_encode() returns false for a string
    // that is not valid UTF-8; the event is then encoded from a cleaned
    // copy, so the line is never empty.
    public static function encode(array $event)
    {
        $json = json_encode($event);
        if (false === $json) {
            $json = json_encode(self::clean_utf8_deep($event));
        }
        if (false === $json) {
            $json = json_encode(array(
                'event'    => isset($event['event']) ? $event['event'] : 'error',
                'severity' => 'ERROR',
                'type'     => 'REPORT_FAILED',
                'path'     => '',
                'detail'   => 'an event could not be encoded as JSON and was dropped',
            ));
        }
        return ($json . "\n");
    }

    public function finding($severity, $type, $path, $detail, $context = array(), $meta = array())
    {
        $this->track($severity);
        $event = array('event' => 'finding', 'severity' => $severity, 'type' => $type, 'path' => $path, 'detail' => $detail);
        if (!empty($context)) {
            $event['context'] = $context;
        }
        echo self::encode($event);
    }

    public function summary($scan, $data, $text)
    {
        echo self::encode(array_merge(array('event' => 'summary', 'scan' => $scan), $data));
    }

    public function progress($text)
    {
        // Informational text must stay off stdout in JSON mode: STDERR on
        // the CLI, nowhere when there is no STDERR.
        if (defined('STDERR')) {
            fwrite(STDERR, $text);
        }
    }

    public function fatal($message)
    {
        echo self::encode(array('event' => 'error', 'detail' => $message));
        if (defined('STDERR')) {
            fwrite(STDERR, 'Error: ' . $message . "\n");
        }
    }
}
