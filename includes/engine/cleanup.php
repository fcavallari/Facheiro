<?php
namespace Facheiro\Engine;

////////////////
// Signature-based malware detection and cleanup (the default scan mode).
//
// Files are collected first into a work file, then scanned in chunks so a
// web request can stop between chunks. The per-file logic is unchanged:
// a file is confirmed when its prefilter and every trigger match; the
// signature's action then removes the injection or deletes the file,
// unless dryrun is set, in which case nothing on disk changes.
//////////////

// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- an exception message is data, not output: the entry layer that catches it (CLI, WP-CLI, admin page, recovery page) escapes it for the place it shows it.
// phpcs:disable WordPress.WP.AlternativeFunctions -- the engine also runs without WordPress (standalone CLI, recovery mode), where WP_Filesystem does not exist; it streams files and handles every failure itself.

class SignatureScanner extends Scanner
{
    const CHUNK_FILES = 200;

    private $scan_dir;

    public function __construct(Context $ctx, $scan_dir)
    {
        parent::__construct($ctx);
        $this->scan_dir = $scan_dir;
    }

    public function name()
    {
        return ('signatures');
    }

    public function plan(array &$state)
    {
        if (!is_dir($this->scan_dir) || !is_readable($this->scan_dir)) {
            throw new Fatal('cannot open scan directory ' . $this->scan_dir);
        }
        require_outside_tool($this->ctx, $this->scan_dir);
        if (is_wordpress_root($this->scan_dir)) {
            Layout::report_notes($this->ctx, false);
        }
        return array(array('collect' => 1));
    }

    public function run(array $unit, array &$state)
    {
        if (isset($unit['collect'])) {
            return ($this->collect($state));
        }
        return ($this->scan_chunk($unit, $state));
    }

    private function collect(array &$state)
    {
        ///////////////
        // Walk the tree once and write every scannable path to a work file
        // (one base64-encoded path per line: filenames can contain newlines
        // and bytes that are not valid UTF-8).
        // Later chunks read from a byte offset, so no list sits in memory.
        //////////////
        $list_path = @tempnam($this->ctx->work_dir, 'facheiro-files');
        if (false === $list_path) {
            throw new Fatal('cannot create a work file in ' . $this->ctx->work_dir);
        }
        $fh = @fopen($list_path, 'w');
        if (false === $fh) {
            @unlink($list_path);
            throw new Fatal('cannot write the work file ' . $list_path);
        }

        // A run that can modify files stays inside the folders it was given:
        // a symbolic link can be planted by the web user, and the operator
        // may run the cleanup with more privileges. A report-only run
        // follows them, or everything behind a linked uploads folder would
        // go unread.
        $files = new TreeWalk(scan_roots($this->ctx, $this->scan_dir), !Layout::may_write($this->ctx));
        foreach ($files as $file) {
            // Skip the tool itself and anything outside the risky-extension
            // list (allfiles=1 overrides) - shared with the correlate walk.
            if (!is_scannable_file($this->ctx, $file)) {
                continue;
            }
            fwrite($fh, base64_encode($file->getPathname()) . "\n"); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- one path per line, whatever bytes the filename holds.
        }
        fclose($fh);
        $this->report_walk($files, 'NOT checked for malware signatures');

        $state['list'] = $list_path;
        return array('from' => 0);
    }

    private function scan_chunk(array $unit, array &$state)
    {
        if (!isset($state['list']) || !is_file($state['list'])) {
            throw new Fatal('the scan work file disappeared mid-scan');
        }
        $fh = @fopen($state['list'], 'r');
        if (false === $fh) {
            throw new Fatal('cannot read the scan work file ' . $state['list']);
        }
        fseek($fh, (int) $unit['from']);

        $processed = 0;
        while (true) {
            if ($processed >= self::CHUNK_FILES || ($processed > 0 && $this->ctx->out_of_time())) {
                $next = array('from' => ftell($fh));
                fclose($fh);
                return ($next);
            }
            $line = fgets($fh);
            if (false === $line) {
                break;
            }
            $target_file = base64_decode(rtrim($line, "\n"), true); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- see collect().
            if (!is_string($target_file) || '' === $target_file) {
                continue;
            }
            $processed++;
            $this->scan_file($target_file);
        }
        fclose($fh);
        @unlink($state['list']);
        unset($state['list']);
        return (null);
    }

    private function scan_file($target_file)
    {
        // Gone since the walk, or a symlink pointing nowhere: nothing to read.
        if (!is_file($target_file)) {
            return;
        }
        $filesize = @filesize($target_file);
        if (false !== $filesize && $filesize > Signatures::FILESIZE_LIMIT) {
            $this->report_too_large($target_file, $filesize);
            return;
        }
        $fh = @fopen($target_file, 'r');
        if (false === $fh) {
            $this->report('ERROR', 'FILE_UNREADABLE', $target_file, 'cannot open the file: NOT checked for malware signatures');
            return;
        }
        // One byte past the cap tells a file that grew since the stat from
        // one that fits: a cleanup must never write back a truncated read.
        $buffer = @fread($fh, Signatures::FILESIZE_LIMIT + 1);
        @fclose($fh);
        if (false === $buffer) {
            $this->report('ERROR', 'FILE_UNREADABLE', $target_file, 'cannot read the file: NOT checked for malware signatures');
            return;
        }
        if (strlen($buffer) > Signatures::FILESIZE_LIMIT) {
            $this->report_too_large($target_file, strlen($buffer));
            return;
        }
        $this->cleanup($buffer, $target_file);
    }

    private function report_too_large($target_file, $size)
    {
        ///////////////
        // Never a silent skip. Large JavaScript bundles are normal (core's
        // own wp-includes/js/dist has several), so those stay INFO; PHP this
        // large is rare and is where a padded backdoor hides, so it is an
        // ERROR like any other check that could not run.
        //////////////
        $limit_mb = (int) (Signatures::FILESIZE_LIMIT / 1048576);
        $detail = 'larger than the ' . $limit_mb . ' MB signature scan limit (' . $size . ' bytes): NOT checked for malware signatures';
        if (is_php_file($target_file)) {
            $this->report('ERROR', 'FILE_TOO_LARGE', $target_file, $detail . ' - PHP this large is unusual, review it by hand');
            return;
        }
        $this->report('INFO', 'FILE_TOO_LARGE', $target_file, $detail);
    }

    private function cleanup($file_buffer, $file_path)
    {
        // Signatures whose regex the engine could not finish on this file.
        $failed = array();
        self::take_regex_error();

        // First confirmed signature wins: apply its action, then stop.
        foreach (Signatures::cleanup() as $signature_name => $signature) {
            $matched = self::signature_matches($file_buffer, $signature);
            $error = self::take_regex_error();
            if (0 !== $error) {
                $failed[$signature_name] = $error;
            }
            if ($matched) {
                $this->apply_action($file_buffer, $file_path, $signature_name, $signature['action']);
                return;
            }
        }

        // Nothing matched the raw bytes: the built-in detection set gets a
        // second look with split strings joined and escapes decoded. Report
        // only, like the rest of that set; custom signatures see raw bytes,
        // as documented.
        $normalized = Signatures::normalize_code($file_buffer);
        if ($normalized !== $file_buffer) {
            foreach (Signatures::builtin_detection() as $signature_name => $signature) {
                $matched = self::signature_matches($normalized, $signature);
                $error = self::take_regex_error();
                if (0 !== $error && !isset($failed[$signature_name])) {
                    $failed[$signature_name] = $error;
                }
                if ($matched) {
                    $this->report_detection($file_path, $signature_name, $signature['action'], ' after joining split strings and decoding escapes');
                    return;
                }
            }
        }
        $this->report_regex_errors($file_path, $failed);
    }

    private function report_regex_errors($file_path, array $failed)
    {
        ///////////////
        // A regex the engine gives up on (backtrack, recursion or JIT stack
        // limit) is a check that did not run, not a clean result: say so,
        // like FILE_TOO_LARGE, instead of letting "no match" stand.
        //////////////
        if (array() === $failed) {
            return;
        }
        $parts = array();
        foreach ($failed as $signature_name => $error) {
            $parts[] = $signature_name . ' (' . self::regex_error_text($error) . ')';
        }
        $this->report('ERROR', 'SIGNATURE_ERROR', $file_path, 'the regex engine gave up on ' . implode(', ', $parts) . ': this file was NOT checked by those signatures - review it by hand');
    }

    private static function regex_error_text($error)
    {
        if (PREG_BACKTRACK_LIMIT_ERROR === $error) {
            return ('backtrack limit, pcre.backtrack_limit');
        }
        if (PREG_RECURSION_LIMIT_ERROR === $error) {
            return ('recursion limit, pcre.recursion_limit');
        }
        if (defined('PREG_JIT_STACKLIMIT_ERROR') && constant('PREG_JIT_STACKLIMIT_ERROR') === $error) {
            return ('JIT stack limit');
        }
        if (PREG_BAD_UTF8_ERROR === $error || PREG_BAD_UTF8_OFFSET_ERROR === $error) {
            return ('the file is not valid UTF-8 for a /u pattern');
        }
        return ('regex engine error ' . (int) $error);
    }

    // The engine error of the last regex condition that failed to run since
    // the previous call (0 for none), then reset.
    private static $regex_error = 0;

    public static function take_regex_error()
    {
        $error = self::$regex_error;
        self::$regex_error = 0;
        return ($error);
    }

    private function report_detection($file_path, $signature_name, $action, $how)
    {
        $how = ('' === $how) ? '' : 'matched' . $how . '; ';
        $this->report($action['detect'], 'MALWARE_FOUND', $file_path, $signature_name . ': ' . $action['description'] . ' (' . $how . 'detection only: never cleaned automatically, review the file)');
    }

    public static function pattern_matches($condition, $file_buffer)
    {
        // A condition is array('string' => needle), array('regex' => pattern)
        // or, built-in only, array('absent' => needles).
        if (isset($condition['string'])) {
            return (false !== strpos($file_buffer, $condition['string']));
        }
        if (isset($condition['absent']) && is_array($condition['absent']) && array() !== $condition['absent']) {
            // Built-in only: true when none of the strings occurs.
            foreach ($condition['absent'] as $needle) {
                if ('' === $needle || false !== strpos($file_buffer, $needle)) {
                    return (false);
                }
            }
            return (true);
        }
        if (isset($condition['regex'])) {
            // preg_match returns false on engine errors (e.g. backtrack limit);
            // only an explicit 1 counts as a match so errors never flag a file.
            // The error is kept so the scan can report the file as unchecked.
            $result = preg_match($condition['regex'], $file_buffer);
            if (false === $result) {
                $error = preg_last_error();
                self::$regex_error = (PREG_NO_ERROR === $error) ? PREG_INTERNAL_ERROR : $error;
            }
            return (1 === $result);
        }
        // Unknown condition types never match, so a typo'd signature fails
        // closed instead of flagging files.
        return (false);
    }

    public static function signature_matches($file_buffer, $signature)
    {
        // The prefilter is the cheap first check and counts as confirmed
        // evidence; every additional trigger must ALSO match.
        if (!self::pattern_matches($signature['prefilter'], $file_buffer)) {
            return (false);
        }
        foreach ($signature['triggers'] as $trigger) {
            if (!self::pattern_matches($trigger, $file_buffer)) {
                return (false);
            }
        }
        return (true);
    }

    ///////////////
    // Apply a remove_regex. With a 'start' pattern the file is cut where
    // each injection begins and every stretch is cleaned on its own: the
    // removal patterns are greedy up to the campaign's closing sequence, and
    // on a file injected twice one match would otherwise run from the first
    // injection to the end of the second, taking the legitimate code between
    // them. Null when the regex engine gives up on any stretch.
    //////////////
    public static function remove_matches($file_buffer, $action)
    {
        if (!isset($action['start'])) {
            return (preg_replace($action['remove_regex'], '', $file_buffer));
        }
        $hits = array();
        $found = preg_match_all($action['start'], $file_buffer, $hits, PREG_OFFSET_CAPTURE);
        if (false === $found) {
            return (null);
        }
        if ($found < 2) {
            return (preg_replace($action['remove_regex'], '', $file_buffer));
        }
        // The first stretch runs from the top of the file to the second
        // start, the last one to the end of the file.
        $cleared = '';
        $from = 0;
        for ($i = 1; $i <= $found; $i++) {
            $to = ($i < $found) ? $hits[0][$i][1] : strlen($file_buffer);
            $piece = preg_replace($action['remove_regex'], '', substr($file_buffer, $from, $to - $from));
            if (null === $piece) {
                return (null);
            }
            $cleared .= $piece;
            $from = $to;
        }
        return ($cleared);
    }

    private function apply_action($file_buffer, $file_path, $signature_name, $action)
    {
        $dryrun = $this->ctx->has('dryrun');

        ///////////////
        // A symbolic link is never written through or replaced. The rename
        // in write_cleaned_file() would swap the link for a regular file and
        // leave the real, still infected file where it is; writing to the
        // target instead would let a link planted by the web user point a
        // more privileged operator's cleanup at any file. Report it and let
        // the operator scan the folder the target lives in. Said the same
        // way in a dry run, which must predict what the real run does.
        //////////////
        if ((isset($action['remove_regex']) || isset($action['delete_file'])) && is_link($file_path)) {
            $target = @realpath($file_path);
            $this->report('HIGH', 'MALWARE_FOUND', $file_path, $signature_name . ' (symbolic link' . (false === $target ? '' : ' to ' . $target) . ': never modified, clean the file it points to)');
            return;
        }

        if (isset($action['remove_regex'])) {
            // $file_buffer already holds the whole file: files larger than
            // the read cap are reported as FILE_TOO_LARGE, never scanned.
            $cleared_file = self::remove_matches($file_buffer, $action);
            if ($cleared_file === null || (strlen($file_buffer) === strlen($cleared_file))) {
                $this->report('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': cleanup regex removed nothing: ' . $action['remove_regex']);
                return;
            }
            // Dry run: the cleanup regex was applied and verified to change
            // the file, but nothing is written or deleted.
            if ($dryrun) {
                $this->report('HIGH', 'MALWARE_FOUND', $file_path, $signature_name . ' (dry run: file not modified)');
                return;
            }
            if (!write_cleaned_file($file_path, $cleared_file)) {
                $this->report('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': could not write cleaned file');
                return;
            }
            $this->report('HIGH', 'MALWARE_CLEANED', $file_path, $signature_name);
            return;
        }

        if (isset($action['delete_file'])) {
            if ($dryrun) {
                $this->report('HIGH', 'MALWARE_FOUND', $file_path, $signature_name . ' (dry run: file not deleted)');
                return;
            }
            if (false === @unlink($file_path)) {
                $this->report('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': could not delete file');
                return;
            }
            $this->report('HIGH', 'MALWARE_CLEANED', $file_path, $signature_name . ' (file deleted)');
            return;
        }

        if (isset($action['detect'])) {
            // Built-in detection set: report only, in dry and real runs
            // alike. A generic shape names no bytes to remove.
            $this->report_detection($file_path, $signature_name, $action, '');
            return;
        }

        if (isset($action['report'])) {
            // Custom signatures: detection only, identical in dry and real
            // runs.
            $about = (isset($action['description']) && '' !== $action['description']) ? ': ' . $action['description'] : '';
            $this->report($action['report'], 'SIGNATURE_MATCH', $file_path, $signature_name . $about . ' (custom signature, report only)');
            return;
        }

        $this->report('ERROR', 'CLEANUP_FAILED', $file_path, 'unknown action for signature ' . $signature_name);
    }
}
