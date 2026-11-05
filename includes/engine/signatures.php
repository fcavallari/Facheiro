<?php
namespace Elderward\Engine;

////////////////
// Signature data. Every set is compile-checked by Signatures::lint() before
// a scan starts: a malformed regex stops the run naming the signature
// instead of silently never matching.
//////////////

// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- an exception message is data, not output: the entry layer that catches it (CLI, WP-CLI, admin page, recovery page) escapes it for the place it shows it.

final class Signatures
{
    // Files larger than this are skipped by the signature scanner (and the
    // buffer read per file is capped at it).
    const FILESIZE_LIMIT = 2097152;

    // Site-specific signatures added by the operator (plugin signature
    // editor, or signatures=<file.json> on the standalone CLI). They run
    // after the built-in ones and are detection-only: file signatures carry
    // the 'report' action, never remove_regex or delete_file.
    private static $custom = array('cleanup' => array(), 'db_options' => array(), 'db_posts' => array());

    /**
     * Install custom signatures (replaces any set before).
     *
     * @param array $custom array('cleanup' => name => signature,
     *                      'db_options' => list, 'db_posts' => list).
     */
    public static function set_custom(array $custom)
    {
        $clean = array('cleanup' => array(), 'db_options' => array(), 'db_posts' => array());
        if (isset($custom['cleanup']) && is_array($custom['cleanup'])) {
            foreach ($custom['cleanup'] as $name => $signature) {
                // Whatever the source says, a custom file signature only
                // reports: an operator- or assistant-written regex must not
                // be able to rewrite or delete files during a cleanup run.
                $description = '';
                if (isset($signature['action']['description'])) {
                    $description = (string) $signature['action']['description'];
                } elseif (isset($signature['description'])) {
                    $description = (string) $signature['description'];
                }
                $severity = (isset($signature['action']['report']) && in_array($signature['action']['report'], array('HIGH', 'MEDIUM', 'LOW'), true)) ? $signature['action']['report'] : 'HIGH';
                $clean['cleanup'][(string) $name] = array(
                    'prefilter'   => isset($signature['prefilter']) ? $signature['prefilter'] : null,
                    'triggers'    => (isset($signature['triggers']) && is_array($signature['triggers'])) ? array_values($signature['triggers']) : array(),
                    'action'      => array('report' => $severity, 'description' => $description),
                );
            }
        }
        foreach (array('db_options', 'db_posts') as $set) {
            if (isset($custom[$set]) && is_array($custom[$set])) {
                foreach ($custom[$set] as $signature) {
                    $clean[$set][] = $signature;
                }
            }
        }
        self::$custom = $clean;
    }

    public static function custom()
    {
        return self::$custom;
    }

    ////////////////
    // Custom signature definitions: the one format shared by the plugin's
    // signature editor, its export/import, the assistant tools and the CLI's
    // signatures=<file.json>:
    //
    //   {"elderward_signatures": 1, "signatures": [
    //     {"id": "acme-shell", "target": "file", "severity": "HIGH",
    //      "description": "...", "enabled": true,
    //      "match": [{"string": "acme_shell("}, {"regex": "/eval\\s*\\(/"}]},
    //     {"id": "spam-link", "target": "db_option" | "db_post",
    //      "severity": "MEDIUM", "description": "...", "pattern": "@casino@i"}
    //   ]}
    //
    // File signatures: every condition must match; the first is the
    // prefilter, so make it the cheapest (a plain string).
    //////////////
    const MAX_CONDITIONS = 10;
    const MAX_PATTERN = 2000;

    public static function targets()
    {
        return array('file', 'db_option', 'db_post');
    }

    /**
     * Problem with one definition, or null when it is valid.
     */
    public static function validate_definition($def)
    {
        if (!is_array($def)) {
            return 'a signature must be an object';
        }
        $id = isset($def['id']) ? $def['id'] : '';
        if (!is_string($id) || 1 !== preg_match('/^[a-z0-9][a-z0-9._-]{1,62}$/', $id)) {
            return 'id must be 2-63 characters of a-z, 0-9, dot, dash or underscore';
        }
        $target = isset($def['target']) ? $def['target'] : '';
        if (!in_array($target, self::targets(), true)) {
            return $id . ': target must be one of ' . implode(', ', self::targets());
        }
        $severity = isset($def['severity']) ? $def['severity'] : '';
        if (!in_array($severity, array('HIGH', 'MEDIUM', 'LOW'), true)) {
            return $id . ': severity must be HIGH, MEDIUM or LOW';
        }
        if (isset($def['description']) && !is_string($def['description'])) {
            return $id . ': description must be text';
        }
        if ('file' === $target) {
            if (!isset($def['match']) || !is_array($def['match']) || count($def['match']) < 1 || count($def['match']) > self::MAX_CONDITIONS) {
                return $id . ': match must list 1 to ' . self::MAX_CONDITIONS . ' conditions';
            }
            foreach (array_values($def['match']) as $i => $condition) {
                $problem = self::validate_condition($condition);
                if (null !== $problem) {
                    return $id . ': condition ' . ($i + 1) . ': ' . $problem;
                }
            }
            return null;
        }
        $pattern = isset($def['pattern']) ? $def['pattern'] : null;
        $problem = self::validate_condition(array('regex' => $pattern));
        return (null === $problem) ? null : $id . ': pattern: ' . $problem;
    }

    private static function validate_condition($condition)
    {
        if (!is_array($condition) || 1 !== count($condition)) {
            return 'must be {"string": ...} or {"regex": ...}';
        }
        if (isset($condition['string'])) {
            if (!is_string($condition['string']) || strlen($condition['string']) < 3 || strlen($condition['string']) > self::MAX_PATTERN) {
                return 'string must be 3 to ' . self::MAX_PATTERN . ' characters';
            }
            return null;
        }
        if (isset($condition['regex'])) {
            $regex = $condition['regex'];
            if (!is_string($regex) || '' === $regex || strlen($regex) > self::MAX_PATTERN) {
                return 'regex must be 1 to ' . self::MAX_PATTERN . ' characters';
            }
            if (false === @preg_match($regex, '')) {
                return 'regex does not compile (bring delimiters, e.g. /eval\\(/i)';
            }
            // A pattern that matches the empty string would flag every file.
            if (1 === @preg_match($regex, '')) {
                return 'regex matches an empty file, so it would flag everything';
            }
            return null;
        }
        return 'must be {"string": ...} or {"regex": ...}';
    }

    /**
     * Turn valid, enabled definitions into the set_custom() structure.
     * Invalid definitions throw Fatal naming the signature.
     */
    public static function from_definitions(array $defs)
    {
        $custom = array('cleanup' => array(), 'db_options' => array(), 'db_posts' => array());
        foreach ($defs as $def) {
            $problem = self::validate_definition($def);
            if (null !== $problem) {
                throw new Fatal('invalid custom signature ' . $problem);
            }
            if (isset($def['enabled']) && false === $def['enabled']) {
                continue;
            }
            $name = 'custom.' . $def['id'];
            $description = isset($def['description']) ? $def['description'] : '';
            if ('file' === $def['target']) {
                $match = array_values($def['match']);
                $custom['cleanup'][$name] = array(
                    'prefilter'   => $match[0],
                    'triggers'    => array_slice($match, 1),
                    'action'      => array('report' => $def['severity'], 'description' => $description),
                );
            } else {
                $set = ('db_option' === $def['target']) ? 'db_options' : 'db_posts';
                $custom[$set][] = array(
                    'name'        => $name,
                    'pattern'     => $def['pattern'],
                    'severity'    => $def['severity'],
                    'description' => '' === $description ? 'custom signature' : $description,
                );
            }
        }
        return $custom;
    }

    /**
     * Parse a signature file (JSON text) into definitions.
     */
    public static function parse_file($json)
    {
        $data = json_decode($json, true);
        if (!is_array($data) || !isset($data['signatures']) || !is_array($data['signatures'])) {
            throw new Fatal('signature file must be JSON with a "signatures" list');
        }
        return array_values($data['signatures']);
    }

    /**
     * Which custom definitions match a piece of text: the editor's and the
     * assistant tools' "test" button. Returns ids.
     */
    public static function test_definitions(array $defs, $text)
    {
        $hits = array();
        foreach ($defs as $def) {
            if (null !== self::validate_definition($def)) {
                continue;
            }
            if ('file' === $def['target']) {
                $all = true;
                foreach ($def['match'] as $condition) {
                    if (!SignatureScanner::pattern_matches($condition, $text)) {
                        $all = false;
                        break;
                    }
                }
                if ($all) {
                    $hits[] = $def['id'];
                }
            } elseif (1 === preg_match($def['pattern'], $text)) {
                $hits[] = $def['id'];
            }
        }
        return $hits;
    }

    public static function cleanup()
    {
        // Order matters: the first signature that matches a file wins, so
        // the ones that can clean come first, then the built-in detection
        // set (strongest evidence first), then the custom set.
        return array_merge(self::builtin_cleanup(), self::builtin_detection(), self::$custom['cleanup']);
    }

    public static function db_options()
    {
        return array_merge(self::builtin_db_options(), self::$custom['db_options']);
    }

    public static function db_posts()
    {
        return array_merge(self::builtin_db_posts(), self::$custom['db_posts']);
    }

    ////////////////
    // Cleanup signatures.
    //
    // Each entry is keyed by a unique signature name and holds:
    //
    //   'prefilter'  One cheap condition, checked first on every file. It counts
    //                as confirmed evidence, so it does not need to be repeated
    //                in the triggers.
    //   'triggers'   Zero or more further conditions that must ALL also match
    //                before the file is considered infected.
    //   'action'     What to do with a confirmed file.
    //
    // A condition is array('string' => needle) (fast strpos lookup, preferred
    // for the prefilter) or array('regex' => pattern). Regexes are full PCRE
    // patterns: bring your own delimiters and flags. Built-in triggers may
    // also use array('absent' => array(needles)), true when none of the
    // strings occur in the file (custom signatures cannot: it can only
    // widen a match, never confirm one).
    //
    // Actions:
    //   array('remove_regex' => pattern)   Delete every match of the pattern
    //                                      from the file. Fails (and reports)
    //                                      if nothing was removed. It must
    //                                      begin at the campaign's own marker,
    //                                      never at a shape legitimate code
    //                                      shares. With 'start' => pattern
    //                                      (where one injection begins) the
    //                                      file is cut at every start and each
    //                                      stretch cleaned on its own, so a
    //                                      greedy removal cannot run from one
    //                                      injection into the next and take
    //                                      the legitimate code between them.
    //   array('delete_file' => true)       Delete the whole file.
    //   array('report' => SEVERITY)        Report SIGNATURE_MATCH only, never
    //                                      modify (custom signatures).
    //   array('detect' => SEVERITY,        Report MALWARE_FOUND only, never
    //         'description' => text)       modify (built-in detection set).
    //////////////
    public static function builtin_cleanup()
    {
        return array(
            'javascript_ndsw' => array(
                'prefilter' => array('regex' => '/if\((typeof)?\s*nds.===.?undefined.?\)/'),
                'triggers'  => array(
                    array('regex' => '/\w\s*=\s*parseInt\(\w\(\w\.\w\)\)\s*\/\s*[\dx]+\s*[\+\s*\-]+\s*parseInt\(\w\(\w\.\w\)\)\s*\/\s*[\dx]+\s*[\+\s*\-]+\s*/'),
                ),
                'action'    => array(
                    'remove_regex' => '/if\((typeof)?\s*nds.===.?undefined.?\)[^#]+return\s*A\s*\(\s*\)\s*;?\s*}\s*}\s*;?/s',
                    'start'        => '/if\((typeof)?\s*nds.===.?undefined.?\)/',
                ),
            ),
            'javascript_wqpq' => array(
                'prefilter' => array('regex' => '/if\((typeof)?\s*wqpq\s*===.?undefined.?\)/'),
                'triggers'  => array(
                    array('regex' => '/try{var\s*\w\s*=\s*\-?parseInt\(\w\(0x\d+,\s*.\w+/'),
                ),
                // The removal starts at the wqpq guard itself: "\w+" here
                // once matched any typeof guard (if(typeof jQuery===
                // "undefined")), and on a one-line minified file took the
                // legitimate code from that guard to the injection with it.
                'action'    => array(
                    'remove_regex' => '/if\((typeof)?\s*wqpq\s*===.?undefined.?\)[^\n]+;\s*\}\s*\}\s*\(\s*\)\s*\);\s*\};/s',
                    'start'        => '/if\((typeof)?\s*wqpq\s*===.?undefined.?\)/',
                ),
            ),
        );
    }

    ////////////////
    // Built-in detection signatures: generic webshell and backdoor shapes,
    // modelled on the detections that php-malware-finder, AMWScan,
    // signature-base (gen_webshells), scr34m/php-malware-scanner and Linux
    // Malware Detect have in common. They are re-expressed here, not copied.
    //
    // They only report (MALWARE_FOUND with their own severity), in dry and
    // real runs alike: a generic shape says "this is a backdoor", not which
    // bytes are the injection, so removing it is the operator's call.
    //
    // HIGH means a dangerous sink fed straight from the request, a password
    // gate or a known shell family: no legitimate plugin does that. MEDIUM
    // means obfuscation that legitimate code almost never needs (some
    // commercial licence checks do it); verify before removing.
    //
    // Shapes are bounded ({0,N}) so no pattern can backtrack across a whole
    // file, and every prefilter is cheap. Each one has a positive case and
    // clean-code negatives in tests/regress.sh.
    //////////////
    public static function builtin_detection()
    {
        // Built once per process: the scan asks for the set for every file.
        static $set = null;
        if (null !== $set) {
            return ($set);
        }
        // Request input: indexed superglobals in their direct and indirect
        // spellings, request headers, and the raw request body. Bare names
        // ("we require $_GET") are prose in comments, not input.
        $req = '(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*[\[{]|\$_SERVER\s*\[\s*[\'"]HTTP_|\$\{\s*[\'"]_(?:GET|POST|REQUEST|COOKIE)[\'"]\s*\}'
            . '|\$GLOBALS\s*\[\s*[\'"]_(?:GET|POST|REQUEST|COOKIE)[\'"]\s*\]|file_get_contents\s*\(\s*[\'"]php://input[\'"]\s*\)|getallheaders\s*\(\s*\)'
            // A whole superglobal unwrapped to one value: eval(end($_POST)).
            . '|(?:end|current|reset|array_pop|array_shift|implode|join)\s*\(\s*(?:[\'"][^\'"]{0,8}[\'"]\s*,\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b)';
        // Up to four decoding wrappers between a sink and its input.
        $dec = '(?:@?\s*(?:(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|stripslashes|urldecode|rawurldecode|hex2bin|convert_uudecode|trim)\s*\(|pack\s*\(\s*[\'"]H\*[\'"]\s*,)\s*){0,4}';
        // A variable name: PHP allows bytes 0x80-0xff, which \w (no /u) does not match.
        $v = '[\w\x80-\xff]';
        // A function call, not a method ($x->eval(), X::eval()) or a longer
        // name ending the same way (curl_exec).
        $fn = '(?<![\w>:$])';
        $code_sinks = '(?:eval|assert|create_function|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)';
        $req_prefilter = array('regex' => '~_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|php://input|getallheaders~');
        // include/require as a statement, not the word in a path
        // ('include/images/x.png', $x->include()) or in prose ("requests do
        // not include $_GET['key']": a word and a space before it). Checked
        // with fixed-length lookbehinds so the match starts at the keyword.
        $inc = '(?<![\w$>:\\\\/.\'"-])(?:(?<!\w[ \t])|(?<=else[ \t]|php[ \t]))(?:include|require)(?:_once)?\b(?![-/])';
        // The file uses WordPress's own permission or upload checks: a
        // plugin's upload handler, not an uploader shell. Only the looser
        // shapes are excused by it.
        // A plain string search: a whole-file regex for "none of these"
        // runs into pcre.backtrack_limit on large files.
        $wp_guarded = array('absent' => array('current_user_can', 'wp_verify_nonce', 'check_admin_referer', 'check_ajax_referer', 'sanitize_file_name', 'wp_handle_upload'));
        // One escaped character of a name (\\x41 hex, \\101 or \\66 octal).
        $esc_digit = '\\\\x3[0-9]|\\\\0?(?:6[0-7]|7[01])';
        $esc_upper = '\\\\x(?:4[1-9a-f]|5[0-9a])|\\\\1(?:0[1-7]|[1-2][0-7]|3[0-2])';
        $esc_lower = '\\\\x(?:5f|6[1-9a-f]|7[0-9a])|\\\\1(?:37|4[1-7]|[56][0-7]|7[0-2])';
        $esc_name = $esc_digit . '|' . $esc_upper . '|' . $esc_lower;
        // The client's file name for an upload.
        $client_name = '\$_FILES\s*\[[^\]]{1,40}\]\s*\[\s*[\'"]name[\'"]\s*\]';
        $tmp_name = '\$_FILES\s*\[[^\]]{1,40}\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]';

        $set = array(
            'php_eval_request' => array(
                'prefilter' => array('regex' => '~(?:eval|assert|create_function)\s*\(~i'),
                'triggers'  => array(
                    array('regex' => '~' . $fn . '(?:(?:eval|assert|create_function)\s*\(|create_function\s*\([^,;)]{0,60},)\s*' . $dec . '@?\s*' . $req . '~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'code from the request is evaluated (eval/assert/create_function on request input)'),
            ),
            'php_exec_request' => array(
                'prefilter' => $req_prefilter,
                'triggers'  => array(
                    array('regex' => '~' . $fn . '(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*' . $dec . '@?\s*' . $req . '~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a shell command from the request is executed'),
            ),
            'php_sink_request_variable' => array(
                'prefilter' => $req_prefilter,
                'triggers'  => array(
                    array('regex' => '~\$(' . $v . '{1,40})\s*=\s*' . $dec . '@?\s*' . $req . '[^;]{0,200};[\s\S]{0,3000}?' . $fn . $code_sinks . '\s*\(\s*' . $dec . '@?\s*[\'"]?\$\1(?!' . $v . ')~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'request input is copied to a variable that is then evaluated or executed'),
            ),
            'php_request_callback' => array(
                'prefilter' => $req_prefilter,
                'triggers'  => array(
                    array('regex' => '~(?:\$_(?:GET|POST|REQUEST|COOKIE)|\$\{\s*[\'"]_(?:GET|POST|REQUEST|COOKIE)[\'"]\s*\})\s*\[[^\]]{1,40}\]\s*\(\s*(?:[$@\'"\d)\\\\]|\w{1,40}\s*\()'
                        . '|' . $fn . '(?:call_user_func(?:_array)?|array_map|register_shutdown_function|register_tick_function|forward_static_call(?:_array)?|ob_start|iterator_apply)\s*\(\s*' . $dec . '@?\s*' . $req
                        . '|' . $fn . '(?:array_filter|array_walk(?:_recursive)?|usort|uasort|uksort|array_reduce|preg_replace_callback|array_diff_ukey|array_udiff|array_intersect_ukey)\s*\([^,;()]{1,200},\s*' . $dec . '@?\s*' . $req
                        . '|' . $fn . '(?:usort|uasort|uksort|array_diff_ukey|array_diff_uassoc|array_udiff(?:_u?assoc)?|array_intersect_ukey|array_intersect_uassoc|array_uintersect(?:_assoc)?)\s*\([^;]{0,300}?,\s*@?\s*' . $req . '[^,;()]{0,60}\)\s*;~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a function named by the request is called (request input used as a callback)'),
            ),
            'php_dangerous_callback_name' => array(
                'prefilter' => array('regex' => '~[\'"](?:assert|eval|create_function|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[\'"]~i'),
                'triggers'  => array(
                    array('regex' => '~' . $fn . '(?:call_user_func(?:_array)?|array_map|register_shutdown_function|register_tick_function|forward_static_call(?:_array)?|ob_start|iterator_apply)\s*\(\s*[\'"](?:assert|eval|create_function|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[\'"]'
                        . '|' . $fn . '(?:array_filter|array_walk(?:_recursive)?|usort|uasort|uksort|array_reduce|preg_replace_callback)\s*\([^,;()]{1,200},\s*[\'"](?:assert|create_function|system|shell_exec|passthru|exec|popen|proc_open)[\'"]~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a code or command function is passed by name as a callback (hidden eval/exec)'),
            ),
            'php_variable_function_name' => array(
                'prefilter' => array('regex' => '~[\'"](?:assert|create_function|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[\'"]~i'),
                'triggers'  => array(
                    array('regex' => '~\$(' . $v . '{1,40})\s*=\s*[\'"](?:assert|create_function|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[\'"]\s*;[\s\S]{0,3000}?(?<![\w>:$\\\\])\$\1\s*\(~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a code or command function name is stored in a variable and called through it'),
            ),
            'php_extract_request_call' => array(
                'prefilter' => array('regex' => '~extract\s*\(~i'),
                'triggers'  => array(
                    array('regex' => '~' . $fn . 'extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*[,)]~i'),
                    array('regex' => '~(?<![\w>:$\\\\])\$' . $v . '{1,40}\s*\(\s*@?\$' . $v . '{1,40}\s*(?:,\s*@?\$' . $v . '{1,40}\s*){0,3}\)~'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'request input is turned into variables (extract) and a variable is called as a function'),
            ),
            'php_request_alias_call' => array(
                'prefilter' => $req_prefilter,
                'triggers'  => array(
                    array('regex' => '~\$(' . $v . '{1,40})\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*;[\s\S]{0,600}?\$\1\s*\[[^\]]{1,40}\]\s*\(~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a copy of the request array is called through one of its entries'),
            ),
            'php_include_request' => array(
                'prefilter' => $req_prefilter,
                'triggers'  => array(
                    array('regex' => '~' . $inc . '\s*\(?\s*' . $dec . '@?\s*' . $req . '~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a file named by the request is included and run'),
            ),
            'php_request_file_write' => array(
                'prefilter' => $req_prefilter,
                'triggers'  => array(
                    array('regex' => '~' . $fn . '(?:file_put_contents|copy)\s*\(\s*' . $dec . '@?\s*' . $req
                        . '|' . $fn . 'fopen\s*\(\s*@?\s*' . $req . '[^;]{0,80},\s*[\'"][waxc]'
                        . '|' . $fn . 'copy\s*\([^,;()]{1,200},\s*@?\s*' . $req . '~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a file named by the request is written (dropper or file manager backdoor)'),
            ),
            'php_request_name_write' => array(
                'prefilter' => array('regex' => '~(?:file_put_contents|copy|rename|move_uploaded_file)\s*\(~i'),
                'triggers'  => array(
                    $req_prefilter,
                    // The file name from the request is held in a variable
                    // first, then written to, copied or moved.
                    array('regex' => '~\$(' . $v . '{1,40})\s*=\s*(?:@?\s*(?:basename|stripslashes|trim|urldecode|base64_decode)\s*\(\s*){0,3}@?\s*' . $req . '[^;]{0,60};[\s\S]{0,600}?' . $fn . '(?:file_put_contents|copy|rename|move_uploaded_file)\s*\(\s*(?:[^,;()]{0,80}?[\s.(\'"])?\$\1(?!' . $v . ')[^,;()]{0,40},'
                        . '|\$(' . $v . '{1,40})\s*=\s*(?:@?\s*(?:basename|stripslashes|trim|urldecode)\s*\(\s*){0,3}@?\s*' . $req . '[^;]{0,60};[\s\S]{0,600}?' . $fn . '(?:copy|rename|move_uploaded_file)\s*\([^,;()]{1,100},\s*(?:[^,;()]{0,80}?[\s.(\'"])?\$\2(?!' . $v . ')~i'),
                    $wp_guarded,
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a file named by the request (through a variable) is written, with no WordPress permission check in the file (dropper or file manager backdoor)'),
            ),
            'php_raw_upload' => array(
                'prefilter' => array('string' => 'tmp_name'),
                'triggers'  => array(
                    array('regex' => '~' . $fn . '(?:move_uploaded_file|copy)\s*\(\s*@?\s*' . $tmp_name . '\s*,\s*@?\s*(?:' . $client_name . '|' . $req . ')~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'an uploaded file is saved under the name the client chose (uploader shell)'),
            ),
            'php_upload_client_name' => array(
                'prefilter' => array('string' => 'tmp_name'),
                'triggers'  => array(
                    // The destination ends in the client's file name or a
                    // request field, through a path or a variable.
                    array('regex' => '~' . $fn . '(?:move_uploaded_file|copy)\s*\(\s*@?\s*' . $tmp_name . '\s*,\s*@?\s*[^,;()]{0,100}?[\s.(\'"](?:' . $client_name . '|' . $req . ')'
                        . '|\$(' . $v . '{1,40})\s*=\s*[^;]{0,100}?' . $client_name . '[^;]{0,60};[\s\S]{0,800}?' . $fn . '(?:move_uploaded_file|copy)\s*\([^,;]{1,100},\s*[^;]{0,60}?\$\1(?!' . $v . ')~i'),
                    $wp_guarded,
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'an uploaded file is saved under the name the client chose, with no WordPress permission or upload check in the file (uploader shell)'),
            ),
            'php_password_gate' => array(
                'prefilter' => $req_prefilter,
                'triggers'  => array(
                    array('regex' => '~(?:md5|sha1|crc32)\s*\(\s*@?\s*' . $req . '[^)]{0,60}\)\s*(?:===?|!==?)\s*[\'"][0-9a-f]{8,64}[\'"]'
                        . '|hash\s*\(\s*[\'"]\w{3,12}[\'"]\s*,\s*@?\s*' . $req . '[^)]{0,60}\)\s*(?:===?|!==?)\s*[\'"][0-9a-f]{8,64}[\'"]'
                        . '|[\'"][0-9a-f]{8,64}[\'"]\s*(?:===?|!==?)\s*(?:md5|sha1|crc32)\s*\(\s*@?\s*' . $req
                        // WSO / FilesMan keep the hash in $auth_pass and compare it later.
                        . '|\$auth_pass\s*=\s*[\'"][0-9a-f]{32}[\'"]~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'access is gated by a hard-coded password hash compared with request input (shell login)'),
            ),
            'php_webshell_family' => array(
                'prefilter' => array('regex' => '~\b(?:FilesMan|WSOsetcookie|WSOstripslashes|wso_version|b374k|c99shell|c99_buff_prepare|c99sh_|r57shell|IndoXploit|ALFA_DATA|AlfaTeam|Alfa_Shell|0byt3m1n1|Ani-Shell|AnonymousFox)\b~'),
                'triggers'  => array(
                    array('regex' => '~(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open|move_uploaded_file|file_put_contents)\s*\(~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'marker of a known web shell family (WSO/FilesMan, b374k, c99, r57, IndoXploit, Alfa, AnonymousFox)'),
            ),
            'php_image_header' => array(
                'prefilter' => array('regex' => '~\A(?:GIF8[79]a|\x89PNG\r\n|\xFF\xD8\xFF)~'),
                'triggers'  => array(
                    array('regex' => '~<\?php~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'PHP code behind an image header (disguised to pass upload checks)'),
            ),
            'php_escaped_include' => array(
                'prefilter' => array('regex' => '~(?:include|require)~i'),
                'triggers'  => array(
                    array('regex' => '~' . $inc . '\s*\(?\s*[\'"][^\'"]{0,20}?\\\\(?:x[0-9a-f]{2}|[0-7]{3})(?:[^\'"]{0,30}?\\\\(?:x[0-9a-f]{2}|[0-7]{3})){3,}~i'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'a file is included through a path written in escape codes (hidden loader)'),
            ),
            'php_wp_vcd' => array(
                'prefilter' => array('regex' => '~\b(?:wp_vcd|div_code_name|wp-vcd\.php)\b~'),
                'triggers'  => array(
                    array('regex' => '~\$tmpcontent|wp-tmp\.php|theme_temp_setup|class\.theme-modules\.php|\$wp_auth_key~'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'WP-VCD backdoor (spread through nulled themes and plugins)'),
            ),
            'javascript_ndsw_variant' => array(
                'prefilter' => array('regex' => '~rand\(\)\s*\+\s*rand\(\)~'),
                'triggers'  => array(
                    array('regex' => '~token\s*=\s*function\s*\(\s*\)\s*\{\s*return\s+rand\(\)\s*\+\s*rand\(\)\s*;?\s*\}~'),
                ),
                'action'    => array('detect' => 'HIGH', 'description' => 'NDSW/NDSJ script injection with renamed variables (the cleanup rule only knows the original names)'),
            ),
            'php_obfuscated_eval' => array(
                'prefilter' => array('regex' => '~(?:eval|assert)\s*\(~i'),
                'triggers'  => array(
                    array('regex' => '~' . $fn . '(?:eval|assert)\s*\(\s*(?:[\'"]\?>[\'"]\s*\.\s*)?(?:@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin|urldecode|rawurldecode)\s*\(\s*)+~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'decoded data is evaluated (eval of base64/gzinflate/rot13 output)'),
            ),
            'php_preg_replace_eval' => array(
                'prefilter' => array('string' => 'preg_replace'),
                'triggers'  => array(
                    // Old libraries (vBulletin 3, PEAR, Doctrine 1) shipped /e with
                    // replacements like "func('\\1')"; a shell's replacement holds
                    // request input, a decoder, an escaped payload or a junk blob.
                    array('regex' => '~preg_replace\s*\(\s*([\'"])([^\w\s\\\\])(?:(?!\1).){0,300}?\2[imsxuADSUXJ]*e[imsxuADSUXJ]*\1\s*,'
                        . '(?:(?=[^;]{0,200}?(?:' . $req . '|\b(?:eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|shell_exec|passthru|system)\b|\$_\s*\(|\$\{\s*\$|(?:\\\\x[0-9a-f]{2}\s*){4}|(?:\\\\[0-7]{2,3}){4}))'
                        . '|\s*[\'"][^\'"\\\\$]{80}|\s*@?\$' . $v . '{1,40}\s*,)~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'preg_replace with the /e modifier evaluates the replacement as PHP (removed in PHP 7; only old shells still use it)'),
            ),
            'php_encoded_blob' => array(
                'prefilter' => array('string' => 'base64_decode'),
                'triggers'  => array(
                    array('regex' => '~(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(\s*base64_decode\s*\(\s*[\'"][A-Za-z0-9+/=]{500,}~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'a large base64 blob is decompressed or unscrambled in code (packed payload)'),
            ),
            'php_scrambled_function_names' => array(
                'prefilter' => array('regex' => '~(?:strrev|str_rot13)~i'),
                'triggers'  => array(
                    array('regex' => '~[\'"](?:edoced_46esab|etalfnizg|sserpmocnuzg|edocedzg|tressa|metsys|cexe_llehs|urhtssap|noitcnuf_etaerc|lave|riny|onfr64_qrpbqr|tmvasyngr|tmhapbzcerff|flfgrz|nffreg|furyy_rkrp|cnffgueh|perngr_shapgvba)[\'"]~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'a dangerous function name is hidden reversed or rot13-encoded'),
            ),
            'php_escaped_function_name' => array(
                'prefilter' => array('string' => '\\'),
                'triggers'  => array(
                    // A name of six or more characters written entirely in
                    // escapes, starting with "_" or a lower-case letter
                    // (_REQUEST, base64_decode, fromCharCode), upper case
                    // with an underscore (HTTP_USER_AGENT), or any sixteen or
                    // more letters and digits. Short upper-case magic
                    // numbers ("\x47\x49\x46\x38\x37\x61" is GIF87a) and
                    // strings being compared are file formats, not names.
                    array('regex' => '~(?<!==)(?<!==\s)(?<!!=)(?<!!=\s)[\'"](?=(?:\\\\(?:x[0-9a-f]{2}|[0-7]{2,3})){6})'
                        . '(?:(?:' . $esc_lower . ')(?>' . $esc_name . ')++|(?>' . $esc_upper . ')(?>' . $esc_upper . '|' . $esc_digit . ')*+(?:\\\\x5f|\\\\137)(?>' . $esc_name . ')*+'
                        // Or any run of sixteen or more (an escaped key or blob).
                        . '|(?>' . $esc_name . '){16,}+)[\'"]~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'a name is written entirely in hex or octal escapes (hidden function name)'),
            ),
            'php_chr_chain' => array(
                'prefilter' => array('regex' => '~chr\s*\(~i'),
                'triggers'  => array(
                    // Printable characters only: libraries build binary byte
                    // tables this way (TCPDF, mPDF, transliteration maps).
                    array('regex' => '~(?:chr\s*+\(\s*+(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])\s*+\)\s*+\.\s*+){8}~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'a string is built from a long chain of chr() calls (hidden code)'),
            ),
            'php_globals_call' => array(
                'prefilter' => array('regex' => '~\$(?:GLOBALS|\{)~'),
                'triggers'  => array(
                    array('regex' => '~\$GLOBALS\s*\[\s*[\'"][^\'"]{1,40}[\'"]\s*\]\s*\[\s*\d{1,4}\s*\]\s*\(|\$\{\s*[\'"](?:\\\\x47|\\\\107)~'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'functions are called through an index into $GLOBALS (array obfuscator)'),
            ),
            'php_shell_console' => array(
                'prefilter' => array('regex' => '~uname\s+-a|\bwhoami\b|/etc/passwd|\bnetstat\s+-~'),
                'triggers'  => array(
                    array('regex' => '~(?<![\w>:$\\\\])(?:system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*["\']?\$\w{1,40}~i'),
                    array('regex' => '~' . $req . '~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'a command console: runs commands held in variables, reads request input and probes the server (uname, whoami, /etc/passwd)'),
            ),
            'php_tiny_dynamic_call' => array(
                // Under 800 bytes, no class, and no WordPress ABSPATH guard (a
                // plugin template is tiny once its licence comments are gone).
                'prefilter' => array('regex' => '~\A(?=[\s\S]{0,800}\z)(?![\s\S]{0,800}?(?:\b(?:class|trait|interface|namespace)\s|ABSPATH))[\s\S]{0,800}?<\?~i'),
                'triggers'  => array(
                    array('regex' => '~(?<![\w>:$\\\\])(?<!new\s)\$' . $v . '{1,40}\s*\(\s*@?\$(?:_(?:GET|POST|REQUEST|COOKIE|SERVER|SESSION)\s*\[|' . $v . '{1,40}\s*[\[)])~'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'a tiny PHP file (under 800 bytes, no class) that calls a variable as a function (one-line backdoor)'),
            ),
            'php_indexed_variable_call' => array(
                'prefilter' => array('regex' => '~\]\s*\(\s*\$~'),
                'triggers'  => array(
                    // Not inside a string: "$m[1]($m[2])" is interpolation.
                    array('regex' => '~(?<![\w>:$\\\\"])\$(' . $v . '{1,40})\s*\[\s*\d{1,2}\s*\]\s*\(\s*\$\1\s*\[\s*\d{1,2}\s*\]\s*\)~'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'an array calls one of its own entries with another ($x[0]($x[1]): unpacked payload)'),
            ),
            'php_eval_indexed' => array(
                'prefilter' => array('regex' => '~(?:eval|assert)\s*\(~i'),
                'triggers'  => array(
                    array('regex' => '~' . $fn . '(?:eval|assert)\s*\(\s*\$\w{1,40}\s*\[\s*\$\w{1,40}\s*\[~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'code looked up through nested array indexes is evaluated (obfuscated eval)'),
            ),
            'php_binary_identifiers' => array(
                'prefilter' => array('regex' => '~\$[\x80-\xff]{2}~'),
                'triggers'  => array(
                    array('regex' => '~(?:\$[a-z_]*[\x80-\xff][^=;]{0,40}=[^;]{0,200};[\s\S]{0,200}?){4,}~i'),
                    array('regex' => '~(?:eval|base64_decode|gzinflate|str_rot13|create_function)\s*\(~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'variables named with non-printable bytes next to a decoder (machine obfuscation)'),
            ),
            'php_include_image' => array(
                'prefilter' => array('regex' => '~(?:include|require)~i'),
                'triggers'  => array(
                    array('regex' => '~' . $inc . '\s*\(?[^;\n]{0,200}?\.(?:ico|png|jpe?g|gif|bmp|webp)\s*[\'"]\s*\)?\s*;~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'an image or icon file is included as PHP (payload hidden in a media file)'),
            ),
            'javascript_charcode_payload' => array(
                'prefilter' => array('string' => 'fromCharCode'),
                'triggers'  => array(
                    // String.fromCharCode, or the same through an alias (S[f](...)).
                    array('regex' => '~(?:fromCharCode|\])\s*+\(\s*+(?:\d{2,3}+\s*+,\s*+){40}~'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'a script is assembled from a long list of character codes (injected loader)'),
            ),
            'javascript_obfuscated_eval' => array(
                'prefilter' => array('string' => 'eval'),
                'triggers'  => array(
                    array('regex' => '~\beval\s*\(\s*(?:window\.)?(?:atob\s*\(|(?:unescape|decodeURIComponent)\s*\(\s*[\'"]%[0-9a-f]{2}%)~i'),
                ),
                'action'    => array('detect' => 'MEDIUM', 'description' => 'decoded data is evaluated in a script (eval of atob/unescape output)'),
            ),
        );
        return ($set);
    }

    ////////////////
    // The second look the detection set gets at a file nothing matched:
    // the cheap normalisation Manul, AMWScan and Shell Detector do before
    // matching. Block comments go (eval/**/(), letters, digits and path
    // characters written as \xNN or octal escapes are decoded, and string
    // fragments joined with "." are glued ('ev'.'al' becomes 'eval').
    // The result is only matched, never written anywhere; a failing regex
    // returns the input unchanged, so the second look is simply skipped.
    //////////////
    public static function normalize_code($buffer)
    {
        // Block comments, then line comments that start a line or follow
        // code punctuation ('php://input' and '#fff' inside strings stay;
        // PHP 8 attributes #[...] are not comments).
        $out = preg_replace(array('~/\*.{0,4096}?\*/~s', '~(?<=^|[\s;{}()])(?://|#(?!\[))[^\r\n]{0,4096}~m'), '', $buffer);
        if (null === $out) {
            return ($buffer);
        }
        $decoded = preg_replace_callback('~\\\\(?:x([0-9a-f]{2})|([0-7]{2,3}))~i', array(__CLASS__, 'decode_escape'), $out);
        if (null === $decoded) {
            return ($buffer);
        }
        $joined = preg_replace('~[\'"]\s*\.\s*[\'"]~', '', $decoded);
        if (null === $joined) {
            return ($buffer);
        }
        // $f = 'ev'; $f .= 'al'; becomes $f = 'eval'; (a bounded number of
        // rounds, each one gluing one append onto the assignment before it).
        for ($round = 0; $round < 16; $round++) {
            $glued = preg_replace('~(\$[\w\x80-\xff]{1,40})\s*=\s*([\'"])((?:(?!\2)[^\\\\]){0,400}+)\2\s*;\s*\1\s*\.=\s*\2~', '$1 = $2$3', $joined);
            if (null === $glued || $glued === $joined) {
                break;
            }
            $joined = $glued;
        }
        // ${"_POST"} (once the split string is joined) is $_POST.
        $named = preg_replace('~(\$)\{\s*[\'"](_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES))[\'"]\s*\}~', '$1$2', $joined);
        return ((null === $named) ? $buffer : $named);
    }

    public static function decode_escape($m)
    {
        $code = ('' !== $m[1]) ? hexdec($m[1]) : octdec($m[2]);
        // \400 to \777 are not bytes (PHP keeps the low eight bits; chr()
        // warns): leave them alone.
        if ($code > 255) {
            return ($m[0]);
        }
        $char = chr($code);
        // Only characters that spell names and paths: decoding a quote or a
        // control byte could only change the code's shape, never reveal it.
        return ((1 === preg_match('~^[A-Za-z0-9_./:-]$~', $char)) ? $char : $m[0]);
    }

    // Crontab persistence patterns: name => pattern pairs.
    public static function crontab()
    {
        return array(
            array( 'crontab.tmp.001' => '@\* \* (\/var)?\/tmp\/@'),
            array( 'crontab.tmp.002' => '@php -q [^\.]+\/\.cron@'),
            array( 'crontab.tmp.003' => '@wget\shttp[^-]*\.txt\s*\-O\s\/wp-\w+\/[^>]*\>\/dev\/null;\sfetch\s-o\s\/wp-\w+[^\>]*\.txt\s\>.dev.null\s*2>\&1;\stouch\s-t\s\d+\s\/wp-\w+[^;]*null;\schmod\s0755[^;]*null;\srm\s-f\s+[^;]*null;\stouch\s-t\s\d+\s[^>]*\>.dev.null@'),
            array( 'crontab.tmp.004' => '@&& chmod 0755 xxxd@'),
            array( 'crontab.tmp.004.02' => '@(wget|curl) .+&& \/bin\/sh \w{4,} \/[^&]+&& rm -f \w@'),
            array( 'crontab.tmp.005' => '@.php && chmod +x /@'),
            array( 'crontab.tmp.006' => '@\|\s*base64 --decode\s*>@'),
            array( 'crontab.tmp.007' => '@\.file_get_contents\(.https:\/\/bit.ly\/\w@'),
            array( 'crontab.tmp.008' => '@\|base64 -d\|gunzip -c\)@'),
            array( 'crontab.tmp.009' => '@https:\/\/pastebin.com\/raw@'),
            array( 'crontab.tmp.010' => '@eval.gzinflate.base64_decode@'),
        );
    }

    ///////////////
    // Access log IoC signatures.
    // Each signature matches one line of a common/combined format access log.
    // "threshold" hides findings until that many hits are seen: a single POST to
    // wp-login.php is normal traffic, five hundred of them is a brute force.
    // Findings report as MEDIUM (attack attempts) unless the signature sets
    // "severity" - traffic to a shell already on disk is HIGH.
    //////////////
    public static function access_log()
    {
        return array(
            array(
                'name'        => 'access.uploads.php',
                'pattern'     => '@"(?:GET|POST|HEAD) /[^"\s]*wp-content/uploads/[^"\s]*\.ph(?:p[34578]?|tml|ps|t)\b@i',
                'threshold'   => 1,
                'severity'    => 'HIGH',
                'description' => 'PHP file requested inside wp-content/uploads. Uploads should never contain executable PHP; this is usually a webshell dropped through an upload form.',
            ),
            array(
                'name'        => 'access.webshell.names',
                'pattern'     => '@"(?:GET|POST|HEAD) /[^"\s]*(?:wso\d*|filesman|alfa(?:-rex|_data)?|b374k|c99(?:shell)?|r57|indoxploit|mini_?shell|webshell|priv8)[^"\s]*\.ph@i',
                'threshold'   => 1,
                'severity'    => 'HIGH',
                'description' => 'Request to a well-known webshell filename (WSO, FilesMan, AlfaShell, c99, r57, ...).',
            ),
            array(
                'name'        => 'access.adminer',
                'pattern'     => '@"(?:GET|POST) /[^"\s]*adminer[^"\s]*\.php@i',
                'threshold'   => 1,
                'description' => 'Request to an Adminer database client. Attackers drop it to reuse the credentials from wp-config.php against the database.',
            ),
            array(
                'name'        => 'access.wp-file-manager.rce',
                'pattern'     => '@wp-file-manager/lib/php/connector\.minimal\.php@i',
                'threshold'   => 1,
                'description' => 'Request to wp-file-manager connector.minimal.php, exploited for unauthenticated file upload (CVE-2020-25213).',
            ),
            array(
                'name'        => 'access.revslider',
                'pattern'     => '@admin-ajax\.php\?[^"\s]*action=revslider@i',
                'threshold'   => 1,
                'description' => 'Slider Revolution admin-ajax action, exploited for arbitrary file download/upload in old plugin versions.',
            ),
            array(
                'name'        => 'access.timthumb',
                'pattern'     => '@timthumb\.php\?[^"\s]*src=https?@i',
                'threshold'   => 1,
                'description' => 'TimThumb remote-source request, exploited for remote file inclusion in old theme bundles.',
            ),
            array(
                'name'        => 'access.setup-config',
                'pattern'     => '@"(?:GET|POST) /[^"\s]*wp-admin/(?:setup-config|install)\.php@i',
                'threshold'   => 1,
                'description' => 'Access to the WordPress installer/setup-config, used to take over half-finished or broken installs.',
            ),
            array(
                'name'        => 'access.env.probe',
                'pattern'     => '@"(?:GET|POST) /[^"\s]*\.env(?:\.\w+)?["\s]@i',
                'threshold'   => 1,
                'description' => 'Probe for a .env file, hunting for exposed credentials.',
            ),
            array(
                'name'        => 'access.traversal',
                'pattern'     => '@"(?:GET|POST|HEAD) /[^"]*\.\./\.\./@',
                'threshold'   => 1,
                'description' => 'Directory traversal attempt (../../) in the request path or query string.',
            ),
            array(
                'name'        => 'access.query.code-injection',
                'pattern'     => '@"(?:GET|POST) /[^"]*(?:eval\(|base64_decode|gzinflate|call_user_func|assert\()@i',
                'threshold'   => 1,
                'description' => 'PHP code passed in the request, a code injection attempt against a vulnerable plugin or theme.',
            ),
            array(
                'name'        => 'access.query.php-ini-injection',
                'pattern'     => '@(?:auto_prepend_file|allow_url_include|disable_functions)=@i',
                'threshold'   => 1,
                'description' => 'php.ini directives in the query string, a PHP-CGI argument injection attempt (CVE-2012-1823 / CVE-2024-4577).',
            ),
            array(
                'name'        => 'access.user.enumeration',
                'pattern'     => '@"GET /[^"\s]*(?:wp-json/wp/v2/users|\?author=\d)@i',
                'threshold'   => 10,
                'description' => 'Username enumeration through the REST API or ?author= redirects, usually reconnaissance before a brute force.',
            ),
            array(
                'name'        => 'access.xmlrpc.flood',
                'pattern'     => '@"POST /[^"\s]*xmlrpc\.php@i',
                'threshold'   => 50,
                'description' => 'High volume of xmlrpc.php POSTs, typically credential brute forcing via system.multicall or pingback abuse.',
            ),
            array(
                'name'        => 'access.wp-login.bruteforce',
                'pattern'     => '@"POST /[^"\s]*wp-login\.php@i',
                'threshold'   => 50,
                'description' => 'High volume of wp-login.php POSTs, a login brute force.',
            ),
        );
    }

    // Patterns matched against option values (first 256KB of each).
    public static function builtin_db_options()
    {
        return array(
            array(
                'name'        => 'db.option.php-exec',
                'pattern'     => '@(?:eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|assert\s*\(|create_function\s*\()@i',
                'severity'    => 'HIGH',
                'description' => 'PHP execution/decoding functions inside an option value - options should hold settings, never code',
            ),
            array(
                'name'        => 'db.option.php-tag',
                'pattern'     => '@<\?php@i',
                'severity'    => 'HIGH',
                'description' => 'PHP tag inside an option value',
            ),
            array(
                'name'        => 'db.option.hidden-iframe',
                'pattern'     => '@<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width=["\']?0["\']?[\s>]|height=["\']?0["\']?[\s>])@i',
                'severity'    => 'HIGH',
                'description' => 'Hidden iframe inside an option value - a classic drive-by injection',
            ),
            array(
                'name'        => 'db.option.js-obfuscation',
                'pattern'     => '@(?:String\.fromCharCode\s*\(|atob\s*\(|unescape\s*\(\s*[\'"]%)@i',
                'severity'    => 'MEDIUM',
                'description' => 'Obfuscated JavaScript inside an option value',
            ),
            array(
                'name'        => 'db.option.script-src',
                'pattern'     => '@<script[^>]+src\s*=@i',
                'severity'    => 'MEDIUM',
                'description' => 'Remote script tag inside an option value - theme/plugin settings can legitimately hold analytics snippets, verify the source',
            ),
        );
    }

    // Patterns matched against post content (candidates come from a
    // server-side LIKE prefilter).
    public static function builtin_db_posts()
    {
        return array(
            array(
                'name'        => 'db.post.php-tag',
                'pattern'     => '@<\?php@i',
                'severity'    => 'HIGH',
                'description' => 'PHP tag inside post content - WordPress never stores executable PHP in posts',
            ),
            array(
                'name'        => 'db.post.hidden-iframe',
                'pattern'     => '@<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden)@i',
                'severity'    => 'HIGH',
                'description' => 'Hidden iframe inside post content',
            ),
            array(
                'name'        => 'db.post.js-obfuscation',
                'pattern'     => '@(?:String\.fromCharCode\s*\(|atob\s*\(|unescape\s*\(\s*[\'"]%|eval\s*\()@i',
                'severity'    => 'MEDIUM',
                'description' => 'Obfuscated JavaScript inside post content',
            ),
        );
    }

    ///////////////
    // Extra files that are commonly legitimate, keyed by basename. They still
    // report (an attacker can hide behind a known name) but as INFO with the
    // reason, so HIGH/MEDIUM triage stays clean.
    //////////////
    public static function known_benign()
    {
        return array(
            'error_log'         => 'PHP error log created by the hosting stack - not malware, but worth reading for attack traces',
            'php_errorlog'      => 'PHP error log created by the hosting stack - not malware, but worth reading for attack traces',
            'wordfence-waf.php' => 'Wordfence extended protection bootstrap (auto_prepend_file) - verify it only loads wordfence/waf/bootstrap.php',
        );
    }

    // Extensions the signature scanner (and the correlate walk) look at
    // unless allfiles=1 widens the scan to everything.
    public static function extensions()
    {
        return array(
            'asa', 'asp', 'aspx', 'cfm', 'cgi', 'cin', 'conf', 'cron', 'css', 'ejl',
            'htm', 'html', 'inc', 'izo', 'js', 'local', 'mod', 'php', 'php3', 'php4',
            'php5', 'php7', 'php8', 'phps', 'pht', 'phtml', 'pl', 'py', 'sct', 'sh',
            'shtml', 'tmpl', 'tpl',
        );
    }

    ///////////////
    // A malformed signature would otherwise silently never match. Stop the
    // run and name the broken signature instead.
    //////////////
    public static function lint()
    {
        foreach (self::cleanup() as $name => $signature) {
            if (!isset($signature['prefilter'], $signature['triggers'], $signature['action']) || !is_array($signature['prefilter'])) {
                throw new Fatal('invalid cleanup signature ' . $name . ': prefilter, triggers and action are required');
            }
            if (isset($signature['action']['detect']) && (!in_array($signature['action']['detect'], array('HIGH', 'MEDIUM', 'LOW'), true) || !isset($signature['action']['description']))) {
                throw new Fatal('invalid detection signature ' . $name . ': detect needs HIGH, MEDIUM or LOW and a description');
            }

            $conditions = array_merge(array($signature['prefilter'], $signature['action']), $signature['triggers']);
            foreach ($conditions as $condition) {
                $pattern = null;
                if (isset($condition['regex'])) {
                    $pattern = $condition['regex'];
                } elseif (isset($condition['remove_regex'])) {
                    $pattern = $condition['remove_regex'];
                }
                if (null !== $pattern && false === @preg_match($pattern, '')) {
                    throw new Fatal('invalid regex in cleanup signature ' . $name . ': ' . $pattern);
                }
                if (isset($condition['start']) && (!isset($condition['remove_regex']) || !is_string($condition['start']) || false === @preg_match($condition['start'], '') || 1 === @preg_match($condition['start'], ''))) {
                    throw new Fatal('invalid cleanup signature ' . $name . ': start needs remove_regex and a regex that does not match the empty string');
                }
                if (isset($condition['absent']) && (!is_array($condition['absent']) || array() === $condition['absent'] || in_array('', $condition['absent'], true))) {
                    throw new Fatal('invalid cleanup signature ' . $name . ': absent needs a list of non-empty strings');
                }
            }
        }

        foreach (self::crontab() as $item) {
            foreach ($item as $name => $pattern) {
                if (false === @preg_match($pattern, '')) {
                    throw new Fatal('invalid regex in crontab signature ' . $name . ': ' . $pattern);
                }
            }
        }

        foreach (self::access_log() as $signature) {
            if (false === @preg_match($signature['pattern'], '')) {
                throw new Fatal('invalid regex in access log signature ' . $signature['name'] . ': ' . $signature['pattern']);
            }
        }

        foreach (array_merge(self::db_options(), self::db_posts()) as $signature) {
            if (!isset($signature['name'], $signature['pattern'], $signature['severity']) || false === @preg_match($signature['pattern'], '')) {
                throw new Fatal('invalid regex in database signature ' . $signature['name'] . ': ' . $signature['pattern']);
            }
        }
    }
}
