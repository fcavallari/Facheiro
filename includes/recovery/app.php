<?php
////////////////
// Elderward recovery mode: the key-protected page that scans the site
// without WordPress (entry point: recovery.php in the plugin folder).
//
// Rules this file keeps:
// - Inert without a valid, unexpired key file next to the plugins folder:
//   404 and nothing else. The engine is only loaded after sign-in.
// - Report-only: files and the database are read, never written. Its only
//   writes are its own state (job, sign-in attempts) in a private folder.
// - Everything shown comes from a possibly compromised site: escape it all.
// - PHP 5.6 syntax, like the engine: a broken site may run old PHP.
//////////////

namespace Elderward\Recovery;

use Elderward\Engine\BaseReporter;
use Elderward\Engine\Context;
use Elderward\Engine\CurlHttp;
use Elderward\Engine\Fatal;
use Elderward\Engine\MysqliDb;
use Elderward\Engine\Runner;
use Elderward\Engine\Scanner;
use Elderward\Engine\Signatures;

if (!defined('ELDERWARD_RECOVERY_ENTRY')) {
    exit;
}

final class App
{
    const KEY_FILE = 'elderward-recovery-key.php';
    const GUARD = '<?php exit; ?>';
    const MIN_KEY = 24;
    const SESSION_TTL = 3600;
    const MAX_FAILS = 10;
    // A unit started this many times without finishing (PHP died while
    // running it) stops the scan instead of looping forever.
    const MAX_ATTEMPTS = 3;
    const LOCK_SECONDS = 900;
    // Clients tracked in the attempts file at most: behind a proxy the
    // forwarded address can be spoofed, and the file must not grow with
    // every request an attacker sends.
    const MAX_CLIENTS = 500;
    const MAX_FINDINGS = 5000;
    const COOKIE = 'elderward_recovery';

    private static $plugin_dir;
    private static $content_dir;
    private static $root;
    private static $key;
    private static $state_dir;
    private static $nonce;
    private static $lang = 'en';
    private static $strings = array();

    public static function run($plugin_dir)
    {
        self::$nonce = bin2hex(self::random(16));
        self::headers();

        $script = isset($_SERVER['SCRIPT_FILENAME']) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
        // Paths as the web server sees them (not symlink-resolved), so they
        // match the plugin's own idea of where wp-content is.
        self::$plugin_dir = '' !== $script ? dirname($script) : $plugin_dir;
        self::$content_dir = dirname(dirname(self::$plugin_dir));

        self::$key = self::load_key(self::$content_dir);
        if (null === self::$key) {
            self::not_found();
        }
        self::$root = self::find_root(self::$content_dir);
        self::$state_dir = self::state_dir();
        self::pick_language();

        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : 'GET';
        $do = isset($_POST['do']) ? (string) $_POST['do'] : '';

        if ('POST' === $method && 'login' === $do) {
            self::login();
            return;
        }
        $session = self::session();
        if (null === $session) {
            self::page_login('');
            return;
        }
        if ('POST' === $method) {
            if (!isset($_POST['token']) || !hash_equals(self::csrf($session), (string) $_POST['token'])) {
                self::json(array('ok' => false, 'message' => self::t('Your session expired. Reload the page.')), 403);
            }
            switch ($do) {
                case 'logout':
                    self::set_cookie('', time() - 3600);
                    header('Location: ' . self::self_url(), true, 303);
                    exit;
                case 'start':
                    self::json(self::start());
                    break;
                case 'step':
                    self::json(self::step());
                    break;
                case 'cancel':
                    self::json(self::cancel());
                    break;
            }
            self::json(array('ok' => false, 'message' => self::t('Unknown action.')), 400);
        }
        if (isset($_GET['export'])) {
            self::export();
        }
        self::page_main($session);
    }

    ////////////////
    // Language: English or Brazilian Portuguese, from the switch in the
    // header (remembered in a cookie) or the browser's preferred language.
    // WordPress's translations cannot be used: WordPress is not loaded.
    //////////////

    const LANG_COOKIE = 'elderward_recovery_lang';

    private static function pick_language()
    {
        $languages = array('en', 'pt_BR');
        if (isset($_GET['lang']) && in_array($_GET['lang'], $languages, true)) {
            $chosen = (string) $_GET['lang'];
            header('Set-Cookie: ' . self::LANG_COOKIE . '=' . $chosen . '; Expires=' . gmdate('D, d M Y H:i:s', time() + 31536000) . ' GMT; Path=' . self::cookie_path() . '; HttpOnly; SameSite=Lax' . (self::https() ? '; Secure' : ''), false);
            header('Location: ' . self::self_url(), true, 303);
            exit;
        }
        if (isset($_COOKIE[self::LANG_COOKIE]) && in_array($_COOKIE[self::LANG_COOKIE], $languages, true)) {
            self::$lang = (string) $_COOKIE[self::LANG_COOKIE];
        } else {
            $accept = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? strtolower((string) $_SERVER['HTTP_ACCEPT_LANGUAGE']) : '';
            foreach (explode(',', $accept) as $item) {
                $tag = trim((string) strtok($item, ';'));
                if (0 === strpos($tag, 'pt')) {
                    self::$lang = 'pt_BR';
                    break;
                }
                if (0 === strpos($tag, 'en')) {
                    break;
                }
            }
        }
        if ('en' !== self::$lang) {
            $file = __DIR__ . '/i18n/' . self::$lang . '.php';
            $strings = is_file($file) ? include $file : array();
            self::$strings = is_array($strings) ? $strings : array();
        }
    }

    /**
     * The text in the page's language (the English text when there is no
     * translation). Extra arguments fill placeholders like sprintf(); they
     * are not escaped here.
     */
    private static function t(/* $text, ...$args */)
    {
        $args = func_get_args();
        $text = (string) array_shift($args);
        $out = isset(self::$strings[$text]) ? self::$strings[$text] : $text;
        return empty($args) ? $out : vsprintf($out, $args);
    }

    /**
     * Escaped translation.
     */
    private static function e(/* $text, ...$args */)
    {
        return self::h(call_user_func_array(array(__CLASS__, 't'), func_get_args()));
    }

    ////////////////
    // Key, sessions, rate limiting.
    //////////////

    private static function random($bytes)
    {
        if (function_exists('random_bytes')) {
            return random_bytes($bytes);
        }
        return openssl_random_pseudo_bytes($bytes);
    }

    /**
     * The key file's hash and lifetime, or null when recovery is off.
     */
    private static function load_key($content_dir)
    {
        $file = $content_dir . '/' . self::KEY_FILE;
        if (!is_file($file) || !is_readable($file) || filesize($file) > 4096) {
            return null;
        }
        $raw = (string) file_get_contents($file); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- no WordPress here; the key file, at most 4 KB.
        $json = trim(preg_replace('/^\s*<\?php.*?\?>/s', '', $raw, 1));
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return null;
        }
        if (isset($data['key']) && is_string($data['key']) && strlen($data['key']) >= self::MIN_KEY) {
            $hash = hash('sha256', $data['key']);
            $manual = true;
        } elseif (isset($data['hash']) && is_string($data['hash']) && 1 === preg_match('/^[0-9a-f]{64}$/', $data['hash'])) {
            $hash = $data['hash'];
            $manual = false;
        } else {
            return null;
        }
        $expires = isset($data['expires']) ? (int) $data['expires'] : 0;
        if (0 !== $expires && $expires <= time()) {
            return null;
        }
        $created = isset($data['created']) ? (int) $data['created'] : (int) filemtime($file);
        return array(
            'hash'    => $hash,
            'manual'  => $manual,
            'expires' => $expires,
            // Sessions are signed with this: replacing or revoking the key
            // ends every session.
            'secret'  => hash('sha256', 'elderward-recovery-session|' . $hash . '|' . $created),
        );
    }

    /**
     * Who is signing in, for the lockout of hand-written keys. Behind a
     * proxy or CDN every visitor arrives from the proxy's private address,
     * so the forwarded client address is used then (it can be spoofed,
     * which only lets an attacker spread guesses, not lock others out).
     */
    private static function client_id()
    {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : 'unknown';
        $public = false !== filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        if (!$public) {
            foreach (array('HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR') as $header) {
                if (!empty($_SERVER[$header])) {
                    $first = trim(strtok((string) $_SERVER[$header], ','));
                    if (false !== filter_var($first, FILTER_VALIDATE_IP)) {
                        $ip = $first;
                        break;
                    }
                }
            }
        }
        return substr(hash('sha256', $ip . '|' . self::$key['secret']), 0, 16);
    }

    /**
     * A generated key is 32 random characters (~190 bits): guessing it is
     * hopeless, so a wrong key is simply refused. It neither locks anyone
     * out (a lockout would let anyone block the owner) nor sleeps (a delay
     * would let anyone tie up the site's PHP workers from this page while
     * adding nothing against a key that size). A hand-written key may be
     * weaker, so it gets a per-client lockout and a one-second delay.
     */
    private static function login()
    {
        $attempts = self::read_state('attempts');
        $id = self::client_id();
        $now = time();
        $mine = isset($attempts[$id]) ? $attempts[$id] : array('fails' => 0, 'since' => $now);
        if ($now - (int) $mine['since'] > self::LOCK_SECONDS) {
            $mine = array('fails' => 0, 'since' => $now);
        }
        if (self::$key['manual'] && (int) $mine['fails'] >= self::MAX_FAILS) {
            http_response_code(429);
            self::page_login(self::t('Too many wrong keys. Try again in 15 minutes.'));
            return;
        }
        $given = isset($_POST['key']) ? trim((string) $_POST['key']) : '';
        if ('' !== $given && hash_equals(self::$key['hash'], hash('sha256', $given))) {
            unset($attempts[$id]);
            self::write_state('attempts', $attempts);
            self::set_cookie(self::sign(array('exp' => $now + self::SESSION_TTL, 'n' => bin2hex(self::random(8)))), $now + self::SESSION_TTL);
            header('Location: ' . self::self_url(), true, 303);
            exit;
        }
        if (!self::$key['manual']) {
            http_response_code(403);
            self::page_login(self::t('That key is not valid.'));
            return;
        }
        $mine['fails'] = (int) $mine['fails'] + 1;
        $attempts[$id] = $mine;
        // Keep the file small: forget clients idle for a while, and never
        // track more than MAX_CLIENTS (the oldest go first).
        foreach ($attempts as $client => $entry) {
            if ($now - (int) $entry['since'] > self::LOCK_SECONDS) {
                unset($attempts[$client]);
            }
        }
        if (count($attempts) > self::MAX_CLIENTS) {
            uasort($attempts, function ($a, $b) {
                return (int) $b['since'] - (int) $a['since'];
            });
            $attempts = array_slice($attempts, 0, self::MAX_CLIENTS, true);
        }
        self::write_state('attempts', $attempts);
        sleep(1);
        http_response_code(403);
        self::page_login(self::t('That key is not valid.'));
    }

    private static function sign(array $payload)
    {
        $data = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '='); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress here; session payload.
        return $data . '.' . hash_hmac('sha256', $data, self::$key['secret']);
    }

    private static function session()
    {
        if (!isset($_COOKIE[self::COOKIE])) {
            return null;
        }
        $parts = explode('.', (string) $_COOKIE[self::COOKIE]);
        if (2 !== count($parts) || !hash_equals(hash_hmac('sha256', $parts[0], self::$key['secret']), $parts[1])) {
            return null;
        }
        $payload = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
        if (!is_array($payload) || !isset($payload['exp']) || (int) $payload['exp'] < time()) {
            return null;
        }
        $payload['raw'] = $parts[0];
        return $payload;
    }

    private static function csrf(array $session)
    {
        return hash_hmac('sha256', 'csrf|' . $session['raw'], self::$key['secret']);
    }

    private static function https()
    {
        if (isset($_SERVER['HTTPS']) && '' !== $_SERVER['HTTPS'] && 'off' !== strtolower($_SERVER['HTTPS'])) {
            return true;
        }
        return isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && 'https' === strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']);
    }

    private static function cookie_path()
    {
        $name = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '/';
        $dir = rtrim(str_replace('\\', '/', dirname($name)), '/');
        return $dir . '/';
    }

    private static function set_cookie($value, $expires)
    {
        $cookie = self::COOKIE . '=' . $value
            . '; Expires=' . gmdate('D, d M Y H:i:s', $expires) . ' GMT'
            . '; Path=' . self::cookie_path()
            . '; HttpOnly; SameSite=Strict'
            . (self::https() ? '; Secure' : '');
        header('Set-Cookie: ' . $cookie, false);
    }

    private static function self_url()
    {
        $name = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : 'recovery.php';
        return basename($name);
    }

    ////////////////
    // Private state: the scan job and sign-in attempts.
    //////////////

    private static function state_dir()
    {
        $tag = substr(hash('sha256', (string) self::$root), 0, 16);
        $candidates = array(
            rtrim(sys_get_temp_dir(), '/\\') . '/elderward-recovery-' . $tag,
            self::$content_dir . '/elderward-recovery',
        );
        foreach ($candidates as $dir) {
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- no WordPress here; failure is handled by the checks below.
            }
            if (self::private_dir($dir)) {
                if (0 === strpos($dir, self::$content_dir)) {
                    // Inside the web root: deny web access wherever the
                    // server honours it; every state file is exit-guarded.
                    self::protect_dir($dir);
                }
                return $dir;
            }
        }
        return null;
    }

    /**
     * Only a folder this PHP user owns and nobody else can enter: on hosts
     * that share the system temp folder, another account could otherwise
     * create it first and plant a job or attempts file.
     */
    private static function private_dir($dir)
    {
        clearstatcache(true, $dir);
        if (!is_dir($dir) || is_link($dir) || !is_writable($dir)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- no WordPress here.
            return false;
        }
        $me = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();
        if (fileowner($dir) !== $me) {
            return false;
        }
        return 0 === (fileperms($dir) & 0077);
    }

    private static function protect_dir($dir)
    {
        $files = array(
            '.htaccess'  => "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n",
            'index.php'  => "<?php\n// Silence is golden.\n",
            'web.config' => "<?xml version=\"1.0\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
        );
        foreach ($files as $name => $content) {
            if (!is_file($dir . '/' . $name)) {
                @file_put_contents($dir . '/' . $name, $content); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- no WordPress here; deny files for its own state folder, best effort (state files are exit-guarded anyway).
            }
        }
    }

    private static function read_state($name)
    {
        if (null === self::$state_dir) {
            return array();
        }
        $file = self::$state_dir . '/' . $name . '.php';
        if (!is_file($file)) {
            return array();
        }
        $raw = (string) @file_get_contents($file); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- no WordPress here; its own state file.
        $data = json_decode((string) substr($raw, strlen(self::GUARD) + 1), true);
        return is_array($data) ? $data : array();
    }

    private static function write_state($name, array $data)
    {
        if (null === self::$state_dir) {
            return false;
        }
        $file = self::$state_dir . '/' . $name . '.php';
        $tmp = $file . '.' . bin2hex(self::random(4)) . '.tmp';
        if (false === @file_put_contents($tmp, self::GUARD . "\n" . json_encode($data), LOCK_EX)) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress here; its own exit-guarded state file, written to a temp name and renamed; failure is returned.
            return false;
        }
        return @rename($tmp, $file); // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- atomic replace of its own state file.
    }

    ////////////////
    // Site discovery and the "what broke" report.
    //////////////

    private static function find_root($content_dir)
    {
        $dir = $content_dir;
        for ($i = 0; $i < 3; $i++) {
            $dir = dirname($dir);
            if (is_file($dir . '/wp-includes/version.php') || is_file($dir . '/wp-settings.php')) {
                return $dir;
            }
        }
        return dirname($content_dir);
    }

    private static function wp_version()
    {
        $file = self::$root . '/wp-includes/version.php';
        $content = is_file($file) ? (string) @file_get_contents($file, false, null, 0, 8192) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- no WordPress here; wp-includes/version.php, read (never run), first 8 KB.
        return preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m) ? $m[1] : null;
    }

    /**
     * Error log files that may explain the outage.
     */
    private static function error_logs()
    {
        $candidates = array(
            self::$content_dir . '/debug.log',
            self::$root . '/error_log',
            self::$root . '/php_errorlog',
            self::$root . '/wp-admin/error_log',
            self::$content_dir . '/error_log',
        );
        $ini = (string) ini_get('error_log');
        if ('' !== $ini && '/' === $ini[0]) {
            $candidates[] = $ini;
        }
        $out = array();
        foreach (array_unique($candidates) as $file) {
            if (is_file($file) && is_readable($file)) {
                $out[] = $file;
            }
        }
        return $out;
    }

    /**
     * The latest fatal errors from the logs, and which plugins/themes they
     * point at.
     */
    private static function recent_errors()
    {
        $lines = array();
        $suspects = array();
        foreach (self::error_logs() as $file) {
            $size = (int) filesize($file);
            $handle = @fopen($file, 'rb'); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- no WordPress here; reads the tail of a PHP error log.
            if (false === $handle) {
                continue;
            }
            $read = min($size, 262144);
            fseek($handle, $size - $read);
            $chunk = (string) fread($handle, $read); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- see above; at most 256 KB.
            fclose($handle); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- see above.
            foreach (explode("\n", $chunk) as $line) {
                if (1 === preg_match('/PHP (?:Fatal error|Parse error)|Uncaught |Allowed memory size/i', $line)) {
                    $lines[] = array('file' => $file, 'line' => substr(trim($line), 0, 600), 'mtime' => filemtime($file));
                    if (preg_match_all('#wp-content/(plugins|themes|mu-plugins)/([^/\s:]+)#', $line, $m, PREG_SET_ORDER)) {
                        foreach ($m as $match) {
                            $name = $match[1] . '/' . $match[2];
                            $suspects[$name] = isset($suspects[$name]) ? $suspects[$name] + 1 : 1;
                        }
                    }
                }
            }
        }
        arsort($suspects);
        return array('lines' => array_slice($lines, -15), 'suspects' => $suspects, 'logs' => self::error_logs());
    }

    ////////////////
    // The scan: the plugin's scanall, stepped in short requests.
    //////////////

    private static function load_engine()
    {
        if (!defined('ELDERWARD_RECOVERY')) {
            define('ELDERWARD_RECOVERY', true);
        }
        require_once self::$plugin_dir . '/includes/engine/load.php';
        if (!class_exists('Elderward\\Recovery\\CollectReporter')) {
            require_once __DIR__ . '/reporter.php';
        }
    }

    private static function work_dir()
    {
        if (null === self::$state_dir) {
            return null;
        }
        $dir = self::$state_dir . '/work';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- no WordPress here; the engine work folder inside its private state folder.
        }
        return $dir;
    }

    private static function context(array $options, $reporter)
    {
        return new Context($options, $reporter, new CurlHttp(), new MysqliDb(), self::$plugin_dir, self::work_dir());
    }

    /**
     * The options a recovery scan runs with, whatever the state file says:
     * always the report-only scanall of this site (scanall_context() adds
     * dryrun and drops restore), plus a log path that still resolves.
     */
    private static function scan_options(array $stored)
    {
        $options = array('scanall' => 1, 'scandirectory' => self::$root);
        if (isset($stored['scanlog'])) {
            $real = realpath((string) $stored['scanlog']);
            if (false !== $real && is_readable($real)) {
                $options['scanlog'] = $real;
            }
        }
        return $options;
    }

    /**
     * The job lock: steps take it without waiting (another step is
     * running), start and cancel wait for the running step to finish so it
     * cannot write its stale copy over theirs.
     */
    private static function lock($wait)
    {
        if (null === self::$state_dir) {
            return null;
        }
        $handle = @fopen(self::$state_dir . '/job.lock', 'c'); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- no WordPress here; a lock file in the private state folder.
        if (false === $handle) {
            return null;
        }
        if (!flock($handle, $wait ? LOCK_EX : LOCK_EX | LOCK_NB)) {
            fclose($handle); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- see above.
            return null;
        }
        return $handle;
    }

    private static function unlock($handle)
    {
        flock($handle, LOCK_UN);
        fclose($handle); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- see lock().
    }

    private static function start()
    {
        if (null === self::$state_dir) {
            return array('ok' => false, 'message' => self::t('No writable folder for the scan state (neither the system temp folder nor wp-content).'));
        }
        self::load_engine();
        $options = array('scanall' => 1, 'scandirectory' => self::$root);
        $log = isset($_POST['log']) ? trim((string) $_POST['log']) : '';
        if ('' !== $log) {
            $real = realpath($log);
            if (false === $real || !is_readable($real)) {
                return array('ok' => false, 'message' => self::t('The access log path does not exist or PHP cannot read it.'));
            }
            $options['scanlog'] = $real;
        }
        $reporter = new CollectReporter(array());
        try {
            Signatures::lint();
            $ctx = Runner::scanall_context(self::context($options, $reporter));
        } catch (Fatal $e) {
            return array('ok' => false, 'message' => $e->getMessage());
        }
        $lock = self::lock(true);
        if (null === $lock) {
            return array('ok' => false, 'message' => self::t('Could not lock the scan state.'));
        }
        $current = self::read_state('job');
        if (!empty($current) && 'running' === $current['status']) {
            self::unlock($lock);
            return array('ok' => false, 'message' => self::t('A scan is already running. Cancel it first.'));
        }
        $job = array(
            'status'      => 'running',
            'options'     => self::scan_options($ctx->options),
            'stages'      => Runner::scanall_stages($ctx),
            'stage_index' => 0,
            'queue'       => null,
            'state'       => array(),
            'states'      => array(),
            'findings'    => array(),
            'counts'      => array(),
            'dropped'     => 0,
            'units'       => 0,
            'started'     => time(),
            'finished'    => null,
            'message'     => '',
            'error'       => '',
            'attempt'     => array('key' => '', 'count' => 0),
        );
        self::write_state('job', $job);
        self::unlock($lock);
        return self::status_payload($job);
    }

    private static function budget()
    {
        $max = (int) ini_get('max_execution_time');
        $budget = 10.0;
        if ($max > 0) {
            $budget = min($budget, max(2.0, $max * 0.5));
        }
        return $budget;
    }

    private static function step()
    {
        $job = self::read_state('job');
        if (empty($job) || 'running' !== $job['status']) {
            return self::status_payload($job);
        }
        $lock = self::lock(false);
        if (null === $lock) {
            // Another request is running a step.
            return self::status_payload($job);
        }
        $job = self::read_state('job');
        if (empty($job) || 'running' !== $job['status']) {
            self::unlock($lock);
            return self::status_payload($job);
        }
        self::load_engine();
        @set_time_limit(60); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- may be disabled by the host; the step budget stays within the default limit anyway.
        $deadline = microtime(true) + self::budget();
        $reporter = new CollectReporter(isset($job['counts']) ? (array) $job['counts'] : array());
        try {
            // Never trust the stored options: rebuild them, so a state file
            // that was tampered with cannot turn the scan into a cleanup.
            $ctx = Runner::scanall_context(self::context(self::scan_options(isset($job['options']) ? (array) $job['options'] : array()), $reporter));
            if (!isset($job['stages']) || $job['stages'] !== Runner::scanall_stages($ctx)) {
                throw new Fatal(self::t('The saved scan state does not match this site; start a new scan.'));
            }
            if (!isset($job['attempt']) || !is_array($job['attempt'])) {
                $job['attempt'] = array('key' => '', 'count' => 0);
            }
            while (microtime(true) < $deadline) {
                if ($job['stage_index'] >= count($job['stages'])) {
                    $job['status'] = 'done';
                    $job['finished'] = time();
                    $job['message'] = '';
                    break;
                }
                $stage = $job['stages'][$job['stage_index']];
                $ctx->deadline = $deadline;
                $scanner = Runner::make_stage($ctx, $stage, $job['states']);
                if (null === $job['queue']) {
                    $job['state'] = $scanner->init_state();
                    $job['queue'] = $scanner->plan($job['state']);
                }
                if (0 === count($job['queue'])) {
                    $ctx->deadline = null;
                    $scanner->finish($job['state']);
                    $job['states'][$stage] = $job['state'];
                    $job['stage_index']++;
                    $job['queue'] = null;
                    $job['state'] = array();
                    $job = self::absorb($job, $reporter);
                    continue;
                }
                // Record the attempt (with the unit still queued) before
                // running it: if PHP dies inside, the next step sees it.
                $unit = $job['queue'][0];
                $key = md5($stage . '|' . json_encode($unit)); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress here.
                if ($job['attempt']['key'] === $key) {
                    $job['attempt']['count']++;
                } else {
                    $job['attempt'] = array('key' => $key, 'count' => 1);
                }
                if ($job['attempt']['count'] > self::MAX_ATTEMPTS) {
                    throw new Fatal(self::t('PHP stopped %1$d times on the same part of the "%2$s" stage (usually the memory or time limit). Raise memory_limit, or run php bin/elderward.php scanall=1 from a shell.', self::MAX_ATTEMPTS, self::t(Runner::stage_label($stage))));
                }
                $job = self::absorb($job, $reporter);
                self::write_state('job', $job);
                array_shift($job['queue']);
                $next = $scanner->run($unit, $job['state']);
                if (null !== $next) {
                    $job['queue'] = array_merge(Scanner::as_unit_list($next), $job['queue']);
                }
                $job['units']++;
                $job = self::absorb($job, $reporter);
            }
        } catch (Fatal $e) {
            $job['status'] = 'failed';
            $job['error'] = $e->getMessage();
            $job['finished'] = time();
        } catch (\Exception $e) {
            $job['status'] = 'failed';
            $job['error'] = get_class($e) . ': ' . $e->getMessage();
            $job['finished'] = time();
        } catch (\Throwable $e) { // phpcs:ignore PHPCompatibility.Classes.NewClasses.throwableFound -- PHP 7+ errors; on PHP 5.6 this clause never matches.
            $job['status'] = 'failed';
            $job['error'] = get_class($e) . ': ' . $e->getMessage();
            $job['finished'] = time();
        }
        $job = self::absorb($job, $reporter);
        self::write_state('job', $job);
        self::unlock($lock);
        return self::status_payload($job);
    }

    private static function absorb(array $job, CollectReporter $reporter)
    {
        foreach ($reporter->take() as $finding) {
            if (count($job['findings']) < self::MAX_FINDINGS) {
                $job['findings'][] = $finding;
            } else {
                $job['dropped']++;
            }
        }
        $job['counts'] = $reporter->counts();
        if ('' !== $reporter->last_progress()) {
            $job['message'] = $reporter->last_progress();
        }
        return $job;
    }

    private static function cancel()
    {
        $lock = self::lock(true);
        $job = self::read_state('job');
        if (!empty($job) && 'running' === $job['status']) {
            $job['status'] = 'cancelled';
            $job['finished'] = time();
            self::write_state('job', $job);
        }
        if (null !== $lock) {
            self::unlock($lock);
        }
        return self::status_payload($job);
    }

    private static function status_payload($job)
    {
        if (empty($job)) {
            return array('ok' => true, 'status' => '', 'percent' => 0, 'message' => '');
        }
        $stages = max(1, count($job['stages']));
        $percent = 'done' === $job['status'] ? 100 : (int) floor(($job['stage_index'] / $stages) * 100);
        $label = '';
        if ('running' === $job['status'] && $job['stage_index'] < count($job['stages'])) {
            self::load_engine();
            $label = self::t(Runner::stage_label($job['stages'][$job['stage_index']]));
        }
        return array(
            'ok'      => true,
            'status'  => $job['status'],
            'percent' => $percent,
            'stage'   => $label,
            'message' => (string) $job['message'],
            'counts'  => $job['counts'],
            'error'   => (string) $job['error'],
        );
    }

    private static function export()
    {
        $job = self::read_state('job');
        header('Content-Type: application/x-ndjson; charset=utf-8');
        header('Content-Disposition: attachment; filename="elderward-recovery-' . gmdate('Ymd-His') . '.json"');
        foreach (isset($job['findings']) ? $job['findings'] : array() as $finding) {
            echo json_encode(array_merge(array('event' => 'finding'), $finding)) . "\n"; // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress here; JSON responses of the recovery page.
        }
        exit;
    }

    ////////////////
    // Output.
    //////////////

    private static function headers()
    {
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('X-Robots-Tag: noindex, nofollow');
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" . self::$nonce . "'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; img-src data:");
    }

    private static function not_found()
    {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Not Found\n";
        exit;
    }

    private static function json(array $data, $status = 200)
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress here; NDJSON export.
        exit;
    }

    private static function h($text)
    {
        return htmlspecialchars((string) $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function relative($path)
    {
        $root = rtrim((string) self::$root, '/');
        $path = (string) $path;
        return (0 === strpos($path, $root . '/')) ? substr($path, strlen($root) + 1) : $path;
    }

    private static function page_start($title)
    {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="' . ('pt_BR' === self::$lang ? 'pt-BR' : 'en') . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<meta name="robots" content="noindex, nofollow"><title>' . self::h($title) . '</title><style>' . self::css() . '</style></head><body>';
        $other = 'pt_BR' === self::$lang ? array('en', 'English', 'en') : array('pt_BR', 'Português', 'pt-BR');
        echo '<main class="wrap"><header class="brand"><div><div class="word">Elderward</div><div class="tag">' . self::e('Recovery mode · works without WordPress') . '</div></div>'
            . '<a class="lang" href="' . self::h(self::self_url() . '?lang=' . $other[0]) . '" hreflang="' . $other[2] . '" lang="' . $other[2] . '">' . self::h($other[1]) . '</a></header>';
        if (!self::https()) {
            echo '<p class="note warn">' . self::e('This page is not using HTTPS: the key and the results cross the network unencrypted. Use the https:// address if the site has one.') . '</p>';
        }
    }

    private static function page_end($script = '')
    {
        echo '</main>';
        if ('' !== $script) {
            echo '<script nonce="' . self::h(self::$nonce) . '">' . $script . '</script>';
        }
        echo '</body></html>';
        exit;
    }

    private static function page_login($error)
    {
        self::page_start(self::t('Elderward recovery'));
        echo '<section class="card narrow"><h1>' . self::e('Sign in') . '</h1>';
        echo '<p>' . self::e('Enter the recovery key created in Elderward > Recovery, with WP-CLI, or in the key file you uploaded.') . '</p>';
        if ('' !== $error) {
            echo '<p class="note error" role="alert">' . self::h($error) . '</p>';
        }
        echo '<form method="post" action="' . self::h(self::self_url()) . '" autocomplete="off">';
        echo '<input type="hidden" name="do" value="login"><label for="key">' . self::e('Recovery key') . '</label>';
        echo '<input type="password" id="key" name="key" required autofocus spellcheck="false">';
        echo '<button type="submit" class="primary">' . self::e('Sign in') . '</button></form></section>';
        self::page_end();
    }

    private static function page_main(array $session)
    {
        $token = self::csrf($session);
        $version = self::wp_version();
        $errors = self::recent_errors();
        $job = self::read_state('job');
        $config = is_file(self::$root . '/wp-config.php') ? self::$root . '/wp-config.php' : (is_file(dirname(self::$root) . '/wp-config.php') ? dirname(self::$root) . '/wp-config.php' : null);

        self::page_start(self::t('Elderward recovery'));
        echo '<form method="post" action="' . self::h(self::self_url()) . '" class="signout"><input type="hidden" name="do" value="logout"><input type="hidden" name="token" value="' . self::h($token) . '"><button type="submit">' . self::e('Sign out') . '</button></form>';
        if (self::$key['manual']) {
            echo '<p class="note warn">' . self::t('This key was added by hand and never expires. Delete %s when you are done.', '<code>' . self::h(self::relative(self::$content_dir . '/' . self::KEY_FILE)) . '</code>') . '</p>';
        }

        echo '<section class="card"><h2>' . self::e('This site') . '</h2><dl class="facts">';
        echo '<dt>' . self::e('WordPress folder') . '</dt><dd><code>' . self::h(self::$root) . '</code></dd>';
        echo '<dt>' . self::e('WordPress version') . '</dt><dd>' . (null === $version ? '<span class="bad">' . self::e('wp-includes/version.php not found') . '</span>' : self::h($version)) . '</dd>';
        echo '<dt>wp-config.php</dt><dd>' . (null === $config ? '<span class="bad">' . self::e('not found') . '</span>' : '<code>' . self::h(self::relative($config)) . '</code> ' . self::e('(read, never run)')) . '</dd>';
        echo '<dt>PHP</dt><dd>' . self::e('%1$s, memory limit %2$s', PHP_VERSION, (string) ini_get('memory_limit')) . '</dd>';
        if (is_file(self::$root . '/.maintenance')) {
            echo '<dt>' . self::e('Maintenance') . '</dt><dd><span class="bad">' . self::e('.maintenance exists') . '</span>: ' . self::e('an update stopped halfway, which shows "Briefly unavailable for scheduled maintenance". Delete the file if no update is running.') . '</dd>';
        }
        echo '</dl></section>';

        echo '<section class="card"><h2>' . self::e('What broke the site') . '</h2>';
        if (empty($errors['logs'])) {
            echo '<p>' . self::t('No PHP error log was found. To get one, add %s to wp-config.php, load the broken page once, then reload this page.', '<code>' . self::h("define('WP_DEBUG', true); define('WP_DEBUG_LOG', true); define('WP_DEBUG_DISPLAY', false);") . '</code>') . '</p>';
        } elseif (empty($errors['lines'])) {
            echo '<p>' . self::e('No fatal errors in the latest part of: %s.', implode(', ', array_map(array(__CLASS__, 'relative'), $errors['logs']))) . '</p>';
        } else {
            if (!empty($errors['suspects'])) {
                echo '<p><strong>' . self::e('The errors point at:') . '</strong></p><ul class="suspects">';
                foreach ($errors['suspects'] as $name => $count) {
                    echo '<li><code>wp-content/' . self::h($name) . '</code> (' . self::e(1 === $count ? '%d error' : '%d errors', (int) $count) . ')</li>';
                }
                echo '</ul><p class="hint">' . self::t('Renaming that plugin or theme folder (or a single must-use plugin file), for example by adding %s to its name over FTP or your host\'s file manager, switches it off and usually brings the site back. Then scan below: code that suddenly fails may have been modified by malware.', '<code>.off</code>') . '</p>';
            }
            echo '<details open><summary>' . self::e('Latest fatal errors') . '</summary><pre class="log">';
            foreach ($errors['lines'] as $entry) {
                echo self::h($entry['line']) . "\n";
            }
            echo '</pre></details>';
        }
        echo '</section>';

        $running = !empty($job) && 'running' === $job['status'];
        echo '<section class="card" id="scan" data-token="' . self::h($token) . '" data-running="' . ($running ? '1' : '0') . '"><h2>' . self::e('Scan for malware') . '</h2>';
        echo '<p>' . self::e('The same report-only scan as the Elderward admin page: WordPress, plugin and theme files against the official copies, known malware, the database (through the settings in wp-config.php), faked file dates and the server crontab. Nothing is changed.') . '</p>';
        echo '<label for="log">' . self::e('Access logs (optional)') . '</label><input type="text" id="log" placeholder="/var/log/apache2" spellcheck="false">';
        echo '<p class="buttons"><button type="button" class="primary" id="start"' . ($running ? ' disabled' : '') . '>' . self::e('Start scan') . '</button> <button type="button" id="cancel"' . ($running ? '' : ' disabled') . '>' . self::e('Cancel') . '</button></p>';
        echo '<div id="progress"' . ($running ? '' : ' hidden') . '><div class="bar"><div class="fill" style="width:0%"></div></div><p id="status">' . self::e('Keep this page open while the scan runs.') . '</p></div>';
        if (!empty($job) && 'running' !== $job['status']) {
            self::render_results($job);
        }
        echo '</section>';

        echo '<section class="card"><h2>' . self::e('After the scan') . '</h2><ol>';
        echo '<li>' . self::e('Take a backup of the files and the database before changing anything.') . '</li>';
        echo '<li>' . self::t('Remove known malware and restore modified core, plugin and theme files from the command line: %1$s shows the same report, %2$s previews a cleanup.', '<code>php wp-content/plugins/elderward/bin/elderward.php scanall=1</code>', '<code>scandirectory=… dryrun=1</code>') . '</li>';
        echo '<li>' . self::e('Once WordPress loads again, change every password and the salts in wp-config.php, and revoke this recovery key.') . '</li>';
        echo '</ol></section>';

        self::page_end(self::script());
    }

    private static function render_results(array $job)
    {
        $order = array('HIGH' => 0, 'ERROR' => 1, 'MEDIUM' => 2, 'LOW' => 3, 'INFO' => 4);
        $findings = $job['findings'];
        usort($findings, function ($a, $b) use ($order) {
            $x = isset($order[$a['severity']]) ? $order[$a['severity']] : 9;
            $y = isset($order[$b['severity']]) ? $order[$b['severity']] : 9;
            return $x - $y;
        });
        $words = array('done' => self::t('complete'), 'failed' => self::t('failed'), 'cancelled' => self::t('cancelled'));
        echo '<p class="last">' . self::t('Last scan: %1$s, started %2$s UTC.', '<strong>' . self::h(isset($words[$job['status']]) ? $words[$job['status']] : $job['status']) . '</strong>', self::h(gmdate('Y-m-d H:i', (int) $job['started'])));
        if ('' !== (string) $job['error']) {
            echo ' <span class="bad">' . self::h($job['error']) . '</span>';
        }
        echo '</p><p class="counts">';
        foreach ($order as $severity => $unused) {
            $count = isset($job['counts'][$severity]) ? (int) $job['counts'][$severity] : 0;
            echo '<span class="sev sev-' . self::h(strtolower($severity)) . '">' . self::h($severity) . ' ' . $count . '</span> ';
        }
        echo '<a href="' . self::h(self::self_url()) . '?export=1">' . self::e('Export JSON') . '</a></p>';
        if ((int) $job['dropped'] > 0) {
            echo '<p class="note warn">' . self::e('%d more findings were not kept; export from the command line for the full list.', (int) $job['dropped']) . '</p>';
        }
        if (empty($findings)) {
            echo '<p>' . self::e('Nothing found.') . '</p>';
            return;
        }
        if ('en' !== self::$lang) {
            echo '<p class="hint">' . self::e('Finding details are in English, as in exports and on the command line.') . '</p>';
        }
        echo '<div class="scroll"><table><thead><tr><th>' . self::e('Severity') . '</th><th>' . self::e('Type') . '</th><th>' . self::e('Where') . '</th><th>' . self::e('Details') . '</th></tr></thead><tbody>';
        foreach ($findings as $finding) {
            echo '<tr><td><span class="sev sev-' . self::h(strtolower($finding['severity'])) . '">' . self::h($finding['severity']) . '</span></td>';
            echo '<td class="type">' . self::h($finding['type']) . '</td>';
            echo '<td><code>' . self::h(self::relative($finding['path'])) . '</code></td>';
            echo '<td>' . self::h($finding['detail']);
            if (!empty($finding['context'])) {
                echo '<details><summary>' . self::e('Context') . '</summary><pre>' . self::h(implode("\n", array_map('strval', (array) $finding['context']))) . '</pre></details>';
            }
            echo '</td></tr>';
        }
        echo '</tbody></table></div>';
    }

    private static function script()
    {
        $strings = array();
        foreach (array('Scanning: ', 'Working…', 'Error.', 'Lost contact with the server; retrying…', 'Starting…', 'Could not start.') as $text) {
            $strings[$text] = self::t($text);
        }
        $json = json_encode($strings, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress here; inline script data, HTML-safe flags.
        return 'var ELDERWARD_L = ' . $json . ';' . <<<'JS'
(function () {
	var L = function (text) { return ELDERWARD_L[text] || text; };
	var box = document.getElementById('scan');
	if (!box) { return; }
	var token = box.getAttribute('data-token');
	var start = document.getElementById('start');
	var cancel = document.getElementById('cancel');
	var progress = document.getElementById('progress');
	var fill = progress.querySelector('.fill');
	var status = document.getElementById('status');
	var stopped = false;
	function post(action, extra) {
		var body = new URLSearchParams();
		body.append('do', action);
		body.append('token', token);
		Object.keys(extra || {}).forEach(function (k) { body.append(k, extra[k]); });
		return fetch(location.pathname, { method: 'POST', credentials: 'same-origin', body: body }).then(function (r) { return r.json(); });
	}
	function show(data) {
		fill.style.width = (data.percent || 0) + '%';
		status.textContent = data.stage ? (L('Scanning: ') + data.stage + (data.message ? ' — ' + data.message : '')) : (data.message || L('Working…'));
	}
	function loop() {
		if (stopped) { return; }
		post('step').then(function (data) {
			if (!data.ok) { status.textContent = data.message || L('Error.'); return; }
			show(data);
			if (data.status === 'running') { setTimeout(loop, 200); } else { location.reload(); }
		}).catch(function () { status.textContent = L('Lost contact with the server; retrying…'); setTimeout(loop, 3000); });
	}
	start.addEventListener('click', function () {
		start.disabled = true; cancel.disabled = false; progress.hidden = false; stopped = false;
		status.textContent = L('Starting…');
		post('start', { log: document.getElementById('log').value }).then(function (data) {
			if (!data.ok) { status.textContent = data.message || L('Could not start.'); start.disabled = false; cancel.disabled = true; return; }
			show(data); loop();
		});
	});
	cancel.addEventListener('click', function () {
		stopped = true;
		post('cancel').then(function () { location.reload(); });
	});
	if (box.getAttribute('data-running') === '1') { loop(); }
})();
JS;
    }

    private static function css()
    {
        return 'body{margin:0;background:#f0f0f1;color:#1d2327;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif}'
            . '.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 48px;box-sizing:border-box}'
            . '.brand{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:20px 24px;border-radius:6px;background:#061614;color:#dcd3b0;border:1px solid #173d37;margin-bottom:20px}'
            . '.brand .lang{color:#8fb9ab;font-size:13px;border:1px solid #2c5a51;border-radius:999px;padding:2px 12px;text-decoration:none;white-space:nowrap}.brand .lang:hover{color:#f0e6c4}'
            . '.brand .word{font:600 30px/1.1 Georgia,"Times New Roman",serif;color:#f0e6c4}.brand .tag{color:#b9b195;margin-top:4px}'
            . '.card{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:20px 24px;margin:0 0 20px;box-shadow:0 1px 2px rgba(0,0,0,.04)}'
            . '.card.narrow{max-width:460px;margin:40px auto}h1,h2{margin:0 0 12px;font-size:20px;font-weight:600}'
            . 'label{display:block;font-weight:600;margin:12px 0 6px}input[type=password],input[type=text]{width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid #8c8f94;border-radius:4px;font:14px Menlo,Consolas,monospace}'
            . 'button{font:inherit;padding:8px 16px;border-radius:4px;border:1px solid #2271b1;background:#fff;color:#2271b1;cursor:pointer}button.primary{background:#2271b1;color:#fff}button:disabled{opacity:.5;cursor:default}'
            . 'form button{margin-top:12px}.signout{float:right;margin:-8px 0 0}.signout button{margin:0}'
            . '.note{padding:10px 14px;border-left:4px solid #72aee6;background:#f0f6fc}.note.warn{border-color:#dba617;background:#fcf9e8}.note.error{border-color:#d63638;background:#fcf0f1}'
            . '.facts{display:grid;grid-template-columns:200px 1fr;gap:6px 16px;margin:0}.facts dt{font-weight:600}.facts dd{margin:0}'
            . 'code,pre{font-family:Menlo,Consolas,monospace;font-size:13px}code{background:#f6f7f7;padding:1px 4px;border-radius:3px;word-break:break-all}'
            . 'pre.log,td pre{white-space:pre-wrap;word-break:break-all;background:#1d2327;color:#f0f0f1;padding:12px;border-radius:4px;max-height:320px;overflow:auto}'
            . '.bad{color:#b32d2e;font-weight:600}.hint{color:#50575e}.bar{height:10px;background:#dcdcde;border-radius:999px;overflow:hidden}.fill{height:100%;background:#2271b1;transition:width .3s}'
            . '.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:720px}th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid #f0f0f1}'
            . '.type{font-size:12px;font-weight:600}.sev{display:inline-block;min-width:56px;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-align:center;color:#fff;background:#646970}'
            . '.sev-high{background:#d63638}.sev-error{background:#996800}.sev-medium{background:#dba617;color:#1d2327}.sev-low{background:#2271b1}'
            . '.counts .sev{margin-right:4px}[hidden]{display:none}'
            . '@media(max-width:600px){.facts{grid-template-columns:1fr}.card{padding:16px}}';
    }
}
