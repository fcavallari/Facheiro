<?php
/**
 * The recovery key: what unlocks recovery.php, the page that scans the site
 * without loading WordPress.
 *
 * Only a SHA-256 of the key is stored, in wp-content/facheiro-recovery-key.php
 * (next to the plugins folder, where recovery.php finds it without
 * WordPress). The file starts with "<?php exit; ?>", so requesting it over
 * the web shows nothing. Without that file, recovery.php answers 404.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Recovery_Key
{
    const FILE = 'facheiro-recovery-key.php';
    const GUARD = '<?php exit; ?>';
    const MIN_LENGTH = 24;

    /**
     * The folder that holds the plugins folder (wp-content on almost every
     * site). recovery.php computes the same folder from its own location.
     */
    public static function dir()
    {
        return Facheiro_Plugin::content_dir();
    }

    public static function path()
    {
        return self::dir() . '/' . self::FILE;
    }

    public static function url()
    {
        return plugins_url('recovery.php', FACHEIRO_FILE);
    }

    public static function expiries()
    {
        return array(
            '1'     => __('1 dia', 'facheiro'),
            '7'     => __('7 dias', 'facheiro'),
            '30'    => __('30 dias', 'facheiro'),
            'never' => __('Até eu revogar', 'facheiro'),
        );
    }

    /**
     * The key file's data, or null when there is none.
     *
     * @return array|null array(manual => bool, created, expires, by)
     */
    public static function status()
    {
        $file = self::path();
        if (!is_file($file) || !is_readable($file)) {
            return null;
        }
        $data = Facheiro_Plugin::read_guarded_json($file);
        if (null === $data) {
            return array('manual' => true, 'valid' => false, 'created' => (int) filemtime($file), 'expires' => 0, 'by' => '');
        }
        $manual = isset($data['key']);
        $valid = $manual ? strlen((string) $data['key']) >= self::MIN_LENGTH : (isset($data['hash']) && 64 === strlen((string) $data['hash']));
        return array(
            'manual'  => $manual,
            'valid'   => $valid,
            'created' => isset($data['created']) ? (int) $data['created'] : (int) filemtime($file),
            'expires' => isset($data['expires']) ? (int) $data['expires'] : 0,
            'by'      => isset($data['by']) ? (string) $data['by'] : '',
        );
    }

    public static function active()
    {
        $status = self::status();
        return null !== $status && $status['valid'] && (0 === $status['expires'] || $status['expires'] > time());
    }

    /**
     * Create a new key (replacing any other). Returns the key, shown once.
     *
     * @param string $expiry Days ('1', '7', '30') or 'never'.
     * @return string|WP_Error
     */
    public static function create($expiry, $by = '')
    {
        $days = 'never' === $expiry ? 0 : max(1, min(365, (int) $expiry));
        $key = wp_generate_password(32, false, false);
        $data = array(
            'hash'    => hash('sha256', $key),
            'created' => time(),
            'expires' => 0 === $days ? 0 : time() + $days * DAY_IN_SECONDS,
            'by'      => sanitize_user((string) $by),
        );
        if (!wp_is_writable(self::dir()) && !(is_file(self::path()) && wp_is_writable(self::path()))) {
            /* translators: %s: folder path */
            return new WP_Error('facheiro_recovery_write', sprintf(__('O PHP não consegue gravar em %s, então o arquivo da chave não pôde ser salvo.', 'facheiro'), self::dir()));
        }
        if (!Facheiro_Plugin::write_guarded_json(self::path(), $data)) {
            return new WP_Error('facheiro_recovery_write', __('Não foi possível salvar o arquivo da chave.', 'facheiro'));
        }
        return $key;
    }

    public static function revoke()
    {
        $file = self::path();
        if (is_file($file)) {
            wp_delete_file($file);
        }
        return !is_file($file);
    }

    /**
     * Template for creating a key by hand (FTP, file manager) when
     * WordPress no longer loads.
     */
    public static function manual_template($key)
    {
        return self::GUARD . "\n" . wp_json_encode(array('key' => $key)) . "\n";
    }

    /**
     * The folders recovery.php may have used for its state. It names the
     * temp one after the WordPress folder as the web server sees it, which
     * can differ from ABSPATH (symlinks), and uses the system temp folder,
     * which can differ from get_temp_dir() (WP_TEMP_DIR): try them all.
     */
    public static function state_dirs()
    {
        $roots = array_unique(array_filter(array(
            untrailingslashit(ABSPATH),
            realpath(ABSPATH),
            dirname(self::dir()),
            realpath(dirname(self::dir())),
        )));
        $temps = array_unique(array_filter(array(rtrim(sys_get_temp_dir(), '/\\'), untrailingslashit(get_temp_dir()))));
        $dirs = array(self::dir() . '/facheiro-recovery');
        foreach ($temps as $temp) {
            foreach ($roots as $root) {
                $dirs[] = $temp . '/facheiro-recovery-' . substr(hash('sha256', untrailingslashit((string) $root)), 0, 16);
            }
        }
        return array_values(array_unique($dirs));
    }

    /**
     * Uninstall: the key file and recovery's state folders (job with the
     * findings, sign-in attempts, engine work files).
     */
    public static function uninstall()
    {
        self::revoke();
        foreach (self::state_dirs() as $dir) {
            if (self::own_private_dir($dir)) {
                self::delete_tree($dir);
            }
        }
    }

    /**
     * The same test recovery.php applies before using a state folder: a
     * real directory owned by this PHP user that nobody else can enter. In
     * a shared system temp folder another account could otherwise plant a
     * folder (or swap in a link) under the predictable name and have the
     * uninstall delete through it.
     */
    private static function own_private_dir($dir)
    {
        clearstatcache(true, $dir);
        if (!is_dir($dir) || is_link($dir)) {
            return false;
        }
        $me = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();
        if (fileowner($dir) !== $me) {
            return false;
        }
        return 0 === (fileperms($dir) & 0077);
    }

    /**
     * Delete a folder and everything in it, without following symlinks
     * (a link is removed, never its target).
     */
    private static function delete_tree($dir)
    {
        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($items as $item) {
            $path = $item->getPathname();
            if ($item->isDir() && !$item->isLink()) {
                @rmdir($path); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- uninstall, best effort; an empty folder of recovery's own state.
            } else {
                wp_delete_file($path);
            }
        }
        @rmdir($dir); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- see above.
    }
}
