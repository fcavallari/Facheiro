<?php
/**
 * Server hardening: rules that stop the web server from running or serving
 * files it never should (PHP dropped into uploads, wp-config backups, .git,
 * WordPress internals), for Apache/LiteSpeed (.htaccess files written here)
 * or Nginx (a configuration file the administrator includes).
 *
 * Writes are limited to Elderward's own "# BEGIN Elderward" blocks, made
 * with WordPress's insert_with_markers(). The site is checked before and
 * after: if it starts failing, every file is put back as it was.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Hardening
{
    const OPTION = 'elderward_hardening';
    const MARKER = 'Elderward';
    const PHP_EXT = '\.ph(?:p[0-9]?|t|tml|ar|ps)(?:\.|$)';

    /**
     * Every protection: label, explanation, what it can break, and which
     * templates include it.
     */
    public static function features()
    {
        return array(
            'uploads_php'   => array(
                'label'   => __('Block PHP in the uploads folder', 'elderward'),
                'help'    => __('Uploads hold images and documents. A PHP file there is almost always a web shell an attacker managed to upload; this stops it from running.', 'elderward'),
                'risk'    => __('Rarely breaks anything. A few badly written plugins keep PHP in uploads.', 'elderward'),
                'presets' => array('recommended', 'strict'),
            ),
            'core_includes' => array(
                'label'   => __('Block direct access to WordPress internals', 'elderward'),
                'help'    => __('Files in wp-includes and wp-admin/includes are loaded by WordPress itself and never need to be opened from a browser. Attackers request them to probe for weaknesses.', 'elderward'),
                'risk'    => __('Safe for WordPress itself; the few files that must stay reachable are allowed.', 'elderward'),
                'presets' => array('recommended', 'strict'),
            ),
            'config'        => array(
                'label'   => __('Protect wp-config files', 'elderward'),
                'help'    => __('wp-config.php holds the database password. This also covers copies such as wp-config.php.bak or wp-config.old that would otherwise be downloadable as plain text.', 'elderward'),
                'risk'    => __('Safe: nothing should ever request these files.', 'elderward'),
                'presets' => array('recommended', 'strict'),
            ),
            'sensitive'     => array(
                'label'   => __('Block backups, logs and server settings', 'elderward'),
                'help'    => __('Stops downloads of files such as .sql dumps, .bak and .old copies, editor backups (~), .log files (including debug.log), .ini files and shell scripts, plus readme.html and license.txt, which reveal the WordPress version.', 'elderward'),
                'risk'    => __('Breaks links to files with these extensions, if your site offers any for download.', 'elderward'),
                'presets' => array('recommended', 'strict'),
            ),
            'dotfiles'      => array(
                'label'   => __('Block hidden files and folders', 'elderward'),
                'help'    => __('Names starting with a dot (.git, .env, .htaccess, .user.ini) often hold passwords, keys or the whole source history. The .well-known folder used for SSL certificates stays reachable.', 'elderward'),
                'risk'    => __('Safe for almost every site.', 'elderward'),
                'presets' => array('recommended', 'strict'),
            ),
            'indexes'       => array(
                'label'   => __('Turn off folder listings', 'elderward'),
                'help'    => __('Without an index file, some servers list every file in a folder (for example everything in uploads), which helps attackers find what to target.', 'elderward'),
                'risk'    => __('On a few Apache hosts this setting is not allowed in .htaccess and the site would show an error; Elderward checks the site and undoes the change if that happens.', 'elderward'),
                'presets' => array('recommended', 'strict'),
            ),
            'themes_php'    => array(
                'label'   => __('Block direct PHP in themes', 'elderward'),
                'help'    => __('Theme files are loaded by WordPress; a request straight to a PHP file inside a theme folder is a sign of an attack or a planted file.', 'elderward'),
                'risk'    => __('Breaks old themes that link to their own PHP files (for example a custom image or CSS generator).', 'elderward'),
                'presets' => array('strict'),
            ),
            'headers'       => array(
                'label'   => __('Add security headers', 'elderward'),
                'help'    => __('X-Content-Type-Options (no content-type guessing), X-Frame-Options SAMEORIGIN (no framing by other sites, against clickjacking) and Referrer-Policy (less information in links to other sites).', 'elderward'),
                'risk'    => __('Other sites can no longer show your pages in a frame.', 'elderward'),
                'presets' => array('strict'),
            ),
            'xmlrpc'        => array(
                'label'   => __('Turn off XML-RPC', 'elderward'),
                'help'    => __('xmlrpc.php is an old remote-publishing interface and a favourite target for password guessing and pingback abuse.', 'elderward'),
                'risk'    => __('Breaks Jetpack, the WordPress mobile apps and other tools that publish through XML-RPC.', 'elderward'),
                'presets' => array('strict'),
            ),
            'plugins_php'   => array(
                'label'   => __('Block direct PHP in plugins', 'elderward'),
                'help'    => __('Like the theme rule, for the plugins folder. Elderward\'s recovery page stays reachable.', 'elderward'),
                'risk'    => __('Breaks every plugin that has its own PHP entry point (some payment callbacks, image tools, older admin screens). Test the site carefully.', 'elderward'),
                'presets' => array(),
            ),
        );
    }

    public static function presets()
    {
        return array(
            'recommended' => __('Recommended', 'elderward'),
            'strict'      => __('Strict', 'elderward'),
            'custom'      => __('Custom', 'elderward'),
        );
    }

    public static function preset_features($preset)
    {
        $out = array();
        foreach (self::features() as $id => $feature) {
            if (in_array($preset, $feature['presets'], true)) {
                $out[] = $id;
            }
        }
        return $out;
    }

    /**
     * Only known feature ids, in the canonical order.
     */
    public static function clean_features($features)
    {
        $features = array_map('strval', (array) $features);
        return array_values(array_filter(array_keys(self::features()), function ($id) use ($features) {
            return in_array($id, $features, true);
        }));
    }

    public static function servers()
    {
        return array(
            'apache' => __('Apache or LiteSpeed (.htaccess)', 'elderward'),
            'nginx'  => __('Nginx', 'elderward'),
        );
    }

    /**
     * Best guess from the server's own name; null when unknown.
     */
    public static function detect_server()
    {
        $software = isset($_SERVER['SERVER_SOFTWARE']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']))) : '';
        if (false !== strpos($software, 'nginx') || false !== strpos($software, 'openresty')) {
            return 'nginx';
        }
        if (false !== strpos($software, 'apache') || false !== strpos($software, 'litespeed')) {
            return 'apache';
        }
        return null;
    }

    public static function state()
    {
        $state = get_option(self::OPTION, array());
        $state = is_array($state) ? $state : array();
        $detected = self::detect_server();
        return array_merge(array(
            'server'   => null === $detected ? 'apache' : $detected,
            'preset'   => 'recommended',
            'features' => self::preset_features('recommended'),
            'applied'  => array(),
            'files'    => array(),
            'time'     => 0,
            'user'     => 0,
        ), $state);
    }

    private static function save_state(array $state)
    {
        update_option(self::OPTION, $state, false);
    }

    /**
     * Remember the choices shown on the page (no files are touched).
     */
    public static function remember($server, $preset, $features)
    {
        $state = self::state();
        $state['server'] = array_key_exists($server, self::servers()) ? $server : 'apache';
        $state['preset'] = array_key_exists($preset, self::presets()) ? $preset : 'custom';
        $state['features'] = self::clean_features($features);
        self::save_state($state);
        return $state;
    }

    ////////////////
    // Paths.
    //////////////

    /**
     * URL path of a site URL, without the trailing slash ('' for the root).
     */
    private static function url_path($url)
    {
        $path = (string) wp_parse_url($url, PHP_URL_PATH);
        return untrailingslashit($path);
    }

    private static function uploads()
    {
        $uploads = wp_upload_dir(null, false);
        return array(
            'dir' => untrailingslashit($uploads['basedir']),
            'url' => untrailingslashit($uploads['baseurl']),
        );
    }

    private static function home_dir()
    {
        if (!function_exists('get_home_path')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        return untrailingslashit(get_home_path());
    }

    /**
     * The .htaccess files Elderward manages, by role.
     */
    public static function apache_targets()
    {
        $uploads = self::uploads();
        return array(
            'root'           => self::home_dir() . '/.htaccess',
            'uploads'        => $uploads['dir'] . '/.htaccess',
            'includes'       => ABSPATH . WPINC . '/.htaccess',
            'admin_includes' => ABSPATH . 'wp-admin/includes/.htaccess',
            'themes'         => untrailingslashit(get_theme_root()) . '/.htaccess',
            'plugins'        => untrailingslashit(WP_PLUGIN_DIR) . '/.htaccess',
        );
    }

    ////////////////
    // Rules.
    //////////////

    private static function apache_deny()
    {
        return array(
            '    <IfModule mod_authz_core.c>',
            '        Require all denied',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order allow,deny',
            '        Deny from all',
            '    </IfModule>',
        );
    }

    private static function apache_allow()
    {
        return array(
            '    <IfModule mod_authz_core.c>',
            '        Require all granted',
            '    </IfModule>',
            '    <IfModule !mod_authz_core.c>',
            '        Order allow,deny',
            '        Allow from all',
            '    </IfModule>',
        );
    }

    private static function files_match($regex, $deny = true)
    {
        return array_merge(
            array('<FilesMatch "' . $regex . '">'),
            $deny ? self::apache_deny() : self::apache_allow(),
            array('</FilesMatch>')
        );
    }

    /**
     * The lines for each .htaccess file, for the chosen features. A role
     * with no lines gets its Elderward block removed.
     *
     * @return array role => list of lines
     */
    public static function apache_rules(array $features)
    {
        $on = array_flip(self::clean_features($features));
        $rules = array_fill_keys(array_keys(self::apache_targets()), array());
        $php = '(?i)' . self::PHP_EXT;

        if (isset($on['config'])) {
            $rules['root'][] = '# Protect wp-config.php and any copy of it.';
            $rules['root'] = array_merge($rules['root'], self::files_match('(?i)^wp-config'));
        }
        if (isset($on['sensitive'])) {
            $rules['root'][] = '# Backups, dumps, logs, server settings and version-revealing files.';
            $rules['root'] = array_merge($rules['root'], self::files_match('(?i)(?:\.(?:bak|old|orig|save|swp|swo|sql|log|ini|sh)|~)$|^(?:readme\.html|license\.txt|error_log)$'));
        }
        if (isset($on['dotfiles'])) {
            $rules['root'][] = '# Hidden files and folders (.git, .env, ...), except .well-known.';
            $rules['root'] = array_merge($rules['root'], self::files_match('^\.'));
            $rules['root'][] = '<IfModule mod_rewrite.c>';
            $rules['root'][] = '    RewriteEngine On';
            $rules['root'][] = '    RewriteRule (?:^|/)\.(?!well-known(?:/|$)) - [F]';
            $rules['root'][] = '</IfModule>';
        }
        if (isset($on['xmlrpc'])) {
            $rules['root'][] = '# XML-RPC.';
            $rules['root'] = array_merge($rules['root'], self::files_match('^xmlrpc\.php$'));
        }
        if (isset($on['indexes'])) {
            $rules['root'][] = '# No folder listings.';
            $rules['root'][] = 'Options -Indexes';
        }
        if (isset($on['headers'])) {
            $rules['root'][] = '# Security headers.';
            $rules['root'][] = '<IfModule mod_headers.c>';
            $rules['root'][] = '    Header always set X-Content-Type-Options "nosniff"';
            $rules['root'][] = '    Header always set X-Frame-Options "SAMEORIGIN"';
            $rules['root'][] = '    Header always set Referrer-Policy "strict-origin-when-cross-origin"';
            $rules['root'][] = '</IfModule>';
        }
        if (isset($on['uploads_php'])) {
            $rules['uploads'][] = '# No PHP runs from uploads.';
            $rules['uploads'] = array_merge($rules['uploads'], self::files_match($php));
        }
        if (isset($on['core_includes'])) {
            $rules['includes'][] = '# WordPress loads these files itself; browsers never need them.';
            $rules['includes'] = array_merge($rules['includes'], self::files_match($php), self::files_match('^(?:wp-tinymce|ms-files)\.php$', false));
            $rules['admin_includes'][] = '# WordPress loads these files itself; browsers never need them.';
            $rules['admin_includes'] = array_merge($rules['admin_includes'], self::files_match($php));
        }
        if (isset($on['themes_php'])) {
            $rules['themes'][] = '# Theme PHP is loaded by WordPress, never requested directly.';
            $rules['themes'] = array_merge($rules['themes'], self::files_match($php));
        }
        if (isset($on['plugins_php'])) {
            $rules['plugins'][] = '# Plugin PHP is loaded by WordPress; Elderward\'s recovery page stays reachable.';
            $rules['plugins'][] = '<IfModule mod_rewrite.c>';
            $rules['plugins'][] = '    RewriteEngine On';
            $rules['plugins'][] = '    RewriteCond %{REQUEST_URI} !/elderward/recovery\.php$';
            $rules['plugins'][] = '    RewriteRule ' . self::PHP_EXT . ' - [NC,F]';
            $rules['plugins'][] = '</IfModule>';
        }
        return $rules;
    }

    /**
     * The Nginx configuration for the chosen features, ready to include
     * inside the site's server { } block.
     */
    public static function nginx_rules(array $features)
    {
        $on = array_flip(self::clean_features($features));
        $home = self::url_path(home_url('/'));
        $uploads = self::uploads();
        $uploads_path = self::url_path($uploads['url']);
        $includes = self::url_path(includes_url('/'));
        $admin = self::url_path(admin_url('/'));
        $content = self::url_path(content_url('/'));
        $q = function ($path) {
            return preg_quote($path, null);
        };
        $php = self::PHP_EXT;

        $lines = array(
            '# Elderward hardening for ' . home_url('/'),
            '# Generated ' . gmdate('Y-m-d H:i') . ' UTC. Include it inside the site\'s server { } block,',
            '# above the "location ~ \.php$" block, then run: nginx -t && systemctl reload nginx',
            '',
        );
        if (isset($on['config'])) {
            $lines[] = '# Protect wp-config.php and any copy of it.';
            $lines[] = 'location ~* ^' . $q($home) . '/wp-config { deny all; }';
        }
        if (isset($on['sensitive'])) {
            $lines[] = '# Backups, dumps, logs, server settings and version-revealing files.';
            $lines[] = 'location ~* (?:\.(?:bak|old|orig|save|swp|swo|sql|log|ini|sh)|~)$ { deny all; }';
            $lines[] = 'location ~* ^' . $q($home) . '/(?:readme\.html|license\.txt|error_log)$ { deny all; }';
        }
        if (isset($on['dotfiles'])) {
            $lines[] = '# Hidden files and folders (.git, .env, ...), except .well-known.';
            $lines[] = 'location ~ /\.(?!well-known(?:/|$)) { deny all; }';
        }
        if (isset($on['xmlrpc'])) {
            $lines[] = '# XML-RPC.';
            $lines[] = 'location = ' . $home . '/xmlrpc.php { deny all; }';
        }
        if (isset($on['uploads_php'])) {
            $lines[] = '# No PHP runs from uploads.';
            $lines[] = 'location ~* ^' . $q($uploads_path) . '/.*' . $php . ' { deny all; }';
        }
        if (isset($on['core_includes'])) {
            $lines[] = '# WordPress loads these files itself; browsers never need them.';
            $lines[] = 'location ^~ ' . $admin . '/includes/ { deny all; }';
            $lines[] = 'location ~* ^' . $q($includes) . '/(?!js/tinymce/wp-tinymce\.php$|ms-files\.php$).*' . $php . ' { deny all; }';
        }
        if (isset($on['themes_php'])) {
            $lines[] = '# Theme PHP is loaded by WordPress, never requested directly.';
            $lines[] = 'location ~* ^' . $q($content) . '/themes/.*' . $php . ' { deny all; }';
        }
        if (isset($on['plugins_php'])) {
            $lines[] = '# Plugin PHP is loaded by WordPress; Elderward\'s recovery page stays reachable.';
            $lines[] = 'location ~* ^' . $q($content) . '/plugins/(?!elderward/recovery\.php$).*' . $php . ' { deny all; }';
        }
        if (isset($on['indexes'])) {
            $lines[] = '# No folder listings.';
            $lines[] = 'autoindex off;';
        }
        if (isset($on['headers'])) {
            $lines[] = '# Security headers. Nginx drops these in any location that sets its own add_header.';
            $lines[] = 'add_header X-Content-Type-Options "nosniff" always;';
            $lines[] = 'add_header X-Frame-Options "SAMEORIGIN" always;';
            $lines[] = 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;';
        }
        if (4 === count($lines)) {
            $lines[] = '# No protection selected.';
        }
        return implode("\n", $lines) . "\n";
    }

    /**
     * What applying would write: file => lines, for the preview.
     */
    public static function apache_preview(array $features)
    {
        $targets = self::apache_targets();
        $out = array();
        foreach (self::apache_rules($features) as $role => $lines) {
            if (!empty($lines)) {
                $out[$targets[$role]] = $lines;
            }
        }
        return $out;
    }

    ////////////////
    // Applying (Apache / LiteSpeed).
    //////////////

    /**
     * Write the Elderward blocks for these features (and remove them where
     * no longer wanted), then check the site; on failure put every file
     * back. Returns a report.
     *
     * @return array{ok:bool, files:array, rolled_back:bool, health:array, message:string}
     */
    public static function apply(array $features)
    {
        $features = self::clean_features($features);
        $state = self::state();
        $targets = self::apache_targets();
        $rules = self::apache_rules($features);
        $report = array('ok' => true, 'files' => array(), 'rolled_back' => false, 'health' => array(), 'message' => '');

        // Refuse up front if a file that needs writing cannot be written,
        // so nothing is half applied.
        foreach ($targets as $role => $file) {
            $needed = !empty($rules[$role]) || self::has_block($file);
            if ($needed && !self::writable($file)) {
                $report['ok'] = false;
                /* translators: %s: file path */
                $report['message'] = sprintf(__('%s cannot be written by PHP, so nothing was changed. Fix its permissions or add the rules by hand.', 'elderward'), $file);
                return $report;
            }
        }

        $before = self::health();
        $originals = array();
        foreach ($targets as $role => $file) {
            $wanted = $rules[$role];
            if (empty($wanted) && !self::has_block($file)) {
                continue;
            }
            $existed = file_exists($file);
            $originals[$file] = $existed ? (string) file_get_contents($file) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file, kept to restore it.
            $ok = self::write_block($file, $wanted);
            $report['files'][] = array('file' => $file, 'action' => empty($wanted) ? 'removed' : ($existed ? 'updated' : 'created'), 'ok' => $ok);
            if (!$ok) {
                $report['ok'] = false;
            }
            if (!$existed && !empty($wanted)) {
                $state['files'][$file] = 'created';
            } elseif (!isset($state['files'][$file])) {
                $state['files'][$file] = 'existing';
            }
        }

        $after = self::health();
        $report['health'] = array('before' => $before, 'after' => $after);
        if (!$report['ok'] || self::broke($before, $after)) {
            self::restore($originals);
            $report['ok'] = false;
            $report['rolled_back'] = true;
            $report['message'] = __('The site stopped responding normally after the change (or a file could not be written), so every file was put back as it was. Your server probably does not allow one of these rules in .htaccess; try again without "Turn off folder listings" or "Add security headers".', 'elderward');
            return $report;
        }

        $state['applied'] = $features;
        $state['time'] = time();
        $state['user'] = get_current_user_id();
        self::save_state($state);
        return $report;
    }

    /**
     * Remove every Elderward block (and delete the files Elderward created
     * that hold nothing else).
     */
    public static function remove()
    {
        $report = self::apply(array());
        if ($report['ok']) {
            $state = self::state();
            $state['applied'] = array();
            $state['files'] = array();
            self::save_state($state);
        }
        return $report;
    }

    private static function writable($file)
    {
        return file_exists($file) ? wp_is_writable($file) : wp_is_writable(dirname($file));
    }

    public static function has_block($file)
    {
        if (!is_readable($file)) {
            return false;
        }
        $content = (string) file_get_contents($file); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
        return false !== strpos($content, '# BEGIN ' . self::MARKER);
    }

    /**
     * Elderward's block in one file. An empty list removes the block, and
     * the file too when nothing else is left in it.
     */
    private static function write_block($file, array $lines)
    {
        if (!function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
        if (!empty($lines)) {
            return (bool) insert_with_markers($file, self::MARKER, $lines);
        }
        if (!file_exists($file)) {
            return true;
        }
        $content = (string) file_get_contents($file); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
        $pattern = '/\n?# BEGIN ' . self::MARKER . '\r?\n.*?# END ' . self::MARKER . '\r?\n?/s';
        // The newline before the block is the one insert_with_markers()
        // added: taking it with the block leaves the file as it was.
        $stripped = preg_replace($pattern, '', $content);
        if (null === $stripped) {
            return false;
        }
        if ('' === trim($stripped)) {
            return wp_delete_file_from_directory($file, dirname($file)) || !file_exists($file);
        }
        return false !== file_put_contents($file, $stripped, LOCK_EX); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- .htaccess files must be written in place, like insert_with_markers() does.
    }

    private static function restore(array $originals)
    {
        foreach ($originals as $file => $content) {
            if (null === $content) {
                if (file_exists($file)) {
                    wp_delete_file($file);
                }
                continue;
            }
            file_put_contents($file, $content, LOCK_EX); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- puts back the file as it was before.
        }
    }

    /**
     * Status codes of the home page, a login page and an admin request:
     * the pages a broken .htaccess turns into 500 errors.
     */
    private static function health()
    {
        $out = array();
        foreach (array('home' => home_url('/'), 'login' => wp_login_url(), 'ajax' => admin_url('admin-ajax.php')) as $key => $url) {
            $out[$key] = self::status($url);
        }
        return $out;
    }

    private static function broke(array $before, array $after)
    {
        foreach ($after as $key => $code) {
            $was = isset($before[$key]) ? $before[$key] : 0;
            if ($code >= 500 && $was < 500) {
                return true;
            }
            // A page that answered before and no longer answers at all.
            if (0 === $code && $was > 0) {
                return true;
            }
        }
        return false;
    }

    private static function request($url)
    {
        return wp_remote_get($url, array(
            'timeout'     => 10,
            'redirection' => 0,
            'user-agent'  => 'Elderward/' . ELDERWARD_VERSION . ' hardening check',
            'headers'     => array('Cache-Control' => 'no-cache'),
        ));
    }

    private static function status($url)
    {
        $response = self::request($url);
        return is_wp_error($response) ? 0 : (int) wp_remote_retrieve_response_code($response);
    }

    ////////////////
    // Checking what the live site enforces (any server).
    //////////////

    /**
     * Ask the site for things each protection should block. Works the same
     * for Apache and Nginx, and for rules added by hand.
     *
     * @return array feature id => array(status => protected|exposed|unknown, detail)
     */
    public static function check()
    {
        $token = strtolower(wp_generate_password(10, false, false));
        $probe = 'elderward-check-' . $token;
        $uploads = self::uploads();
        $home = trailingslashit(home_url());
        $results = array();

        // A request for a file that does not exist reaches WordPress (404)
        // unless a rule refuses it first (403): no file is created.
        $denied = function ($url) {
            return 403 === self::status($url);
        };
        $refused = function ($url, array &$codes) {
            $code = self::status($url);
            $codes[] = $code;
            return in_array($code, array(401, 403, 404, 410), true) ? true : (0 === $code ? null : false);
        };
        $verdict = function ($ok, $yes, $no) {
            if (null === $ok) {
                return array('status' => 'unknown', 'detail' => __('The site did not answer the test request.', 'elderward'));
            }
            return $ok ? array('status' => 'protected', 'detail' => $yes) : array('status' => 'exposed', 'detail' => $no);
        };
        $reachable = 0 !== self::status($home);
        if (!$reachable) {
            foreach (array_keys(self::features()) as $id) {
                $results[$id] = array('status' => 'unknown', 'detail' => __('This site could not reach itself over HTTP, so nothing could be checked. Tools > Site Health reports this as a loopback problem.', 'elderward'));
            }
            return $results;
        }

        $results['uploads_php'] = $verdict($denied($uploads['url'] . '/' . $probe . '.php'), __('PHP requests in uploads are refused.', 'elderward'), __('A PHP file in uploads would run.', 'elderward'));
        $results['core_includes'] = $verdict($denied(includes_url($probe . '.php')) && $denied(admin_url('includes/' . $probe . '.php')), __('wp-includes and wp-admin/includes refuse direct PHP requests.', 'elderward'), __('PHP files in wp-includes or wp-admin/includes can be requested directly.', 'elderward'));
        $codes = array();
        $results['config'] = $verdict($refused($home . 'wp-config.php', $codes), __('wp-config.php cannot be requested.', 'elderward'), __('wp-config.php answers requests (a copy such as wp-config.php.bak would be downloadable).', 'elderward'));
        $results['sensitive'] = $verdict($denied($home . $probe . '.sql') && $denied($home . $probe . '.log'), __('Backup, dump and log files are refused.', 'elderward'), __('Files such as .sql dumps, .bak copies and logs would be downloadable.', 'elderward'));
        $results['dotfiles'] = $verdict($denied($home . '.' . $probe) && $denied($home . '.' . $probe . '/config'), __('Hidden files and folders are refused.', 'elderward'), __('Hidden files and folders such as .git or .env would be downloadable.', 'elderward'));
        $codes = array();
        $results['xmlrpc'] = $verdict($refused($home . 'xmlrpc.php', $codes), __('xmlrpc.php is refused.', 'elderward'), __('xmlrpc.php answers requests.', 'elderward'));
        $results['themes_php'] = $verdict($denied(get_theme_root_uri() . '/' . $probe . '.php'), __('Direct PHP requests in themes are refused.', 'elderward'), __('PHP files in themes can be requested directly.', 'elderward'));
        $results['plugins_php'] = $verdict($denied(plugins_url($probe . '.php')), __('Direct PHP requests in plugins are refused.', 'elderward'), __('PHP files in plugins can be requested directly.', 'elderward'));

        $listing = self::request($uploads['url'] . '/');
        if (is_wp_error($listing)) {
            $results['indexes'] = $verdict(null, '', '');
        } else {
            $body = (string) wp_remote_retrieve_body($listing);
            $listed = 200 === (int) wp_remote_retrieve_response_code($listing) && 1 === preg_match('/<title>\s*Index of|<h1>\s*Index of/i', $body);
            $results['indexes'] = $verdict(!$listed, __('The uploads folder is not listed.', 'elderward'), __('The uploads folder lists its files.', 'elderward'));
        }

        $page = self::request($home);
        if (is_wp_error($page)) {
            $results['headers'] = $verdict(null, '', '');
        } else {
            $missing = array();
            foreach (array('x-content-type-options', 'x-frame-options', 'referrer-policy') as $header) {
                if ('' === (string) wp_remote_retrieve_header($page, $header)) {
                    $missing[] = $header;
                }
            }
            /* translators: %s: list of HTTP header names */
            $results['headers'] = $verdict(empty($missing), __('All three security headers are sent.', 'elderward'), sprintf(__('Missing: %s.', 'elderward'), implode(', ', $missing)));
        }

        $state = self::state();
        $state['checked'] = array('time' => time(), 'results' => $results);
        self::save_state($state);
        return $results;
    }

    /**
     * Uninstall: take Elderward's blocks out of every file it wrote to.
     */
    public static function uninstall()
    {
        $state = self::state();
        foreach (array_keys((array) $state['files']) as $file) {
            if (self::has_block($file)) {
                self::write_block($file, array());
            }
        }
        foreach (self::apache_targets() as $file) {
            if (self::has_block($file)) {
                self::write_block($file, array());
            }
        }
    }
}
