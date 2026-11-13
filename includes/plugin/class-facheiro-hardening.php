<?php
/**
 * Server hardening: rules that stop the web server from running or serving
 * files it never should (PHP dropped into uploads, wp-config backups, .git,
 * WordPress internals), for Apache/LiteSpeed (.htaccess files written here)
 * or Nginx (a configuration file the administrator includes).
 *
 * Writes are limited to Facheiro's own "# BEGIN Facheiro" blocks, made
 * with WordPress's insert_with_markers(). The site is checked before and
 * after: if it starts failing, every file is put back as it was.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Hardening
{
    const OPTION = 'facheiro_hardening';
    const MARKER = 'Facheiro';
    const PHP_EXT = '\.ph(?:p[0-9]?|t|tml|ar|ps)(?:\.|$)';

    /**
     * Every protection: label, explanation, what it can break, and which
     * templates include it.
     */
    public static function features()
    {
        return array(
            'uploads_php'   => array(
                'label'   => __('Bloquear PHP na pasta de uploads', 'facheiro'),
                'help'    => __('Os uploads guardam imagens e documentos. Um arquivo PHP ali é quase sempre um web shell que um invasor conseguiu enviar; isto impede que ele seja executado.', 'facheiro'),
                'risk'    => __('Raramente quebra algo. Alguns plugins mal escritos guardam PHP nos uploads.', 'facheiro'),
                'presets' => array('recommended', 'strict'),
            ),
            'core_includes' => array(
                'label'   => __('Bloquear o acesso direto aos arquivos internos do WordPress', 'facheiro'),
                'help'    => __('Os arquivos de wp-includes e wp-admin/includes são carregados pelo próprio WordPress e nunca precisam ser abertos pelo navegador. Invasores os pedem para sondar fraquezas.', 'facheiro'),
                'risk'    => __('Seguro para o próprio WordPress; os poucos arquivos que precisam continuar acessíveis são liberados.', 'facheiro'),
                'presets' => array('recommended', 'strict'),
            ),
            'config'        => array(
                'label'   => __('Proteger os arquivos wp-config', 'facheiro'),
                'help'    => __('O wp-config.php guarda a senha do banco de dados. Isto também cobre cópias como wp-config.php.bak ou wp-config.old, que de outra forma poderiam ser baixadas como texto puro.', 'facheiro'),
                'risk'    => __('Seguro: nada deveria pedir esses arquivos.', 'facheiro'),
                'presets' => array('recommended', 'strict'),
            ),
            'sensitive'     => array(
                'label'   => __('Bloquear backups, logs e configurações do servidor', 'facheiro'),
                'help'    => __('Impede o download de arquivos como dumps .sql, cópias .bak e .old, backups de editor (~), arquivos .log (incluindo o debug.log), arquivos .ini e scripts de shell, além do readme.html e do license.txt, que revelam a versão do WordPress.', 'facheiro'),
                'risk'    => __('Quebra links para arquivos com essas extensões, se o seu site oferece algum para download.', 'facheiro'),
                'presets' => array('recommended', 'strict'),
            ),
            'dotfiles'      => array(
                'label'   => __('Bloquear arquivos e pastas ocultos', 'facheiro'),
                'help'    => __('Nomes que começam com ponto (.git, .env, .htaccess, .user.ini) muitas vezes guardam senhas, chaves ou todo o histórico do código. A pasta .well-known, usada pelos certificados SSL, continua acessível.', 'facheiro'),
                'risk'    => __('Seguro para quase todos os sites.', 'facheiro'),
                'presets' => array('recommended', 'strict'),
            ),
            'indexes'       => array(
                'label'   => __('Desativar a listagem de pastas', 'facheiro'),
                'help'    => __('Sem um arquivo de índice, alguns servidores listam todos os arquivos de uma pasta (por exemplo, tudo em uploads), o que ajuda invasores a escolher o alvo.', 'facheiro'),
                'risk'    => __('Em algumas hospedagens Apache esta configuração não é permitida no .htaccess e o site mostraria um erro; o Facheiro verifica o site e desfaz a alteração se isso acontecer.', 'facheiro'),
                'presets' => array('recommended', 'strict'),
            ),
            'themes_php'    => array(
                'label'   => __('Bloquear PHP direto nos temas', 'facheiro'),
                'help'    => __('Os arquivos dos temas são carregados pelo WordPress; um pedido direto a um arquivo PHP dentro da pasta de um tema é sinal de ataque ou de arquivo plantado.', 'facheiro'),
                'risk'    => __('Quebra temas antigos que apontam para os próprios arquivos PHP (por exemplo, um gerador de imagens ou de CSS).', 'facheiro'),
                'presets' => array('strict'),
            ),
            'headers'       => array(
                'label'   => __('Adicionar cabeçalhos de segurança', 'facheiro'),
                'help'    => __('X-Content-Type-Options (sem adivinhar o tipo de conteúdo), X-Frame-Options SAMEORIGIN (outros sites não podem exibir o seu em frames, contra clickjacking) e Referrer-Policy (menos informação nos links para outros sites).', 'facheiro'),
                'risk'    => __('Outros sites não poderão mais mostrar suas páginas em um frame.', 'facheiro'),
                'presets' => array('strict'),
            ),
            'xmlrpc'        => array(
                'label'   => __('Desativar o XML-RPC', 'facheiro'),
                'help'    => __('O xmlrpc.php é uma interface antiga de publicação remota e um alvo preferido para adivinhação de senhas e abuso de pingbacks.', 'facheiro'),
                'risk'    => __('Quebra o Jetpack, os aplicativos móveis do WordPress e outras ferramentas que publicam pelo XML-RPC.', 'facheiro'),
                'presets' => array('strict'),
            ),
            'plugins_php'   => array(
                'label'   => __('Bloquear PHP direto nos plugins', 'facheiro'),
                'help'    => __('Como a regra dos temas, para a pasta de plugins. A página de recuperação do Facheiro continua acessível.', 'facheiro'),
                'risk'    => __('Quebra todo plugin que tem um ponto de entrada PHP próprio (alguns retornos de pagamento, ferramentas de imagem, telas de administração antigas). Teste o site com cuidado.', 'facheiro'),
                'presets' => array(),
            ),
        );
    }

    public static function presets()
    {
        return array(
            'recommended' => __('Recomendado', 'facheiro'),
            'strict'      => __('Rigoroso', 'facheiro'),
            'custom'      => __('Personalizado', 'facheiro'),
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
            'apache' => __('Apache ou LiteSpeed (.htaccess)', 'facheiro'),
            'nginx'  => __('Nginx', 'facheiro'),
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
     * The .htaccess files Facheiro manages, by role.
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
     * with no lines gets its Facheiro block removed.
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
            // Not ".well-known" itself: with no such folder on disk, Apache
            // maps /.well-known/webfinger (and every other address WordPress
            // answers there: ActivityPub, security.txt, app links) to a file
            // of that name, and "^\." alone refused them all.
            $rules['root'] = array_merge($rules['root'], self::files_match('^\.(?!well-known$)'));
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
            $rules['plugins'][] = '# Plugin PHP is loaded by WordPress; Facheiro\'s recovery page stays reachable.';
            $rules['plugins'][] = '<IfModule mod_rewrite.c>';
            $rules['plugins'][] = '    RewriteEngine On';
            $rules['plugins'][] = '    RewriteCond %{REQUEST_URI} !/facheiro/recovery\.php$';
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
            '# Facheiro hardening for ' . home_url('/'),
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
            $lines[] = '# Plugin PHP is loaded by WordPress; Facheiro\'s recovery page stays reachable.';
            $lines[] = 'location ~* ^' . $q($content) . '/plugins/(?!facheiro/recovery\.php$).*' . $php . ' { deny all; }';
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
     * Write the Facheiro blocks for these features (and remove them where
     * no longer wanted), then check the site; on failure put every file
     * back. Returns a report.
     *
     * @param array $features   Protections to write.
     * @param bool  $unverified Write even when the site cannot reach itself
     *                          over HTTP, so nothing can be checked or undone
     *                          (the administrator asked for it explicitly).
     * @return array{ok:bool, files:array, rolled_back:bool, health:array, verified:bool, unverifiable:bool, message:string}
     *         verified is false when the site could not be reached to check
     *         it: then nothing proves it still works. unverifiable is true
     *         when that is why nothing was written.
     */
    public static function apply(array $features, $unverified = false)
    {
        $features = self::clean_features($features);
        $state = self::state();
        $targets = self::apache_targets();
        $rules = self::apache_rules($features);
        $report = array('ok' => true, 'files' => array(), 'rolled_back' => false, 'health' => array(), 'verified' => false, 'unverifiable' => false, 'message' => '');

        // Refuse up front if a file that needs writing cannot be written,
        // so nothing is half applied.
        $touched = array();
        foreach ($targets as $role => $file) {
            $needed = !empty($rules[$role]) || self::has_block($file);
            if ($needed && !self::writable($file)) {
                $report['ok'] = false;
                /* translators: %s: file path */
                $report['message'] = sprintf(__('O PHP não consegue gravar %s, então nada foi alterado. Corrija as permissões ou adicione as regras à mão.', 'facheiro'), $file);
                return $report;
            }
            if ($needed) {
                $touched[] = $role;
            }
        }

        $before = self::health($touched);

        ///////////////
        // The check is what makes writing rules safe: a rule the server
        // does not allow in .htaccess answers every request with a 500, the
        // admin pages included, so the warning printed afterwards would
        // never be seen and "Remove" could not be reached. When the site
        // cannot reach itself, new rules are written only if the
        // administrator asked for that in so many words. Taking rules out
        // is always allowed: it is the way back.
        //////////////
        $can_verify = self::verifiable($before);
        if ($can_verify !== empty($state['unverifiable'])) {
            // Remembered so the page can offer the explicit choice.
            $state['unverifiable'] = !$can_verify;
            self::save_state($state);
        }
        if (!$can_verify && !$unverified && !empty($features) && !empty($touched)) {
            $report['ok'] = false;
            $report['unverifiable'] = true;
            $report['message'] = __('Este site não consegue acessar a si mesmo por HTTP, então o Facheiro não poderia verificá-lo depois da alteração nem desfazer uma quebra. Nada foi alterado. Para gravar as regras mesmo assim, marque "Aplicar sem a verificação de segurança" e tenha acesso por FTP ou pelo gerenciador de arquivos à mão, ou adicione manualmente as regras mostradas na prévia.', 'facheiro');
            return $report;
        }

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

        $after = self::health($touched);
        $report['health'] = array('before' => $before, 'after' => $after);
        $report['verified'] = $can_verify;
        if (!$report['ok'] || self::broke($before, $after)) {
            self::restore($originals);
            $report['ok'] = false;
            $report['rolled_back'] = true;
            $report['message'] = __('O site deixou de responder normalmente depois da alteração (ou um arquivo não pôde ser gravado), então cada arquivo voltou a ser como era. Provavelmente seu servidor não permite uma destas regras no .htaccess; tente de novo sem "Desativar a listagem de pastas" ou "Adicionar cabeçalhos de segurança".', 'facheiro');
            return $report;
        }

        $state['applied'] = $features;
        $state['time'] = time();
        $state['user'] = get_current_user_id();
        self::save_state($state);
        return $report;
    }

    /**
     * Remove every Facheiro block (and delete the files Facheiro created
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
     * Facheiro's block in one file. An empty list removes the block, and
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
     * Status codes of the home page, a login page and an admin request (the
     * pages a broken root .htaccess turns into 500 errors), plus one address
     * inside every other folder whose .htaccess is being written: a rule
     * the server refuses there breaks only that folder (every script and
     * style in wp-includes, every image in uploads) while the three pages
     * keep answering. 0 = no answer.
     *
     * @param array $roles Roles from apache_targets() about to be written.
     */
    private static function health(array $roles = array())
    {
        $urls = array('home' => home_url('/'), 'login' => wp_login_url(), 'ajax' => admin_url('admin-ajax.php'));
        $uploads = self::uploads();
        // A real, static file where WordPress guarantees one (it must keep
        // being served); elsewhere a name that does not exist, which still
        // makes the server read that folder's .htaccess.
        $probes = array(
            'uploads'        => $uploads['url'] . '/facheiro-health-check.txt',
            'includes'       => includes_url('css/dashicons.min.css'),
            'admin_includes' => admin_url('includes/facheiro-health-check.txt'),
            'themes'         => get_stylesheet_directory_uri() . '/style.css',
            'plugins'        => plugins_url('assets/admin.css', FACHEIRO_FILE),
        );
        foreach ($roles as $role) {
            if (isset($probes[$role])) {
                $urls[$role] = $probes[$role];
            }
        }
        $out = array();
        foreach (self::fetch_all($urls) as $key => $response) {
            $out[$key] = $response['code'];
        }
        return $out;
    }

    /**
     * Whether health() could see the site at all: on hosts that block
     * requests from the site to itself every code is 0, and a breakage
     * would go unnoticed.
     */
    private static function verifiable(array $before)
    {
        return max(array_map('intval', $before)) > 0;
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
            // A page or file that was served and is now refused or gone
            // (403 where mod_rewrite is not allowed, a rule that catches
            // more than it should): none of these addresses is one a
            // protection is meant to block.
            if ($was >= 200 && $was < 400 && $code >= 400) {
                return true;
            }
        }
        return false;
    }

    /**
     * GET several URLs of this site at once (no redirects, short timeouts).
     * Parallel through the Requests library that ships with WordPress, so a
     * check costs one timeout, not one per URL; sequential through the HTTP
     * API if the library is missing. TLS is verified with WordPress's CA
     * bundle, as wp_remote_get() does.
     *
     * @param array $urls key => URL
     * @return array key => array(code => int (0 = no answer), body => string, headers => array lower-case name => value)
     */
    private static function fetch_all(array $urls)
    {
        $out = array();
        $class = class_exists('\WpOrg\Requests\Requests') ? '\WpOrg\Requests\Requests' : (class_exists('\Requests') ? '\Requests' : null);
        $agent = 'Facheiro/' . FACHEIRO_VERSION . ' hardening check';
        if (null !== $class) {
            $requests = array();
            foreach ($urls as $key => $url) {
                $requests[$key] = array('url' => $url, 'type' => 'GET', 'headers' => array('Cache-Control' => 'no-cache'));
            }
            $responses = call_user_func(array($class, 'request_multiple'), $requests, array(
                'timeout'          => 8,
                'connect_timeout'  => 5,
                'follow_redirects' => false,
                'useragent'        => $agent,
                'verify'           => ABSPATH . WPINC . '/certificates/ca-bundle.crt',
            ));
            foreach ($urls as $key => $url) {
                $response = isset($responses[$key]) ? $responses[$key] : null;
                if (!is_object($response) || !isset($response->status_code) || $response instanceof Exception) {
                    $out[$key] = array('code' => 0, 'body' => '', 'headers' => array());
                    continue;
                }
                $headers = array();
                foreach (array('x-content-type-options', 'x-frame-options', 'referrer-policy') as $name) {
                    $headers[$name] = isset($response->headers[$name]) ? (string) $response->headers[$name] : '';
                }
                $out[$key] = array('code' => (int) $response->status_code, 'body' => (string) $response->body, 'headers' => $headers);
            }
            return $out;
        }
        foreach ($urls as $key => $url) {
            $response = wp_remote_get($url, array('timeout' => 8, 'redirection' => 0, 'user-agent' => $agent, 'headers' => array('Cache-Control' => 'no-cache')));
            if (is_wp_error($response)) {
                $out[$key] = array('code' => 0, 'body' => '', 'headers' => array());
                continue;
            }
            $headers = array();
            foreach (array('x-content-type-options', 'x-frame-options', 'referrer-policy') as $name) {
                $headers[$name] = (string) wp_remote_retrieve_header($response, $name);
            }
            $out[$key] = array('code' => (int) wp_remote_retrieve_response_code($response), 'body' => (string) wp_remote_retrieve_body($response), 'headers' => $headers);
        }
        return $out;
    }

    ////////////////
    // Checking what the live site enforces (any server).
    //////////////

    /**
     * Ask the site for things each protection should block. Works the same
     * for Apache and Nginx, and for rules added by hand. Every probe but
     * xmlrpc.php names a file that does not exist: it reaches WordPress
     * (404) unless a rule refuses it first (403), and nothing is created.
     *
     * @return array feature id => array(status => protected|exposed|unknown, detail)
     */
    public static function check()
    {
        $probe = 'facheiro-check-' . strtolower(wp_generate_password(10, false, false));
        $uploads = self::uploads();
        $home = trailingslashit(home_url());
        $r = self::fetch_all(array(
            'home'           => $home,
            'uploads'        => $uploads['url'] . '/' . $probe . '.php',
            'includes'       => includes_url($probe . '.php'),
            'admin_includes' => admin_url('includes/' . $probe . '.php'),
            // Starts with "wp-config" like every copy the rule must catch,
            // with an extension no other protection covers.
            'config'         => $home . 'wp-config-' . $probe . '.txt',
            'sql'            => $home . $probe . '.sql',
            'log'            => $home . $probe . '.log',
            'dotfile'        => $home . '.' . $probe,
            'dotdir'         => $home . '.' . $probe . '/config',
            'xmlrpc'         => $home . 'xmlrpc.php',
            'themes'         => get_theme_root_uri() . '/' . $probe . '.php',
            'plugins'        => plugins_url($probe . '.php'),
            'listing'        => $uploads['url'] . '/',
        ));
        $results = array();
        if (0 === $r['home']['code']) {
            foreach (array_keys(self::features()) as $id) {
                $results[$id] = array('status' => 'unknown', 'unreachable' => true);
            }
            return self::describe_all($results);
        }

        // Refused = 403; null when a probe got no answer at all.
        $denied = function () use ($r) {
            $all = true;
            foreach (func_get_args() as $key) {
                if (0 === $r[$key]['code']) {
                    return null;
                }
                $all = $all && 403 === $r[$key]['code'];
            }
            return $all;
        };
        $status = function ($ok) {
            return null === $ok ? 'unknown' : ($ok ? 'protected' : 'exposed');
        };

        $xmlrpc = $r['xmlrpc']['code'];
        $results['uploads_php'] = array('status' => $status($denied('uploads')));
        $results['core_includes'] = array('status' => $status($denied('includes', 'admin_includes')));
        $results['config'] = array('status' => $status($denied('config')));
        $results['sensitive'] = array('status' => $status($denied('sql', 'log')));
        $results['dotfiles'] = array('status' => $status($denied('dotfile', 'dotdir')));
        $results['xmlrpc'] = array('status' => $status(0 === $xmlrpc ? null : in_array($xmlrpc, array(401, 403, 404, 410), true)));
        $results['themes_php'] = array('status' => $status($denied('themes')));
        $results['plugins_php'] = array('status' => $status($denied('plugins')));
        if (0 === $r['listing']['code']) {
            $results['indexes'] = array('status' => 'unknown');
        } else {
            $listed = 200 === $r['listing']['code'] && 1 === preg_match('/<title>\s*Index of|<h1>\s*Index of/i', $r['listing']['body']);
            $results['indexes'] = array('status' => $status(!$listed));
        }
        $missing = array();
        foreach ($r['home']['headers'] as $name => $value) {
            if ('' === $value) {
                $missing[] = $name;
            }
        }
        $results['headers'] = array('status' => $status(empty($missing)), 'missing' => $missing);

        // Saved without text, so the page explains it in the reader's
        // language, whoever ran the check.
        $state = self::state();
        $state['checked'] = array('time' => time(), 'results' => $results);
        self::save_state($state);
        return self::describe_all($results);
    }

    /**
     * Add the explanation ('detail') to each check result, in the current
     * language.
     */
    public static function describe_all(array $results)
    {
        foreach ($results as $id => $result) {
            $results[$id]['detail'] = self::describe($id, $result);
        }
        return $results;
    }

    private static function describe($id, array $result)
    {
        $status = isset($result['status']) ? $result['status'] : 'unknown';
        if ('unknown' === $status) {
            return isset($result['unreachable']) ? __('Este site não conseguiu acessar a si mesmo por HTTP, então nada pôde ser verificado. Ferramentas > Saúde do site mostra isso como um problema de loopback.', 'facheiro') : __('O site não respondeu à requisição de teste.', 'facheiro');
        }
        $ok = 'protected' === $status;
        switch ($id) {
            case 'uploads_php':
                return $ok ? __('Requisições de PHP nos uploads são recusadas.', 'facheiro') : __('Um arquivo PHP nos uploads seria executado.', 'facheiro');
            case 'core_includes':
                return $ok ? __('wp-includes e wp-admin/includes recusam requisições diretas de PHP.', 'facheiro') : __('Arquivos PHP em wp-includes ou wp-admin/includes podem ser pedidos diretamente.', 'facheiro');
            case 'config':
                return $ok ? __('Arquivos wp-config e suas cópias são recusados.', 'facheiro') : __('Uma cópia como wp-config.php.bak poderia ser baixada.', 'facheiro');
            case 'sensitive':
                return $ok ? __('Arquivos de backup, dumps e logs são recusados.', 'facheiro') : __('Arquivos como dumps .sql, cópias .bak e logs poderiam ser baixados.', 'facheiro');
            case 'dotfiles':
                return $ok ? __('Arquivos e pastas ocultos são recusados.', 'facheiro') : __('Arquivos e pastas ocultos, como .git ou .env, poderiam ser baixados.', 'facheiro');
            case 'xmlrpc':
                return $ok ? __('O xmlrpc.php é recusado.', 'facheiro') : __('O xmlrpc.php responde a requisições.', 'facheiro');
            case 'themes_php':
                return $ok ? __('Requisições diretas de PHP nos temas são recusadas.', 'facheiro') : __('Arquivos PHP dos temas podem ser pedidos diretamente.', 'facheiro');
            case 'plugins_php':
                return $ok ? __('Requisições diretas de PHP nos plugins são recusadas.', 'facheiro') : __('Arquivos PHP dos plugins podem ser pedidos diretamente.', 'facheiro');
            case 'indexes':
                return $ok ? __('A pasta de uploads não é listada.', 'facheiro') : __('A pasta de uploads lista seus arquivos.', 'facheiro');
            case 'headers':
                /* translators: %s: list of HTTP header names */
                return $ok ? __('Os três cabeçalhos de segurança são enviados.', 'facheiro') : sprintf(__('Faltando: %s.', 'facheiro'), implode(', ', isset($result['missing']) ? (array) $result['missing'] : array()));
        }
        return '';
    }

    /**
     * Uninstall: take Facheiro's blocks out of every file it wrote to.
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
