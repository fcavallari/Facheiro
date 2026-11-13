<?php
/**
 * The Hardening tab: pick the web server, a template or individual
 * protections, preview the exact rules, then apply them (Apache/LiteSpeed)
 * or download the configuration file (Nginx), and check what the live site
 * enforces.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Admin_Hardening
{
    const NONCE = 'facheiro_hardening';

    public static function init()
    {
        add_action('admin_post_facheiro_harden', array(__CLASS__, 'action'));
        add_action('wp_ajax_facheiro_harden_preview', array(__CLASS__, 'ajax_preview'));
        add_action('wp_ajax_facheiro_harden_check', array(__CLASS__, 'ajax_check'));
    }

    public static function url()
    {
        return add_query_arg('tab', 'hardening', Facheiro_Admin::page_url());
    }

    /**
     * Server, template and features from a request, cleaned.
     */
    private static function choices()
    {
        // phpcs:disable WordPress.Security.NonceVerification -- callers verify the nonce first.
        $server = isset($_POST['server']) ? sanitize_key(wp_unslash($_POST['server'])) : 'apache';
        $preset = isset($_POST['preset']) ? sanitize_key(wp_unslash($_POST['preset'])) : 'custom';
        $features = isset($_POST['features']) && is_array($_POST['features']) ? array_map('sanitize_key', wp_unslash($_POST['features'])) : array();
        // phpcs:enable WordPress.Security.NonceVerification
        if (!array_key_exists($server, Facheiro_Hardening::servers())) {
            $server = 'apache';
        }
        if (!array_key_exists($preset, Facheiro_Hardening::presets())) {
            $preset = 'custom';
        }
        return array($server, $preset, Facheiro_Hardening::clean_features($features));
    }

    private static function require_access()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
    }

    /**
     * Form target: apply, remove, or download the Nginx file.
     */
    public static function action()
    {
        self::require_access();
        check_admin_referer(self::NONCE);
        list($server, $preset, $features) = self::choices();
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        Facheiro_Hardening::remember($server, $preset, $features);

        if ('download' === $op) {
            nocache_headers();
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="facheiro-nginx.conf"');
            header('X-Content-Type-Options: nosniff');
            echo Facheiro_Hardening::nginx_rules($features); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain-text configuration download.
            exit;
        }

        $notices = array();
        if ('apply' === $op || 'remove' === $op) {
            if ('apache' !== $server) {
                $notices[] = array('error', __('O Facheiro só escreve regras para Apache ou LiteSpeed. Para Nginx, baixe o arquivo de configuração.', 'facheiro'));
            } else {
                // Only honoured when the administrator ticked it on the form
                // this request's nonce came from.
                $unverified = !empty($_POST['unverified']);
                $report = 'remove' === $op ? Facheiro_Hardening::remove() : Facheiro_Hardening::apply($features, $unverified);
                $notices = self::report_notices($report, $op);
            }
        }
        if (empty($notices)) {
            $notices[] = array('success', __('Escolhas salvas.', 'facheiro'));
        }
        Facheiro_Admin::notify($notices);
        wp_safe_redirect(self::url());
        exit;
    }

    private static function report_notices(array $report, $op)
    {
        $notices = array();
        if (!$report['ok']) {
            $notices[] = array('error', '' !== $report['message'] ? $report['message'] : __('Não foi possível gravar as regras, então nada foi alterado.', 'facheiro'));
            return $notices;
        }
        $changed = array();
        foreach ($report['files'] as $file) {
            $changed[] = Facheiro_Plugin::relative_path($file['file']) . ' (' . self::action_word($file['action']) . ')';
        }
        if (empty($changed)) {
            $notices[] = array('info', 'remove' === $op ? __('Não havia regras do Facheiro para remover.', 'facheiro') : __('Nada a alterar.', 'facheiro'));
            return $notices;
        }
        if (empty($report['verified'])) {
            // The site could not be reached from itself: nothing proves it
            // still works, so say so instead of claiming it does.
            $notices[] = array('warning', ('remove' === $op
                ? __('Regras do Facheiro removidas, mas este site não consegue acessar a si mesmo por HTTP, então o Facheiro não pôde verificar se ele continua funcionando.', 'facheiro')
                : __('Proteções gravadas, mas este site não consegue acessar a si mesmo por HTTP, então o Facheiro não pôde verificar se ele continua funcionando nem desfazer sozinho uma quebra. Abra o site em uma nova aba agora; se aparecer um erro, clique em "Remover regras do Facheiro" ou apague, por FTP, as linhas entre "# BEGIN Facheiro" e "# END Facheiro".', 'facheiro')) . ' ' . implode(', ', $changed) . '.');
            return $notices;
        }
        $notices[] = array('success', ('remove' === $op
            ? __('Regras do Facheiro removidas. O site continua respondendo normalmente.', 'facheiro')
            : __('Proteções aplicadas. O site continua respondendo normalmente.', 'facheiro')) . ' ' . implode(', ', $changed) . '.');
        if ('apply' === $op) {
            $notices[] = array('info', __('Use "Verificar agora", abaixo, para confirmar que o servidor aplica cada regra.', 'facheiro'));
        }
        return $notices;
    }

    private static function action_word($action)
    {
        switch ($action) {
            case 'created':
                return __('criado', 'facheiro');
            case 'removed':
                return __('regras removidas', 'facheiro');
        }
        return __('atualizado', 'facheiro');
    }

    public static function ajax_preview()
    {
        check_ajax_referer(self::NONCE, 'nonce');
        if (!Facheiro_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('Você não tem permissão para fazer isso.', 'facheiro')), 403);
        }
        list($server, , $features) = self::choices();
        wp_send_json_success(self::preview($server, $features));
    }

    public static function ajax_check()
    {
        check_ajax_referer(self::NONCE, 'nonce');
        if (!Facheiro_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('Você não tem permissão para fazer isso.', 'facheiro')), 403);
        }
        $results = Facheiro_Hardening::check();
        $labels = array();
        foreach (Facheiro_Hardening::features() as $id => $feature) {
            $labels[$id] = $feature['label'];
        }
        wp_send_json_success(array('results' => $results, 'labels' => $labels));
    }

    /**
     * Files and their contents for the preview.
     */
    private static function preview($server, array $features)
    {
        if ('nginx' === $server) {
            return array(array('file' => 'facheiro-nginx.conf', 'content' => Facheiro_Hardening::nginx_rules($features)));
        }
        $out = array();
        foreach (Facheiro_Hardening::apache_preview($features) as $file => $lines) {
            $out[] = array(
                'file'    => Facheiro_Plugin::relative_path($file),
                'content' => "# BEGIN Facheiro\n" . implode("\n", $lines) . "\n# END Facheiro\n",
            );
        }
        if (empty($out)) {
            $out[] = array('file' => '', 'content' => __('Nenhuma proteção selecionada: aplicar remove todas as regras do Facheiro.', 'facheiro'));
        }
        return $out;
    }

    public static function render()
    {
        $state = Facheiro_Hardening::state();
        $detected = Facheiro_Hardening::detect_server();
        $features = Facheiro_Hardening::features();
        $checked = isset($state['checked']['results']) ? Facheiro_Hardening::describe_all((array) $state['checked']['results']) : array();
        $datetime_format = get_option('date_format') . ' ' . get_option('time_format');
        $status_words = array(
            'protected' => __('Protegido', 'facheiro'),
            'exposed'   => __('Desprotegido', 'facheiro'),
            'unknown'   => __('Não verificado', 'facheiro'),
        );
        ?>
        <p class="facheiro-intro"><?php esc_html_e('A blindagem faz o servidor web recusar o que ele nunca deveria entregar: PHP largado na pasta de uploads, cópias do wp-config.php, pastas .git, arquivos internos do WordPress. Ela não remove malware, mas impede muitos ataques e não deixa um web shell plantado ser executado.', 'facheiro'); ?></p>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" id="facheiro-harden-form" data-nonce="<?php echo esc_attr(wp_create_nonce(self::NONCE)); ?>">
            <input type="hidden" name="action" value="facheiro_harden" />
            <?php wp_nonce_field(self::NONCE); ?>

            <div class="facheiro-card">
                <div class="facheiro-card-head">
                    <h2><span class="facheiro-step">1</span> <?php esc_html_e('Seu servidor web', 'facheiro'); ?> <?php Facheiro_Admin::help_button('facheiro-help-server'); ?></h2>
                </div>
                <?php
                Facheiro_Admin::help_text('facheiro-help-server', array(
                    __('Apache e LiteSpeed leem regras de arquivos .htaccess dentro das pastas do site, então o Facheiro pode escrevê-las por você. O Nginx lê a configuração só dos arquivos do próprio servidor, que o PHP não pode (nem deve) alterar: o Facheiro entrega um arquivo para você incluir nela.', 'facheiro'),
                    __('Não tem certeza? A maioria das hospedagens compartilhadas usa Apache ou LiteSpeed. A documentação ou o suporte da sua hospedagem sabe dizer.', 'facheiro'),
                ));
                ?>
                <div class="facheiro-choice-row" role="radiogroup" aria-label="<?php esc_attr_e('Servidor web', 'facheiro'); ?>">
                    <?php foreach (Facheiro_Hardening::servers() as $value => $label) : ?>
                        <label class="facheiro-choice">
                            <input type="radio" name="server" value="<?php echo esc_attr($value); ?>" <?php checked($state['server'], $value); ?> />
                            <span><?php echo esc_html($label); ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
                <p class="description">
                    <?php
                    if (null === $detected) {
                        esc_html_e('O Facheiro não conseguiu identificar o servidor deste site.', 'facheiro');
                    } else {
                        /* translators: %s: web server name */
                        printf(esc_html__('Este site parece rodar em %s.', 'facheiro'), '<strong>' . esc_html('nginx' === $detected ? 'Nginx' : 'Apache / LiteSpeed') . '</strong>');
                    }
                    ?>
                </p>
            </div>

            <div class="facheiro-card">
                <div class="facheiro-card-head">
                    <h2><span class="facheiro-step">2</span> <?php esc_html_e('Escolha as proteções', 'facheiro'); ?></h2>
                </div>
                <div class="facheiro-choice-row" role="radiogroup" aria-label="<?php esc_attr_e('Modelo', 'facheiro'); ?>">
                    <?php foreach (Facheiro_Hardening::presets() as $value => $label) : ?>
                        <label class="facheiro-choice">
                            <input type="radio" name="preset" value="<?php echo esc_attr($value); ?>" <?php checked($state['preset'], $value); ?> data-features="<?php echo esc_attr(wp_json_encode('custom' === $value ? null : Facheiro_Hardening::preset_features($value))); ?>" />
                            <span><?php echo esc_html($label); ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
                <p class="description"><?php esc_html_e('O Recomendado é seguro para quase todos os sites. O Rigoroso acrescenta proteções que podem quebrar alguns temas e integrações. Mude qualquer chave para montar sua própria seleção.', 'facheiro'); ?></p>

                <ul class="facheiro-features">
                    <?php foreach ($features as $id => $feature) : ?>
                        <?php $on = in_array($id, $state['features'], true); ?>
                        <li class="facheiro-feature">
                            <label class="facheiro-switch">
                                <input type="checkbox" name="features[]" value="<?php echo esc_attr($id); ?>" <?php checked($on); ?> />
                                <span class="facheiro-switch-track" aria-hidden="true"></span>
                                <span class="facheiro-feature-name"><?php echo esc_html($feature['label']); ?></span>
                            </label>
                            <span class="facheiro-feature-tags">
                                <?php if (in_array('recommended', $feature['presets'], true)) : ?>
                                    <span class="facheiro-tag"><?php esc_html_e('Recomendado', 'facheiro'); ?></span>
                                <?php elseif (in_array('strict', $feature['presets'], true)) : ?>
                                    <span class="facheiro-tag facheiro-tag-strict"><?php esc_html_e('Rigoroso', 'facheiro'); ?></span>
                                <?php else : ?>
                                    <span class="facheiro-tag facheiro-tag-risky"><?php esc_html_e('Teste com cuidado', 'facheiro'); ?></span>
                                <?php endif; ?>
                                <?php if (isset($checked[$id])) : ?>
                                    <span class="facheiro-check facheiro-check-<?php echo esc_attr($checked[$id]['status']); ?>" data-feature="<?php echo esc_attr($id); ?>"><?php echo esc_html($status_words[$checked[$id]['status']]); ?></span>
                                <?php else : ?>
                                    <span class="facheiro-check" data-feature="<?php echo esc_attr($id); ?>" hidden></span>
                                <?php endif; ?>
                            </span>
                            <p class="facheiro-feature-help"><?php echo esc_html($feature['help']); ?></p>
                            <p class="facheiro-feature-risk"><strong><?php esc_html_e('Pode quebrar:', 'facheiro'); ?></strong> <?php echo esc_html($feature['risk']); ?></p>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>

            <div class="facheiro-card">
                <div class="facheiro-card-head">
                    <h2><span class="facheiro-step">3</span> <?php esc_html_e('Revisar e aplicar', 'facheiro'); ?></h2>
                </div>
                <div data-server-only="apache">
                    <p><?php esc_html_e('O Facheiro coloca estas regras entre as linhas "# BEGIN Facheiro" e "# END Facheiro" e não mexe no resto de cada arquivo. Ele verifica o site antes e depois e, se o site deixar de responder normalmente, devolve cada arquivo ao que era.', 'facheiro'); ?></p>
                    <?php if (!empty($state['applied'])) : ?>
                        <p class="description">
                            <?php
                            $user = get_userdata((int) $state['user']);
                            printf(
                                /* translators: 1: number of protections, 2: user name, 3: date and time */
                                esc_html__('%1$d proteções aplicadas por %2$s em %3$s.', 'facheiro'),
                                (int) count($state['applied']),
                                esc_html($user ? $user->display_name : __('um usuário excluído', 'facheiro')),
                                esc_html(wp_date($datetime_format, (int) $state['time']))
                            );
                            ?>
                        </p>
                    <?php endif; ?>
                    <?php if (!empty($state['unverifiable'])) : ?>
                        <p><label><input type="checkbox" name="unverified" value="1" /> <strong><?php esc_html_e('Aplicar sem a verificação de segurança', 'facheiro'); ?></strong></label></p>
                        <p class="description"><?php esc_html_e('Este site não consegue acessar a si mesmo por HTTP, então o Facheiro não pode verificá-lo depois de gravar as regras. Se o servidor recusar alguma delas, o site inteiro, inclusive esta página, mostrará um erro até que você apague as linhas entre "# BEGIN Facheiro" e "# END Facheiro" nos arquivos .htaccess, por FTP ou pelo gerenciador de arquivos da hospedagem.', 'facheiro'); ?></p>
                    <?php endif; ?>
                </div>
                <div data-server-only="nginx">
                    <ol class="facheiro-steps">
                        <li><?php esc_html_e('Baixe o arquivo abaixo e coloque-o no servidor, por exemplo como /etc/nginx/snippets/facheiro.conf.', 'facheiro'); ?></li>
                        <li><?php esc_html_e('Dentro do bloco server { } deste site, adicione a linha include snippets/facheiro.conf; acima do bloco que entrega os arquivos .php ao PHP (location ~ \\.php$).', 'facheiro'); ?></li>
                        <li><?php esc_html_e('Rode nginx -t para testar a configuração e depois recarregue o Nginx (systemctl reload nginx).', 'facheiro'); ?></li>
                        <li><?php esc_html_e('Volte aqui e use "Verificar agora" para confirmar.', 'facheiro'); ?></li>
                    </ol>
                    <p class="description"><?php esc_html_e('Em hospedagem gerenciada sem acesso ao servidor, envie o arquivo ao suporte da hospedagem e peça para incluí-lo.', 'facheiro'); ?></p>
                </div>
                <div id="facheiro-harden-preview" class="facheiro-preview" aria-live="polite"></div>
                <p class="facheiro-buttons">
                    <button type="submit" name="op" value="apply" class="button button-primary" data-server-only="apache" data-confirm="harden-apply"><?php esc_html_e('Aplicar proteções', 'facheiro'); ?></button>
                    <?php if (!empty($state['applied']) || !empty($state['files'])) : ?>
                        <button type="submit" name="op" value="remove" class="button" data-server-only="apache" data-confirm="harden-remove"><?php esc_html_e('Remover regras do Facheiro', 'facheiro'); ?></button>
                    <?php endif; ?>
                    <button type="submit" name="op" value="download" class="button button-primary" data-server-only="nginx"><?php esc_html_e('Baixar a configuração do Nginx', 'facheiro'); ?></button>
                    <button type="button" class="button" data-server-only="nginx" id="facheiro-harden-copy"><?php esc_html_e('Copiar', 'facheiro'); ?></button>
                </p>
            </div>
        </form>

        <div class="facheiro-card" id="facheiro-harden-check">
            <div class="facheiro-card-head">
                <h2><span class="facheiro-step">4</span> <?php esc_html_e('Verificar o site no ar', 'facheiro'); ?> <?php Facheiro_Admin::help_button('facheiro-help-check'); ?></h2>
                <div class="facheiro-head-actions">
                    <button type="button" class="button" id="facheiro-harden-check-run"><?php esc_html_e('Verificar agora', 'facheiro'); ?></button>
                </div>
            </div>
            <?php
            Facheiro_Admin::help_text('facheiro-help-check', array(
                __('O Facheiro envia requisições de teste inofensivas a este site, como o pedido de um arquivo PHP inexistente na pasta de uploads, e observa a resposta do servidor. Uma recusa significa que a regra funciona. Nada é criado no site.', 'facheiro'),
                __('Funciona não importa quem tenha adicionado as regras, então use depois de incluir o arquivo do Nginx ou editar o .htaccess à mão. Um firewall ou CDN na frente do site pode fazer uma proteção parecer ativa quando a recusa vem do firewall.', 'facheiro'),
            ));
            ?>
            <p class="description" id="facheiro-harden-check-when">
                <?php
                if (isset($state['checked']['time'])) {
                    /* translators: %s: date and time */
                    printf(esc_html__('Última verificação: %s. O resultado de cada proteção aparece ao lado da chave dela, acima.', 'facheiro'), esc_html(wp_date($datetime_format, (int) $state['checked']['time'])));
                } else {
                    esc_html_e('Ainda não verificado.', 'facheiro');
                }
                ?>
            </p>
            <ul class="facheiro-check-list" id="facheiro-harden-check-list">
                <?php foreach ($checked as $id => $result) : ?>
                    <?php if (!isset($features[$id])) { continue; } ?>
                    <li><span class="facheiro-check facheiro-check-<?php echo esc_attr($result['status']); ?>"><?php echo esc_html($status_words[$result['status']]); ?></span> <strong><?php echo esc_html($features[$id]['label']); ?></strong> <?php echo esc_html($result['detail']); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php
    }

    /**
     * Strings for admin.js.
     */
    public static function i18n()
    {
        return array(
            'hardenApply'   => __('Gravar estas regras nos arquivos .htaccess mostrados? O Facheiro verifica o site em seguida e desfaz a alteração se o site parar de funcionar.', 'facheiro'),
            'hardenRemove'  => __('Remover todas as regras do Facheiro dos arquivos .htaccess?', 'facheiro'),
            'hardenChecking' => __('Verificando…', 'facheiro'),
            'statusProtected' => __('Protegido', 'facheiro'),
            'statusExposed'   => __('Desprotegido', 'facheiro'),
            'statusUnknown'   => __('Não verificado', 'facheiro'),
            'checkedNow'      => __('Verificado agora. O resultado de cada proteção aparece ao lado da chave dela, acima.', 'facheiro'),
        );
    }
}
