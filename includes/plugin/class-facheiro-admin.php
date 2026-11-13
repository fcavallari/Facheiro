<?php
/**
 * The Facheiro admin menu: start a report-only scan, watch it progress, read
 * and export the findings.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Admin
{
    const PAGE = 'facheiro';
    const NONCE_SCAN = 'facheiro_scan';
    const NONCE_EXPORT = 'facheiro_export';
    const NONCE_SETTINGS = 'facheiro_settings';
    const NONCE_SAMPLE = 'facheiro_sample_';
    const NONCE_SIGNATURES = 'facheiro_signatures';
    const NONCE_SEAL = 'facheiro_seal';
    const PER_PAGE = 200;
    // Seconds without a saved step after which the page treats the
    // background runner as stalled: it kicks WP-Cron once, then steps from
    // the browser.
    const STALE_SECONDS = 120;

    // Right after Tools (75), before Settings (80).
    const MENU_POSITION = 76;

    private static $hook_suffix = '';

    public static function init()
    {
        if (is_multisite()) {
            add_action('network_admin_menu', array(__CLASS__, 'register_network_menu'));
        } else {
            add_action('admin_menu', array(__CLASS__, 'register_menu'));
        }
        add_action('admin_enqueue_scripts', array(__CLASS__, 'enqueue'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'menu_icon'));
        add_action('admin_init', array(__CLASS__, 'redirect_old_location'));
        add_action('wp_ajax_facheiro_start', array(__CLASS__, 'ajax_start'));
        add_action('wp_ajax_facheiro_step', array(__CLASS__, 'ajax_step'));
        add_action('wp_ajax_facheiro_status', array(__CLASS__, 'ajax_status'));
        add_action('wp_ajax_facheiro_cancel', array(__CLASS__, 'ajax_cancel'));
        add_action('wp_ajax_facheiro_kick', array(__CLASS__, 'ajax_kick'));
        add_action('wp_ajax_facheiro_fp', array(__CLASS__, 'ajax_false_positive'));
        add_action('admin_post_facheiro_export', array(__CLASS__, 'export'));
        add_action('admin_post_facheiro_sample', array(__CLASS__, 'sample'));
        add_action('admin_post_facheiro_signature', array(__CLASS__, 'signature_action'));
        add_action('admin_post_facheiro_signatures_export', array(__CLASS__, 'signatures_export'));
        add_action('wp_ajax_facheiro_sig_test', array(__CLASS__, 'ajax_signature_test'));
        add_action('admin_post_facheiro_seal', array(__CLASS__, 'seal_action'));
        add_action('admin_post_facheiro_save_settings', array(__CLASS__, 'save_settings'));
        Facheiro_Admin_Hardening::init();
        Facheiro_Admin_Recovery::init();
    }

    public static function page_url()
    {
        return is_multisite() ? network_admin_url('admin.php?page=' . self::PAGE) : admin_url('admin.php?page=' . self::PAGE);
    }

    public static function register_menu()
    {
        self::$hook_suffix = add_menu_page(
            __('Facheiro', 'facheiro'),
            __('Facheiro', 'facheiro'),
            'manage_options',
            self::PAGE,
            array(__CLASS__, 'render_page'),
            'none',
            self::MENU_POSITION
        );
        add_action('load-' . self::$hook_suffix, array(__CLASS__, 'add_help'));
    }

    public static function register_network_menu()
    {
        self::$hook_suffix = add_menu_page(
            __('Facheiro', 'facheiro'),
            __('Facheiro', 'facheiro'),
            'manage_network',
            self::PAGE,
            array(__CLASS__, 'render_page'),
            'none',
            self::MENU_POSITION
        );
        add_action('load-' . self::$hook_suffix, array(__CLASS__, 'add_help'));
    }

    /**
     * The screen's Help tab (top right): the whole page explained.
     */
    public static function add_help()
    {
        $screen = get_current_screen();
        if (!$screen) {
            return;
        }
        $tabs = array(
            'facheiro-overview'   => array(__('Visão geral', 'facheiro'), array(
                __('O Facheiro procura neste site malware e sinais de invasão. As varreduras só fazem relatório: nada no site é alterado a partir desta página.', 'facheiro'),
                __('Inicie uma varredura na aba Varredura. Quando ela terminar, os achados aparecem logo abaixo, dos mais graves para os menos graves.', 'facheiro'),
            )),
            'facheiro-findings'   => array(__('Entendendo os achados', 'facheiro'), array(
                __('HIGH: quase certamente malicioso; trate primeiro. MEDIUM: suspeito; confira. LOW: vale saber. INFO: para registro. ERROR: uma verificação não pôde rodar, então essa parte do site está desconhecida, não limpa.', 'facheiro'),
                __('Achados de datas de arquivo e de logs são pistas, não provas. O SHA-256 de um arquivo sinalizado pode ser consultado no VirusTotal; só o hash sai do seu navegador.', 'facheiro'),
                __('"Marcar como falso positivo" esconde, nas próximas varreduras, um achado que você conferiu, com uma nota opcional do motivo. Para arquivos, a marcação só vale enquanto o arquivo continuar exatamente como você o revisou. "Baixar amostra" salva uma cópia protegida por senha (senha: infected) para um analista de malware.', 'facheiro'),
            )),
            'facheiro-settings'   => array(__('Configurações', 'facheiro'), array(
                __('Executar varreduras: em segundo plano (pelo WP-Cron, para você poder sair da página) ou só com a página aberta (se as varreduras em segundo plano nunca terminam na sua hospedagem).', 'facheiro'),
                __('Varreduras automáticas: rodam a mesma varredura diária, duas vezes por dia ou semanalmente. Sempre rodam em segundo plano e são puladas enquanto outra varredura está em andamento.', 'facheiro'),
                __('Logs de acesso: local opcional dos logs do servidor web (um arquivo ou uma pasta, como /var/log/apache2), verificado em toda varredura em busca de tráfego de ataque.', 'facheiro'),
            )),
            'facheiro-signatures' => array(__('Assinaturas', 'facheiro'), array(
                __('Uma assinatura descreve algo a procurar. As assinaturas embutidas vêm com o Facheiro; na aba Assinaturas você pode adicionar as suas para uma ameaça específica deste site, testá-las em um arquivo ou em uma amostra colada e importá-las ou exportá-las.', 'facheiro'),
                __('Assinaturas personalizadas só informam ocorrências. Nunca limpam nem apagam nada.', 'facheiro'),
            )),
            'facheiro-hardening'  => array(__('Blindagem', 'facheiro'), array(
                __('A aba Blindagem adiciona regras ao servidor web que recusam requisições perigosas: PHP nos uploads, cópias do wp-config, arquivos ocultos como .git, arquivos internos do WordPress. Escolha seu servidor, um modelo (Recomendado ou Rigoroso) ou proteções individuais e revise as regras exatas antes de aplicar.', 'facheiro'),
                __('No Apache e no LiteSpeed, o Facheiro grava as regras em arquivos .htaccess, verifica o site em seguida e desfaz a alteração se o site quebrar. No Nginx, baixe o arquivo de configuração e inclua-o na configuração do servidor. "Verificar agora" confirma o que o site no ar realmente aplica.', 'facheiro'),
            )),
            'facheiro-recovery'   => array(__('Recuperação', 'facheiro'), array(
                __('O modo de recuperação faz a varredura do site quando o próprio WordPress não carrega mais (tela branca ou erro fatal), a partir de uma página que não depende do WordPress. Ele é trancado por uma chave que você cria na aba Recuperação, pelo WP-CLI ou enviando um arquivo de chave.', 'facheiro'),
            )),
            'facheiro-assistants' => array(__('Assistentes de IA', 'facheiro'), array(
                __('A aba Assistentes de IA explica como deixar um assistente, como o Claude, rodar varreduras e explicar os achados, pelo plugin MCP Adapter, ou como copiar um resumo para qualquer chat.', 'facheiro'),
            )),
            'facheiro-cleanup'    => array(__('Limpeza', 'facheiro'), array(
                __('A limpeza e a restauração rodam pelo WP-CLI (wp facheiro scan, wp facheiro integrity --restore), onde você pode fazer um backup e conferir cada alteração antes com --dryrun.', 'facheiro'),
            )),
        );
        foreach ($tabs as $id => $tab) {
            $screen->add_help_tab(array(
                'id'      => $id,
                'title'   => $tab[0],
                'content' => '<p>' . implode('</p><p>', array_map('esc_html', $tab[1])) . '</p>',
            ));
        }
        $screen->set_help_sidebar(
            '<p><strong>' . esc_html__('Mais ajuda', 'facheiro') . '</strong></p>'
            . '<p><a href="https://github.com/fcavallari/Facheiro#readme" target="_blank" rel="noopener noreferrer">' . esc_html__('Documentação do Facheiro', 'facheiro') . '</a></p>'
        );
    }

    /**
     * The menu icon is the Facheiro mark, drawn as a CSS mask so it takes
     * the admin colour scheme's colours (normal, hover, current) like the
     * core icons. WordPress's own SVG recolouring only rewrites fills, and
     * the mark is drawn with strokes.
     */
    public static function menu_icon()
    {
        if (!Facheiro_Plugin::can_manage()) {
            return;
        }
        $url = esc_url_raw(FACHEIRO_URL . 'assets/img/facheiro-menu.svg');
        wp_add_inline_style('admin-menu', '#adminmenu .toplevel_page_' . self::PAGE . ' div.wp-menu-image::before {'
            . 'content: ""; display: block; width: 20px; height: 20px; margin: 7px auto 0; padding: 0;'
            . 'background-color: currentColor;'
            . '-webkit-mask: url("' . $url . '") no-repeat center / 20px 20px;'
            . 'mask: url("' . $url . '") no-repeat center / 20px 20px; }');
    }

    /**
     * The page used to live under Tools (Settings in the network admin):
     * old bookmarks land on the new location.
     */
    public static function redirect_old_location()
    {
        global $pagenow;
        if (!isset($_GET['page']) || self::PAGE !== $_GET['page'] || !in_array($pagenow, array('tools.php', 'settings.php'), true)) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only picks where to redirect; nothing is changed.
            return;
        }
        $args = array();
        foreach (array('tab', 'severity', 'view', 'paged', 'edit') as $key) {
            if (isset($_GET[$key])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- carried over to the redirect, then validated by the page.
                $args[$key] = sanitize_text_field(wp_unslash($_GET[$key])); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- see above.
            }
        }
        wp_safe_redirect(add_query_arg($args, self::page_url()));
        exit;
    }

    public static function enqueue($hook_suffix)
    {
        if ($hook_suffix !== self::$hook_suffix) {
            return;
        }
        wp_enqueue_style('facheiro-admin', FACHEIRO_URL . 'assets/admin.css', array(), FACHEIRO_VERSION);
        wp_enqueue_script('facheiro-admin', FACHEIRO_URL . 'assets/admin.js', array(), FACHEIRO_VERSION, true);
        $job = Facheiro_Job::current();
        wp_localize_script('facheiro-admin', 'facheiroAdmin', array(
            'ajaxUrl'    => admin_url('admin-ajax.php'),
            'nonce'      => wp_create_nonce(self::NONCE_SCAN),
            'status'     => null === $job ? '' : $job['status'],
            'background' => null !== $job && !empty($job['background']),
            'stale'      => self::STALE_SECONDS,
            'i18n'       => array_merge(Facheiro_Admin_Hardening::i18n(), Facheiro_Admin_Recovery::i18n(), array(
                'starting'   => __('Iniciando a varredura…', 'facheiro'),
                /* translators: %s: name of the scanner currently running */
                'running'    => __('Verificando: %s', 'facheiro'),
                'done'       => __('Varredura concluída. Recarregando…', 'facheiro'),
                /* translators: %s: error message */
                'failed'     => __('A varredura falhou: %s', 'facheiro'),
                'cancelled'  => __('Varredura cancelada.', 'facheiro'),
                'network'    => __('Perdemos o contato com o servidor; tentando de novo…', 'facheiro'),
                'confirm'    => __('Cancelar a varredura em andamento?', 'facheiro'),
                /* translators: %d: seconds since the background runner last saved progress */
                'idle'       => __('última atividade há %d s', 'facheiro'),
                'background' => __('Rodando em segundo plano: você pode sair desta página e voltar depois.', 'facheiro'),
                'browser'    => __('Mantenha esta página aberta: a varredura roda em pequenas etapas a partir desta aba.', 'facheiro'),
                'fpPrompt'   => __('Marcar este achado como falso positivo? Se quiser, anote o motivo; a nota fica guardada com a decisão.', 'facheiro'),
                'fpMarked'   => __('Marcado como falso positivo. As próximas varreduras o escondem até o arquivo mudar.', 'facheiro'),
                'fpUndo'     => __('Desfazer', 'facheiro'),
                'fpRemoved'  => __('Não é mais um falso positivo; ele volta a aparecer nos achados.', 'facheiro'),
                'fpForget'   => __('Remover todos os falsos positivos salvos? Os achados que eles escondiam voltam a aparecer.', 'facheiro'),
                'fpKeep'     => __('Voltar a confiar neste falso positivo? Faça isso só se você ou outro administrador fez a alteração.', 'facheiro'),
                'sigNone'    => __('Nenhuma assinatura corresponde.', 'facheiro'),
                /* translators: %d: number of matching signatures */
                'sigHits'    => __('Assinaturas correspondentes: %d', 'facheiro'),
                'disabled'   => __('desativada', 'facheiro'),
                'copied'     => __('Copiado.', 'facheiro'),
                'sigDelete'  => __('Excluir esta assinatura personalizada?', 'facheiro'),
                'takeover'   => __('A varredura em segundo plano parou de avançar, então ela continua a partir desta aba enquanto a página estiver aberta. Ferramentas > Saúde do site mostra se este site consegue acessar o próprio wp-cron.php; se não conseguir, ajuste "Executar varreduras" para "Só com esta página aberta".', 'facheiro'),
            )),
        ));
    }

    private static function require_access()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('Você não tem permissão para fazer isso.', 'facheiro')), 403);
        }
    }

    public static function ajax_start()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();

        $options = array();
        $log = isset($_POST['log']) ? sanitize_text_field(wp_unslash($_POST['log'])) : '';
        if ('' === $log) {
            // The page's Start button: the saved access-log setting, skipped
            // (as by automatic scans) when it no longer resolves.
            $settings = Facheiro_Settings::get();
            $real = Facheiro_Settings::resolve_log_path($settings['log']);
            if (is_wp_error($real)) {
                $real = '';
            }
        } else {
            // An explicit path must name an existing, readable log file or
            // directory. Nothing else is accepted.
            $real = Facheiro_Settings::resolve_log_path($log);
            if (is_wp_error($real)) {
                wp_send_json_error(array('message' => $real->get_error_message()), 400);
            }
        }
        if ('' !== $real) {
            $options['scanlog'] = $real;
        }

        $job = Facheiro_Job::start($options, 'manual');
        if (is_wp_error($job)) {
            wp_send_json_error(array('message' => $job->get_error_message()), 409);
        }
        if (!empty($job['background'])) {
            Facheiro_Cron::kick();
        }
        wp_send_json_success(self::status_payload($job));
    }

    /**
     * The page saw no progress for a while: ask WP-Cron for another run.
     */
    public static function ajax_kick()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        $job = Facheiro_Job::current();
        if (null !== $job && 'running' === $job['status'] && !empty($job['background'])) {
            Facheiro_Cron::kick();
        }
        wp_send_json_success(self::status_payload($job));
    }

    public static function ajax_step()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        $job = Facheiro_Job::step();
        wp_send_json_success(self::status_payload($job));
    }

    public static function ajax_status()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        wp_send_json_success(self::status_payload(Facheiro_Job::current()));
    }

    public static function ajax_cancel()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        wp_send_json_success(self::status_payload(Facheiro_Job::cancel()));
    }

    /**
     * Mark a finding as a false positive, undo that, or forget them all.
     */
    public static function ajax_false_positive()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        if ('mark' === $op) {
            $id = isset($_POST['id']) ? absint($_POST['id']) : 0;
            $note = isset($_POST['note']) ? sanitize_text_field(wp_unslash($_POST['note'])) : '';
            $rule = Facheiro_False_Positives::mark($id, $note);
            if (is_wp_error($rule)) {
                wp_send_json_error(array('message' => $rule->get_error_message()), 400);
            }
            wp_send_json_success(array('fingerprint' => Facheiro_False_Positives::fingerprint($rule['type'], $rule['path'], $rule['detail'])));
        }
        if ('unmark' === $op) {
            $fingerprint = isset($_POST['fingerprint']) ? sanitize_key(wp_unslash($_POST['fingerprint'])) : '';
            if (1 !== preg_match('/^[0-9a-f]{40}$/', $fingerprint)) {
                wp_send_json_error(array('message' => __('Falso positivo desconhecido.', 'facheiro')), 400);
            }
            Facheiro_False_Positives::unmark($fingerprint);
            wp_send_json_success(array());
        }
        if ('keep' === $op) {
            $fingerprint = isset($_POST['fingerprint']) ? sanitize_key(wp_unslash($_POST['fingerprint'])) : '';
            if (1 !== preg_match('/^[0-9a-f]{40}$/', $fingerprint)) {
                wp_send_json_error(array('message' => __('Falso positivo desconhecido.', 'facheiro')), 400);
            }
            Facheiro_False_Positives::keep($fingerprint);
            wp_send_json_success(array());
        }
        if ('forget_all' === $op) {
            Facheiro_False_Positives::forget_all();
            wp_send_json_success(array());
        }
        wp_send_json_error(array('message' => __('Pedido desconhecido.', 'facheiro')), 400);
    }

    /**
     * Download one flagged file as an encrypted sample zip for analysis.
     * The administrator submits it; the site never uploads anything.
     */
    public static function sample()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        $id = isset($_GET['id']) ? absint($_GET['id']) : 0;
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::NONCE_SAMPLE . $id)) {
            wp_die(esc_html__('Link expirado, volte e tente de novo.', 'facheiro'), '', array('response' => 403));
        }
        $finding = Facheiro_False_Positives::finding($id);
        if (null === $finding) {
            wp_die(esc_html__('Esse achado não faz parte dos resultados atuais.', 'facheiro'), '', array('response' => 404, 'back_link' => true));
        }
        $zip = Facheiro_Sample::build($finding);
        if (is_wp_error($zip)) {
            wp_die(esc_html($zip->get_error_message()), esc_html__('Amostra indisponível', 'facheiro'), array('response' => 409, 'back_link' => true));
        }
        // A cancelled download aborts the script mid-readfile(); the
        // shutdown function still runs, so the zip never stays in the temp
        // folder.
        register_shutdown_function(
            static function () use ($zip) {
                if (file_exists($zip)) {
                    @unlink($zip); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- our own temporary file.
                }
            }
        );
        nocache_headers();
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="facheiro-sample-' . (int) $id . '-' . gmdate('Ymd-His') . '.zip"');
        header('Content-Length: ' . (int) filesize($zip));
        header('X-Content-Type-Options: nosniff');
        readfile($zip); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- streams our own temporary zip to the administrator.
        exit;
    }

    private static function signatures_url($args = array())
    {
        return add_query_arg(array_merge(array('tab' => 'signatures'), $args), self::page_url());
    }

    public static function notify(array $notices)
    {
        set_transient('facheiro_notice_' . get_current_user_id(), $notices, MINUTE_IN_SECONDS);
    }

    /**
     * Signature editor form target: save, delete, enable/disable, import.
     */
    public static function signature_action()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE_SIGNATURES);
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        $id = isset($_POST['id']) ? sanitize_text_field(wp_unslash($_POST['id'])) : '';
        $back = array();

        if ('save' === $op) {
            // Patterns are kept byte for byte (a signature for "<?php" must
            // survive), validated by the engine, and only ever printed escaped.
            $conditions_raw = isset($_POST['conditions']) ? (string) wp_unslash($_POST['conditions']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- regex/text patterns, validated by Facheiro_Signatures and the engine; escaped on output.
            $input = array(
                'id'          => $id,
                'target'      => isset($_POST['target']) ? sanitize_key(wp_unslash($_POST['target'])) : 'file',
                'severity'    => isset($_POST['severity']) ? sanitize_key(wp_unslash($_POST['severity'])) : 'high',
                'description' => isset($_POST['description']) ? sanitize_text_field(wp_unslash($_POST['description'])) : '',
                'enabled'     => !empty($_POST['enabled']),
            );
            $original = isset($_POST['original_id']) ? sanitize_text_field(wp_unslash($_POST['original_id'])) : '';
            $conditions = Facheiro_Signatures::parse_conditions($conditions_raw);
            $result = $conditions;
            if (!is_wp_error($conditions)) {
                if (!in_array($input['target'], array('file', 'db_option', 'db_post'), true)) {
                    $input['target'] = 'file';
                }
                if ('file' === $input['target']) {
                    $input['match'] = $conditions;
                } else {
                    $input['pattern'] = (1 === count($conditions) && isset($conditions[0]['regex'])) ? $conditions[0]['regex'] : '';
                }
                $result = Facheiro_Signatures::save($input, $original);
            }
            if (is_wp_error($result)) {
                self::notify(array(array('error', $result->get_error_message())));
                set_transient('facheiro_sigform_' . get_current_user_id(), array_merge($input, array('conditions' => $conditions_raw, 'original_id' => $original)), MINUTE_IN_SECONDS);
                $back = array('edit' => '' === $original ? 'new' : $original);
            } else {
                /* translators: %s: signature id */
                self::notify(array(array('success', sprintf(__('Assinatura %s salva. Ela vale a partir da próxima varredura.', 'facheiro'), $result['id']))));
            }
        } elseif ('delete' === $op) {
            Facheiro_Signatures::delete($id);
            /* translators: %s: signature id */
            self::notify(array(array('success', sprintf(__('Assinatura %s excluída.', 'facheiro'), $id))));
        } elseif ('enable' === $op || 'disable' === $op) {
            $result = Facheiro_Signatures::set_enabled($id, 'enable' === $op);
            self::notify(array(is_wp_error($result) ? array('error', $result->get_error_message()) : array('success', 'enable' === $op ? __('Assinatura ativada.', 'facheiro') : __('Assinatura desativada.', 'facheiro'))));
        } elseif ('keep' === $op) {
            Facheiro_Seal::accept('signatures', array($id));
            /* translators: %s: signature id */
            self::notify(array(array('success', sprintf(__('A assinatura %s voltou a ser confiável.', 'facheiro'), $id))));
        } elseif ('acknowledge' === $op) {
            $removed = Facheiro_Seal::diff('signatures');
            Facheiro_Seal::accept('signatures', $removed['removed']);
            self::notify(array(array('success', __('Remoção das assinaturas confirmada.', 'facheiro'))));
        } elseif ('import' === $op) {
            $json = isset($_POST['json']) ? (string) wp_unslash($_POST['json']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON signature file, parsed and validated entry by entry; escaped on output.
            $result = Facheiro_Signatures::import($json);
            /* translators: %d: number of signatures */
            self::notify(array(is_wp_error($result) ? array('error', $result->get_error_message()) : array('success', sprintf(_n('%d assinatura importada.', '%d assinaturas importadas.', $result, 'facheiro'), $result))));
        }
        wp_safe_redirect(self::signatures_url($back));
        exit;
    }

    public static function signatures_export()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::NONCE_SIGNATURES)) {
            wp_die(esc_html__('Link expirado, volte e tente de novo.', 'facheiro'), '', array('response' => 403));
        }
        nocache_headers();
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="facheiro-signatures-' . gmdate('Ymd-His') . '.json"');
        echo Facheiro_Signatures::export_json(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download.
        exit;
    }

    /**
     * Test pasted text, or a file of the site, against every signature.
     */
    public static function ajax_signature_test()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        $path = isset($_POST['path']) ? sanitize_text_field(wp_unslash($_POST['path'])) : '';
        if ('' !== $path) {
            $text = Facheiro_Signatures::read_site_file($path);
            if (is_wp_error($text)) {
                wp_send_json_error(array('message' => $text->get_error_message()), 400);
            }
        } else {
            $text = isset($_POST['text']) ? (string) wp_unslash($_POST['text']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sample text matched in memory, never stored or echoed.
        }
        wp_send_json_success(array('hits' => Facheiro_Signatures::test($text)));
    }

    private static function render_signatures_tab()
    {
        $defs = Facheiro_Signatures::all();
        $seal = Facheiro_Seal::status();
        $sig_diff = $seal['diff']['signatures'];
        $sig_tampered = array_flip(array_merge($sig_diff['added'], $sig_diff['changed']));
        $edit_id = isset($_GET['edit']) ? sanitize_text_field(wp_unslash($_GET['edit'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- selects which row to show in the form.
        $form = array('id' => '', 'target' => 'file', 'severity' => 'HIGH', 'description' => '', 'enabled' => true, 'conditions' => '', 'original_id' => '');
        if ('' !== $edit_id && 'new' !== $edit_id) {
            $def = Facheiro_Signatures::get($edit_id);
            if (null !== $def) {
                $form = array_merge($form, $def, array('conditions' => Facheiro_Signatures::conditions_text($def), 'original_id' => $def['id']));
            }
        }
        $key = 'facheiro_sigform_' . get_current_user_id();
        $kept = get_transient($key);
        if (is_array($kept)) {
            delete_transient($key);
            $form = array_merge($form, $kept);
        }
        $targets = array('file' => __('Arquivos', 'facheiro'), 'db_option' => __('Opções do banco de dados', 'facheiro'), 'db_post' => __('Posts do banco de dados', 'facheiro'));
        $builtin = Facheiro_Signatures::builtin_listing();
        ?>
        <p class="facheiro-intro"><?php esc_html_e('Uma assinatura descreve algo a procurar. Adicione as suas para uma ameaça específica deste site; elas rodam em todas as varreduras a partir da próxima. Assinaturas personalizadas só informam ocorrências (como SIGNATURE_MATCH, para arquivos): nada é limpo ou apagado por causa delas.', 'facheiro'); ?></p>
        <p class="facheiro-intro"><a href="https://github.com/fcavallari/Facheiro/blob/main/docs/writing-signatures.md" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Como escrever uma boa assinatura', 'facheiro'); ?><span class="screen-reader-text"> <?php esc_html_e('(abre em uma nova aba)', 'facheiro'); ?></span></a></p>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Suas assinaturas', 'facheiro'); ?></h2>
                <div class="facheiro-head-actions">
                    <a class="button" href="<?php echo esc_url(self::signatures_url(array('edit' => 'new'))); ?>#facheiro-sig-form"><?php esc_html_e('Adicionar assinatura', 'facheiro'); ?></a>
                </div>
            </div>
            <?php if (!empty($sig_diff['removed'])) : ?>
                <div class="notice notice-error inline facheiro-tamper"><p><?php
                    printf(
                        /* translators: %s: comma-separated signature names */
                        esc_html__('Removidas fora do Facheiro: %s. Importe-as de novo de uma exportação se ainda devem existir.', 'facheiro'),
                        '<code>' . esc_html(implode(', ', $sig_diff['removed'])) . '</code>'
                    );
                ?></p><p><?php self::signature_button('', 'acknowledge', __('Confirmar', 'facheiro')); ?></p></div>
            <?php endif; ?>
            <?php if (empty($defs)) : ?>
                <p class="facheiro-empty"><?php esc_html_e('Ainda não há assinaturas personalizadas. As assinaturas embutidas estão listadas no fim desta página.', 'facheiro'); ?></p>
            <?php else : ?>
                <div class="facheiro-table-scroll"><table class="widefat striped facheiro-table facheiro-sig-table">
                    <thead><tr>
                        <th><?php esc_html_e('Assinatura', 'facheiro'); ?></th>
                        <th class="facheiro-col-target"><?php esc_html_e('Procura em', 'facheiro'); ?></th>
                        <th class="facheiro-col-sev"><?php esc_html_e('Gravidade', 'facheiro'); ?></th>
                        <th><?php esc_html_e('Condições', 'facheiro'); ?></th>
                        <th class="facheiro-col-actions"><?php esc_html_e('Ações', 'facheiro'); ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($defs as $def) : ?>
                        <?php $enabled = !isset($def['enabled']) || $def['enabled']; ?>
                        <?php $is_tampered = isset($def['id']) && isset($sig_tampered[(string) $def['id']]); ?>
                        <tr class="<?php echo $enabled ? '' : 'facheiro-disabled'; ?><?php echo $is_tampered ? ' facheiro-tampered' : ''; ?>">
                            <td><code><?php echo esc_html($def['id']); ?></code><?php echo $enabled ? '' : ' <em>(' . esc_html__('desativada', 'facheiro') . ')</em>'; ?>
                                <?php if ($is_tampered) : ?><p class="facheiro-tamper-badge"><?php esc_html_e('Adicionada ou alterada fora do Facheiro. Mantenha-a só se um administrador fez essa alteração.', 'facheiro'); ?></p><?php endif; ?>
                                <?php if ('' !== (string) $def['description']) : ?><p class="description"><?php echo esc_html($def['description']); ?></p><?php endif; ?></td>
                            <td><?php echo esc_html(isset($targets[$def['target']]) ? $targets[$def['target']] : $def['target']); ?></td>
                            <td><span class="facheiro-sev facheiro-sev-<?php echo esc_attr(strtolower($def['severity'])); ?>"><?php echo esc_html($def['severity']); ?></span></td>
                            <td><pre class="facheiro-conditions"><?php echo esc_html(Facheiro_Signatures::conditions_text($def)); ?></pre></td>
                            <td class="facheiro-actions">
                                <a class="button button-small" href="<?php echo esc_url(self::signatures_url(array('edit' => $def['id']))); ?>#facheiro-sig-form"><?php esc_html_e('Editar', 'facheiro'); ?></a>
                                <?php self::signature_button($def['id'], $enabled ? 'disable' : 'enable', $enabled ? __('Desativar', 'facheiro') : __('Ativar', 'facheiro')); ?>
                                <?php if ($is_tampered) : ?>
                                    <?php self::signature_button($def['id'], 'keep', __('Manter', 'facheiro')); ?>
                                <?php endif; ?>
                                <?php self::signature_button($def['id'], 'delete', __('Excluir', 'facheiro')); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table></div>
            <?php endif; ?>
        </div>

        <div class="facheiro-card" id="facheiro-sig-form">
            <div class="facheiro-card-head">
                <h2><?php echo '' === $form['original_id'] ? esc_html__('Adicionar uma assinatura', 'facheiro') : esc_html__('Editar assinatura', 'facheiro'); ?></h2>
            </div>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="facheiro_signature" />
                <input type="hidden" name="op" value="save" />
                <input type="hidden" name="original_id" value="<?php echo esc_attr($form['original_id']); ?>" />
                <?php wp_nonce_field(self::NONCE_SIGNATURES); ?>
                <table class="form-table" role="presentation">
                    <tr><th scope="row"><label for="facheiro-sig-id"><?php esc_html_e('Nome', 'facheiro'); ?></label></th>
                        <td><input type="text" id="facheiro-sig-id" name="id" class="regular-text code" value="<?php echo esc_attr($form['id']); ?>" placeholder="acme-loader" pattern="[a-z0-9][a-z0-9._\-]{1,62}" required />
                            <p class="description"><?php esc_html_e('Um nome curto com letras minúsculas, números, pontos, hífens e sublinhados. Os achados o mostram como custom.<nome>.', 'facheiro'); ?></p></td></tr>
                    <tr><th scope="row"><label for="facheiro-sig-target"><?php esc_html_e('Procura em', 'facheiro'); ?></label></th>
                        <td><select id="facheiro-sig-target" name="target">
                            <?php foreach ($targets as $value => $label) : ?>
                                <option value="<?php echo esc_attr($value); ?>" <?php selected($form['target'], $value); ?>><?php echo esc_html($label); ?></option>
                            <?php endforeach; ?>
                        </select>
                            <p class="description"><?php esc_html_e('Arquivos: PHP, JavaScript e outros arquivos de código com menos de 2 MB. Opções e posts do banco de dados: valores da tabela de opções e conteúdo dos posts.', 'facheiro'); ?></p></td></tr>
                    <tr><th scope="row"><label for="facheiro-sig-severity"><?php esc_html_e('Gravidade', 'facheiro'); ?></label></th>
                        <td><select id="facheiro-sig-severity" name="severity">
                            <?php foreach (array('HIGH', 'MEDIUM', 'LOW') as $severity) : ?>
                                <option value="<?php echo esc_attr(strtolower($severity)); ?>" <?php selected(strtoupper($form['severity']), $severity); ?>><?php echo esc_html($severity); ?></option>
                            <?php endforeach; ?>
                        </select>
                            <p class="description"><?php esc_html_e('HIGH se uma ocorrência for certamente maliciosa, MEDIUM se precisar ser conferida, LOW se só valer a pena saber.', 'facheiro'); ?></p></td></tr>
                    <tr><th scope="row"><label for="facheiro-sig-description"><?php esc_html_e('Descrição', 'facheiro'); ?></label></th>
                        <td><input type="text" id="facheiro-sig-description" name="description" class="large-text" value="<?php echo esc_attr($form['description']); ?>" placeholder="<?php esc_attr_e('Backdoor do carregador ACME', 'facheiro'); ?>" maxlength="300" />
                            <p class="description"><?php esc_html_e('Aparece em cada ocorrência.', 'facheiro'); ?></p></td></tr>
                    <tr><th scope="row"><label for="facheiro-sig-conditions"><?php esc_html_e('Condições', 'facheiro'); ?></label> <?php self::help_button('facheiro-help-conditions'); ?></th>
                        <td><textarea id="facheiro-sig-conditions" name="conditions" class="large-text code" rows="5" placeholder="text: acme_loader&#10;regex: /eval\s*\(\s*\$_POST/i" required><?php echo esc_textarea($form['conditions']); ?></textarea>
                            <p class="description"><?php esc_html_e('Uma por linha, cada uma começando com text: (texto exato) ou regex: (um padrão). Um arquivo corresponde quando todas as linhas correspondem.', 'facheiro'); ?></p>
                            <?php
                            self::help_text('facheiro-help-conditions', array(
                                __('text: corresponde exatamente aos caracteres que vêm depois, incluindo maiúsculas e minúsculas. regex: recebe uma expressão regular do PHP (PCRE) com delimitadores, como /eval\\s*\\(/i. Uma regex que corresponderia a um arquivo vazio é recusada, porque sinalizaria tudo.', 'facheiro'),
                                __('Para arquivos, até 10 linhas, e todas precisam corresponder. A primeira linha é testada primeiro em cada arquivo, então use um texto curto e característico: isso mantém as varreduras rápidas. Assinaturas de banco de dados usam uma única linha de regex.', 'facheiro'),
                                __('Antes de salvar, teste a assinatura abaixo no arquivo malicioso (ela precisa corresponder) e em um arquivo limpo do mesmo tipo (ela não pode corresponder).', 'facheiro'),
                            ));
                            ?></td></tr>
                    <tr><th scope="row"><?php esc_html_e('Status', 'facheiro'); ?></th>
                        <td><label><input type="checkbox" name="enabled" value="1" <?php checked(!empty($form['enabled'])); ?> /> <?php esc_html_e('Usar nas varreduras', 'facheiro'); ?></label></td></tr>
                </table>
                <?php submit_button('' === $form['original_id'] ? __('Adicionar assinatura', 'facheiro') : __('Salvar alterações', 'facheiro'), 'primary', 'submit', false); ?>
                <?php if ('' !== $form['original_id']) : ?>
                    <a class="button" href="<?php echo esc_url(self::signatures_url()); ?>"><?php esc_html_e('Cancelar', 'facheiro'); ?></a>
                <?php endif; ?>
            </form>
        </div>

        <div class="facheiro-card" id="facheiro-sig-test">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Experimentar assinaturas', 'facheiro'); ?></h2>
            </div>
            <p class="description"><?php esc_html_e('Veja quais assinaturas embutidas e personalizadas correspondem a um arquivo deste site ou a uma amostra colada. Nada é salvo, e só os nomes das assinaturas correspondentes são mostrados.', 'facheiro'); ?></p>
            <div class="facheiro-field">
                <label for="facheiro-test-path"><?php esc_html_e('Arquivo deste site', 'facheiro'); ?></label>
                <input type="text" id="facheiro-test-path" class="large-text code" placeholder="wp-content/uploads/2026/shell.php" autocomplete="off" />
                <p class="description"><?php esc_html_e('Caminho a partir da pasta do WordPress. O wp-config.php não pode ser usado.', 'facheiro'); ?></p>
            </div>
            <div class="facheiro-field">
                <label for="facheiro-test-text"><?php esc_html_e('Ou cole uma amostra', 'facheiro'); ?></label>
                <textarea id="facheiro-test-text" class="large-text code" rows="6"></textarea>
            </div>
            <p><button type="button" class="button button-primary" id="facheiro-test-run"><?php esc_html_e('Testar', 'facheiro'); ?></button></p>
            <div id="facheiro-test-result" class="facheiro-test-result" aria-live="polite"></div>
        </div>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Importar e exportar', 'facheiro'); ?></h2>
                <div class="facheiro-head-actions">
                    <a class="button" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=facheiro_signatures_export'), self::NONCE_SIGNATURES)); ?>"><?php esc_html_e('Exportar assinaturas personalizadas', 'facheiro'); ?></a>
                </div>
            </div>
            <p class="description"><?php esc_html_e('A exportação é um arquivo JSON. Ele também funciona com a ferramenta de linha de comando independente: php bin/facheiro.php scanall=1 signatures=signatures.json', 'facheiro'); ?></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="facheiro_signature" />
                <input type="hidden" name="op" value="import" />
                <?php wp_nonce_field(self::NONCE_SIGNATURES); ?>
                <div class="facheiro-field">
                    <label for="facheiro-sig-import"><?php esc_html_e('Importar', 'facheiro'); ?></label>
                    <textarea id="facheiro-sig-import" name="json" class="large-text code" rows="6" placeholder='{"facheiro_signatures": 1, "signatures": [ ... ]}' required></textarea>
                    <p class="description"><?php esc_html_e('Cole o conteúdo de um arquivo de assinaturas. Assinaturas com o mesmo nome são substituídas. Se alguma entrada for inválida, nada é importado.', 'facheiro'); ?></p>
                </div>
                <?php submit_button(__('Importar', 'facheiro'), 'secondary', 'submit', false); ?>
            </form>
        </div>

        <details class="facheiro-card facheiro-builtin">
            <summary><h2><?php
                /* translators: %d: number of built-in signatures */
                printf(esc_html__('Assinaturas embutidas (%d)', 'facheiro'), count($builtin));
            ?></h2></summary>
            <p class="description"><?php esc_html_e('Vêm com o Facheiro; não podem ser alteradas aqui. Os padrões de log de acesso e de crontab não estão listados.', 'facheiro'); ?></p>
            <div class="facheiro-table-scroll"><table class="widefat striped facheiro-table">
                <thead><tr>
                    <th><?php esc_html_e('Assinatura', 'facheiro'); ?></th>
                    <th class="facheiro-col-target"><?php esc_html_e('Procura em', 'facheiro'); ?></th>
                    <th class="facheiro-col-sev"><?php esc_html_e('Gravidade', 'facheiro'); ?></th>
                    <th><?php esc_html_e('Condições', 'facheiro'); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach ($builtin as $sig) : ?>
                    <tr>
                        <td><code><?php echo esc_html($sig['id']); ?></code><p class="description"><?php echo esc_html($sig['description']); ?></p></td>
                        <td><?php echo esc_html($targets[$sig['target']]); ?></td>
                        <td><span class="facheiro-sev facheiro-sev-<?php echo esc_attr(strtolower($sig['severity'])); ?>"><?php echo esc_html($sig['severity']); ?></span></td>
                        <td><pre class="facheiro-conditions"><?php echo esc_html($sig['conditions']); ?></pre></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table></div>
        </details>
        <?php
    }

    private static function render_assistants_tab()
    {
        $abilities = function_exists('wp_register_ability');
        $adapter = class_exists('WP\\MCP\\Core\\McpAdapter');
        $login = wp_get_current_user()->user_login;
        $stdio = wp_json_encode(array('mcpServers' => array('facheiro' => array(
            'command' => 'wp',
            'args'    => array('--path=' . untrailingslashit(ABSPATH), 'mcp-adapter', 'serve', '--server=mcp-adapter-default-server', '--user=' . $login),
        ))), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $remote = wp_json_encode(array('mcpServers' => array('facheiro' => array(
            'command' => 'npx',
            'args'    => array('-y', '@automattic/mcp-wordpress-remote@latest'),
            'env'     => array(
                'WP_API_URL'      => rest_url('mcp/mcp-adapter-default-server'),
                'WP_API_USERNAME' => $login,
                'WP_API_PASSWORD' => 'paste-an-application-password-here',
            ),
        ))), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        ?>
        <p class="facheiro-intro"><?php esc_html_e('Conecte um assistente de IA, como Claude, ChatGPT, Antigravity ou Cursor, pelo Model Context Protocol (MCP). Ele poderá rodar varreduras, explicar os achados, ler arquivos sinalizados, rascunhar e testar assinaturas e registrar falsos positivos, agindo em seu nome.', 'facheiro'); ?></p>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><span class="facheiro-step">1</span> <?php esc_html_e('Confira os requisitos', 'facheiro'); ?></h2>
            </div>
            <ul class="facheiro-checklist">
                <li class="<?php echo $abilities ? 'is-ok' : 'is-missing'; ?>"><?php echo $abilities ? esc_html__('WordPress 6.9 ou mais recente: as ferramentas do Facheiro estão disponíveis para assistentes.', 'facheiro') : esc_html__('É preciso o WordPress 6.9 ou mais recente (ele traz a Abilities API). Atualize o WordPress ou use o resumo no fim desta página.', 'facheiro'); ?></li>
                <li class="<?php echo $adapter ? 'is-ok' : 'is-missing'; ?>">
                    <?php if ($adapter) : ?>
                        <?php esc_html_e('O plugin MCP Adapter está ativo.', 'facheiro'); ?>
                    <?php else : ?>
                        <?php esc_html_e('Instale e ative o plugin oficial MCP Adapter, do projeto WordPress:', 'facheiro'); ?>
                        <a href="https://github.com/WordPress/mcp-adapter/releases" target="_blank" rel="noopener noreferrer">github.com/WordPress/mcp-adapter</a>
                    <?php endif; ?>
                </li>
            </ul>
        </div>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><span class="facheiro-step">2</span> <?php esc_html_e('Adicione o Facheiro ao seu assistente', 'facheiro'); ?> <?php self::help_button('facheiro-help-mcp'); ?></h2>
            </div>
            <p><?php esc_html_e('Copie a configuração que corresponde ao seu caso para as configurações de MCP do seu assistente.', 'facheiro'); ?></p>
            <?php
            self::help_text('facheiro-help-mcp', array(
                __('Claude Desktop: Settings > Developer > Edit Config, e adicione o item "facheiro" dentro de "mcpServers". Claude Code: rode claude mcp add-json facheiro seguido do objeto interno (a parte depois de "facheiro":). Antigravity, Cursor e outros: adicione-o ao arquivo de configuração de MCP deles.', 'facheiro'),
                __('Depois, reinicie o assistente. Ele deve listar as ferramentas do Facheiro e o prompt "facheiro-triage".', 'facheiro'),
            ));
            ?>
            <div class="facheiro-config">
                <h3><?php esc_html_e('O assistente roda onde o WP-CLI alcança este site', 'facheiro'); ?></h3>
                <p class="description"><?php esc_html_e('Por exemplo, o Claude Code no servidor ou em um computador com uma cópia do site. Nada passa pela rede.', 'facheiro'); ?></p>
                <textarea id="facheiro-config-stdio" class="large-text code facheiro-copy" rows="14" readonly><?php echo esc_textarea($stdio); ?></textarea>
                <p><button type="button" class="button" data-copy="facheiro-config-stdio"><?php esc_html_e('Copiar', 'facheiro'); ?></button></p>
            </div>
            <div class="facheiro-config">
                <h3><?php esc_html_e('O assistente roda no seu computador e o site está no ar', 'facheiro'); ?></h3>
                <p class="description">
                    <?php esc_html_e('Precisa do Node.js no seu computador. Crie uma senha de aplicativo, cole-a no lugar do texto de exemplo e revogue-a quando terminar.', 'facheiro'); ?>
                    <a href="<?php echo esc_url(admin_url('profile.php#application-passwords-section')); ?>"><?php esc_html_e('Criar uma senha de aplicativo', 'facheiro'); ?></a>
                </p>
                <textarea id="facheiro-config-remote" class="large-text code facheiro-copy" rows="17" readonly><?php echo esc_textarea($remote); ?></textarea>
                <p><button type="button" class="button" data-copy="facheiro-config-remote"><?php esc_html_e('Copiar', 'facheiro'); ?></button></p>
            </div>
            <p class="description"><?php esc_html_e('O ChatGPT se conecta a servidores MCP pela internet em vez de rodar um comando, e só nos planos que permitem conectores personalizados. Se o seu não permite, use o resumo no fim desta página.', 'facheiro'); ?></p>
        </div>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><span class="facheiro-step">3</span> <?php esc_html_e('Pergunte', 'facheiro'); ?></h2>
            </div>
            <ul class="facheiro-examples">
                <li><?php esc_html_e('"Use o prompt de triagem do Facheiro." (aparece entre os prompts do servidor)', 'facheiro'); ?></li>
                <li><?php esc_html_e('"Faça uma varredura no meu site com o Facheiro e me diga se ele foi invadido."', 'facheiro'); ?></li>
                <li><?php esc_html_e('"Explique os achados HIGH e o que devo fazer com cada um."', 'facheiro'); ?></li>
                <li><?php esc_html_e('"O Facheiro deixou passar um backdoor em wp-content/plugins/acme/loader.php: escreva uma assinatura para ele, teste nesse arquivo e em um plugin limpo e depois salve."', 'facheiro'); ?></li>
            </ul>
            <p class="facheiro-note"><?php esc_html_e('O assistente age com a sua conta, mas não pode limpar, restaurar nem alterar arquivos: a limpeza continua sendo um comando que você mesmo roda. Tudo o que uma varredura lê do site pode ter sido escrito pelo invasor, e o Facheiro marca isso como não confiável para o assistente. Mesmo assim, confira o raciocínio dele antes de deixá-lo marcar um achado como falso positivo.', 'facheiro'); ?></p>
        </div>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Sem MCP? Copie um resumo para qualquer chat', 'facheiro'); ?></h2>
            </div>
            <p class="description"><?php esc_html_e('Instruções para o chatbot e até 100 dos achados mais graves da última varredura. Inclui caminhos de arquivos e trechos de código deste site, então compartilhe só com um serviço em que você confia para isso.', 'facheiro'); ?></p>
            <textarea id="facheiro-brief" class="large-text code facheiro-copy" rows="14" readonly><?php echo esc_textarea(Facheiro_Abilities::brief()); ?></textarea>
            <p><button type="button" class="button button-primary" data-copy="facheiro-brief"><?php esc_html_e('Copiar resumo', 'facheiro'); ?></button></p>
        </div>
        <?php
    }

    private static function signature_button($id, $op, $label)
    {
        ?>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="facheiro-inline-form" <?php echo 'delete' === $op ? 'data-confirm="sig-delete"' : ''; ?>>
            <input type="hidden" name="action" value="facheiro_signature" />
            <input type="hidden" name="op" value="<?php echo esc_attr($op); ?>" />
            <input type="hidden" name="id" value="<?php echo esc_attr($id); ?>" />
            <?php wp_nonce_field(self::NONCE_SIGNATURES); ?>
            <button type="submit" class="button button-small<?php echo 'delete' === $op ? ' button-link-delete' : ''; ?>"><?php echo esc_html($label); ?></button>
        </form>
        <?php
    }

    private static function status_payload($job)
    {
        if (null === $job) {
            return array('status' => '', 'percent' => 0, 'stage' => '', 'message' => '', 'counts' => array(), 'error' => '');
        }
        return array(
            'status'     => $job['status'],
            'percent'    => Facheiro_Job::percent($job),
            'stage'      => Facheiro_Job::stage_label($job),
            'message'    => $job['message'],
            'counts'     => $job['counts'],
            'error'      => $job['error'],
            'units'      => $job['units_done'],
            'background' => !empty($job['background']),
            'origin'     => isset($job['origin']) ? $job['origin'] : 'manual',
            // Seconds since a step last saved progress; the page uses it to
            // notice a background runner that stopped coming back.
            'idle'       => max(0, time() - (int) $job['updated']),
        );
    }

    /**
     * Settings form target (admin-post): validate, save, re-arm the
     * schedule, and warn when background mode cannot work on this host.
     */
    public static function save_settings()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE_SETTINGS);

        $raw = isset($_POST['facheiro']) && is_array($_POST['facheiro']) ? wp_unslash($_POST['facheiro']) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each scalar is sanitized below, then whitelisted in Facheiro_Settings::sanitize().
        $input = array();
        foreach ($raw as $key => $value) {
            if (is_scalar($value)) {
                $input[sanitize_key($key)] = sanitize_text_field((string) $value);
            }
        }
        $settings = Facheiro_Settings::save($input);

        $notices = array(array('success', __('Configurações salvas.', 'facheiro')));
        if ('' !== $settings['log']) {
            $real = Facheiro_Settings::resolve_log_path($settings['log']);
            if (is_wp_error($real)) {
                $notices[] = array('warning', __('O caminho dos logs de acesso não existe ou o PHP não consegue lê-lo. As varreduras pulam os logs até que ele possa ser lido.', 'facheiro'));
            }
        }
        if ('background' === $settings['runner'] || 'off' !== $settings['schedule']) {
            if (Facheiro_Cron::trigger_disabled()) {
                $notices[] = array('warning', __('DISABLE_WP_CRON está definido neste site, então o WordPress não inicia o WP-Cron sozinho. As varreduras em segundo plano e as automáticas só avançam quando a tarefa cron do servidor chama o wp-cron.php.', 'facheiro'));
            } else {
                $loopback = self::loopback_problem();
                if (null !== $loopback) {
                    $notices[] = array('warning', sprintf(
                        /* translators: %s: the Site Health loopback error */
                        __('Este site não conseguiu acessar o próprio wp-cron.php (%s). As varreduras em segundo plano só vão avançar enquanto a página do Facheiro estiver aberta, e as varreduras automáticas podem nunca começar. Corrija o problema de loopback indicado em Ferramentas > Saúde do site, ou ajuste "Executar varreduras" para "Só com esta página aberta".', 'facheiro'),
                        $loopback
                    ));
                }
            }
        }
        set_transient('facheiro_notice_' . get_current_user_id(), $notices, MINUTE_IN_SECONDS);
        wp_safe_redirect(self::settings_url());
        exit;
    }

    /**
     * Tamper seal: accept the current settings (after the seal went
     * missing) or the scan settings changed outside Facheiro.
     */
    public static function seal_action()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE_SEAL);
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        if ('accept_all' === $op) {
            Facheiro_Seal::accept();
            Facheiro_False_Positives::reset_cache();
            self::notify(array(array('success', __('As configurações salvas atuais voltaram a ser confiáveis.', 'facheiro'))));
        } elseif ('accept_settings' === $op) {
            Facheiro_Seal::accept('settings');
            self::notify(array(array('success', __('As configurações de varredura atuais voltaram a ser confiáveis.', 'facheiro'))));
        }
        wp_safe_redirect(self::page_url());
        exit;
    }

    private static function seal_button($op, $label)
    {
        ?>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="facheiro-inline-form">
            <input type="hidden" name="action" value="facheiro_seal" />
            <input type="hidden" name="op" value="<?php echo esc_attr($op); ?>" />
            <?php wp_nonce_field(self::NONCE_SEAL); ?>
            <button type="submit" class="button button-small"><?php echo esc_html($label); ?></button>
        </form>
        <?php
    }

    /**
     * HIGH/MEDIUM self-check findings of the current job about Facheiro's
     * own files (changed code, added PHP) that nobody marked as a false
     * positive.
     */
    private static function own_files_changed($job)
    {
        global $wpdb;
        if (null === $job || empty($job['summaries']['self'])) {
            return 0;
        }
        $dir = realpath(FACHEIRO_DIR);
        if (false === $dir) {
            return 0;
        }
        $table = Facheiro_Plugin::findings_table();
        // phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table (name from the base prefix); values go through prepare(); must not be cached.
        $count = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM `{$table}` WHERE job_id = %s AND type IN ('INTEGRITY_MODIFIED', 'INTEGRITY_EXTRA') AND severity IN ('HIGH', 'MEDIUM') AND fp <> %d AND path LIKE %s",
            $job['id'],
            Facheiro_False_Positives::MATCHED,
            $wpdb->esc_like(untrailingslashit(str_replace('\\', '/', $dir)) . '/') . '%'
        ));
        // phpcs:enable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $count;
    }

    /**
     * Tamper notices shown at the top of every Facheiro tab: Facheiro's
     * own files changed (from the last scan's self-check), and saved
     * settings changed outside Facheiro (checked now).
     */
    private static function render_tamper_notices($job)
    {
        if (self::own_files_changed($job) > 0) {
            ?>
            <div class="notice notice-error facheiro-tamper"><p><strong><?php esc_html_e('Os próprios arquivos do Facheiro foram alterados, então estes resultados podem não ser confiáveis.', 'facheiro'); ?></strong>
                <?php esc_html_e('Reinstale o Facheiro a partir do wordpress.org, ou rode a ferramenta de linha de comando independente a partir de um download novo, e faça a varredura de novo. Os achados da autoverificação do Facheiro listam os arquivos.', 'facheiro'); ?></p></div>
            <?php
        }
        $status = Facheiro_Seal::status();
        if (!$status['available']) {
            ?>
            <div class="notice notice-warning facheiro-tamper"><p><?php
                /* translators: %s: folder path */
                printf(esc_html__('A detecção de adulteração das configurações salvas está desligada: o PHP não consegue gravar o arquivo de selo em %s.', 'facheiro'), '<code>' . esc_html(Facheiro_Plugin::content_dir()) . '</code>');
            ?></p></div>
            <?php
            return;
        }
        if ($status['lost'] > 0) {
            ?>
            <div class="notice notice-warning facheiro-tamper"><p><?php
                printf(
                    /* translators: %s: date and time */
                    esc_html__('O selo contra adulteração das configurações salvas sumiu em %s e foi recriado a partir das configurações atuais. Algo o apagou, ou o site foi migrado sem ele. Confira os falsos positivos salvos e as assinaturas personalizadas e depois confirme-os.', 'facheiro'),
                    esc_html(wp_date(get_option('date_format') . ' ' . get_option('time_format'), $status['lost']))
                );
            ?></p><p><?php self::seal_button('accept_all', __('As configurações salvas estão corretas', 'facheiro')); ?></p></div>
            <?php
        }
        $fp = $status['diff']['false_positives'];
        $fp_count = count($fp['added']) + count($fp['changed']);
        $sig = $status['diff']['signatures'];
        $sig_count = count($sig['added']) + count($sig['changed']) + count($sig['removed']);
        $set = $status['diff']['settings'];
        $set_count = count($set['added']) + count($set['changed']) + count($set['removed']);
        if (0 === $fp_count + $sig_count + $set_count) {
            return;
        }
        ?>
        <div class="notice notice-error facheiro-tamper"><p><strong><?php esc_html_e('Algumas configurações salvas foram alteradas fora do Facheiro, direto no banco de dados.', 'facheiro'); ?></strong>
            <?php esc_html_e('É assim que um invasor se esconde de um scanner. Revise cada alteração: mantenha-a só se você ou outro administrador a fez de propósito.', 'facheiro'); ?></p>
            <ul class="facheiro-tamper-list">
                <?php if ($fp_count > 0) : ?>
                    <li><?php
                        printf(
                            /* translators: %d: number of false positives */
                            esc_html(_n('%d falso positivo salvo é ignorado até que você o revise.', '%d falsos positivos salvos são ignorados até que você os revise.', $fp_count, 'facheiro')),
                            (int) $fp_count
                        );
                    ?> <a href="<?php echo esc_url(add_query_arg('view', 'fp', self::page_url())); ?>#facheiro-fp-rules"><?php esc_html_e('Revisar falsos positivos', 'facheiro'); ?></a></li>
                <?php endif; ?>
                <?php if ($sig_count > 0) : ?>
                    <li><?php
                        printf(
                            /* translators: %d: number of signatures */
                            esc_html(_n('%d assinatura personalizada foi adicionada, alterada ou removida.', '%d assinaturas personalizadas foram adicionadas, alteradas ou removidas.', $sig_count, 'facheiro')),
                            (int) $sig_count
                        );
                    ?> <a href="<?php echo esc_url(self::signatures_url()); ?>"><?php esc_html_e('Revisar assinaturas', 'facheiro'); ?></a></li>
                <?php endif; ?>
                <?php if ($set_count > 0) : ?>
                    <li><?php esc_html_e('As configurações de varredura (como e quando as varreduras rodam, o caminho dos logs de acesso) foram alteradas.', 'facheiro'); ?>
                        <a href="<?php echo esc_url(self::settings_url()); ?>"><?php esc_html_e('Revisar configurações', 'facheiro'); ?></a>
                        <?php self::seal_button('accept_settings', __('As configurações de varredura estão corretas', 'facheiro')); ?></li>
                <?php endif; ?>
            </ul>
        </div>
        <?php
    }

    /**
     * Site Health's loopback test, which is what WP-Cron spawning needs.
     * Returns the problem text or null when the loopback works.
     */
    private static function loopback_problem()
    {
        if (!class_exists('WP_Site_Health')) {
            require_once ABSPATH . 'wp-admin/includes/class-wp-site-health.php';
        }
        $result = WP_Site_Health::get_instance()->can_perform_loopback();
        if (is_object($result) && isset($result->status) && 'good' === $result->status) {
            return null;
        }
        $message = (is_object($result) && isset($result->message)) ? wp_strip_all_tags((string) $result->message) : '';
        return '' === $message ? __('a requisição de loopback falhou', 'facheiro') : $message;
    }

    private static function take_notices()
    {
        $key = 'facheiro_notice_' . get_current_user_id();
        $notices = get_transient($key);
        if (false !== $notices) {
            delete_transient($key);
        }
        return is_array($notices) ? $notices : array();
    }

    /**
     * Download the findings as today's CLI formats: CSV-style text lines or
     * NDJSON finding events.
     */
    public static function export()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::NONCE_EXPORT)) {
            wp_die(esc_html__('Link expirado, volte e tente de novo.', 'facheiro'), '', array('response' => 403));
        }
        $format = (isset($_GET['format']) && 'json' === $_GET['format']) ? 'json' : 'txt';
        $job = Facheiro_Job::current();
        $job_id = null === $job ? '' : $job['id'];

        nocache_headers();
        header('Content-Type: ' . ('json' === $format ? 'application/x-ndjson' : 'text/plain') . '; charset=utf-8');
        header('Content-Disposition: attachment; filename="facheiro-findings-' . gmdate('Ymd-His') . '.' . $format . '"');

        foreach (self::iterate_findings($job_id) as $row) {
            $context = self::decode_context($row->context);
            $fp = (int) $row->fp;
            if ('json' === $format) {
                $event = array('event' => 'finding', 'severity' => $row->severity, 'type' => $row->type, 'path' => $row->path, 'detail' => $row->detail);
                if (!empty($context)) {
                    $event['context'] = $context;
                }
                if (null !== $row->sha256 && '' !== $row->sha256) {
                    $event['sha256'] = $row->sha256;
                }
                // Cleared findings stay in the JSON record, flagged.
                if (Facheiro_False_Positives::MATCHED === $fp) {
                    $event['false_positive'] = true;
                } elseif (Facheiro_False_Positives::CHANGED === $fp) {
                    $event['false_positive_changed'] = true;
                }
                echo wp_json_encode($event) . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- machine-readable download, JSON-encoded.
            } elseif (Facheiro_False_Positives::MATCHED !== $fp) {
                $line = Facheiro\Engine\BaseReporter::format_text_finding(array(
                    'severity' => $row->severity, 'type' => $row->type, 'path' => $row->path, 'detail' => $row->detail, 'context' => $context,
                ));
                echo $line; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain-text download; the formatter percent-encodes control characters.
            }
        }
        exit;
    }

    /**
     * Every finding of the job, worst severity first. One pass per
     * severity, each paged by id: paging by id over a severity-sorted
     * result would skip every lower-id row after the first page, and an
     * export that silently drops findings is worse than none.
     */
    private static function iterate_findings($job_id)
    {
        global $wpdb;
        $table = Facheiro_Plugin::findings_table();
        $known = array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO');
        // phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table (name from the base prefix, never user input); values go through prepare(); results must not be cached.
        foreach (array_merge($known, array(null)) as $severity) {
            $last = 0;
            while (true) {
                if (null === $severity) {
                    // Anything with an unexpected severity, so nothing is lost.
                    $rows = $wpdb->get_results($wpdb->prepare(
                        "SELECT id, severity, type, path, detail, context, sha256, fp FROM `{$table}` WHERE job_id = %s AND id > %d AND severity NOT IN ('HIGH','ERROR','MEDIUM','LOW','INFO') ORDER BY id LIMIT 500",
                        $job_id, $last
                    ));
                } else {
                    $rows = $wpdb->get_results($wpdb->prepare(
                        "SELECT id, severity, type, path, detail, context, sha256, fp FROM `{$table}` WHERE job_id = %s AND severity = %s AND id > %d ORDER BY id LIMIT 500",
                        $job_id, $severity, $last
                    ));
                }
                if (empty($rows)) {
                    break;
                }
                foreach ($rows as $row) {
                    $last = max($last, (int) $row->id);
                    yield $row;
                }
            }
        }
        // phpcs:enable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    private static function decode_context($json)
    {
        if (null === $json || '' === $json) {
            return array();
        }
        $decoded = json_decode($json, true);
        return is_array($decoded) ? $decoded : array();
    }

    public static function render_page()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        global $wpdb;
        $job = Facheiro_Job::current();
        $table = Facheiro_Plugin::findings_table();
        $severities = array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO');

        $filter = isset($_GET['severity']) ? sanitize_key(wp_unslash($_GET['severity'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter on a listing.
        $filter = in_array(strtoupper($filter), $severities, true) ? strtoupper($filter) : '';
        $paged = isset($_GET['paged']) ? max(1, (int) $_GET['paged']) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only pagination.
        $tab = (isset($_GET['tab']) && in_array($_GET['tab'], array('signatures', 'hardening', 'recovery', 'assistants', 'settings'), true)) ? sanitize_key(wp_unslash($_GET['tab'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- selects a tab.
        $fp_view = isset($_GET['view']) && 'fp' === $_GET['view']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter on a listing.
        if ($fp_view) {
            $filter = '';
        }
        $page_url = self::page_url();
        ?>
        <div class="wrap facheiro-wrap">
            <h1 class="screen-reader-text"><?php esc_html_e('Facheiro', 'facheiro'); ?></h1>
            <header class="facheiro-brand">
                <img class="facheiro-brand-mark" src="<?php echo esc_url(FACHEIRO_URL . 'assets/img/facheiro-mark.svg'); ?>" alt="" width="64" height="64" />
                <div class="facheiro-brand-text">
                    <img class="facheiro-brand-word" src="<?php echo esc_url(FACHEIRO_URL . 'assets/img/facheiro-wordmark.svg'); ?>" alt="<?php esc_attr_e('Facheiro', 'facheiro'); ?>" width="124" height="34" />
                    <p class="facheiro-brand-tag"><?php esc_html_e('Varredura de malware e resposta a incidentes para WordPress', 'facheiro'); ?></p>
                </div>
                <span class="facheiro-brand-version"><?php
                    /* translators: %s: plugin version number */
                    printf(esc_html__('Versão %s', 'facheiro'), esc_html(FACHEIRO_VERSION));
                ?></span>
            </header>
            <hr class="wp-header-end" />
            <?php foreach (self::take_notices() as $notice) : ?>
                <div class="notice notice-<?php echo esc_attr($notice[0]); ?> is-dismissible"><p><?php echo esc_html($notice[1]); ?></p></div>
            <?php endforeach; ?>
            <?php self::render_tamper_notices($job); ?>
            <nav class="nav-tab-wrapper facheiro-tabs">
                <a href="<?php echo esc_url($page_url); ?>" class="nav-tab <?php echo '' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Varredura', 'facheiro'); ?></a>
                <a href="<?php echo esc_url(self::signatures_url()); ?>" class="nav-tab <?php echo 'signatures' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Assinaturas', 'facheiro'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'hardening', $page_url)); ?>" class="nav-tab <?php echo 'hardening' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Blindagem', 'facheiro'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'recovery', $page_url)); ?>" class="nav-tab <?php echo 'recovery' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Recuperação', 'facheiro'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'assistants', $page_url)); ?>" class="nav-tab <?php echo 'assistants' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Assistentes de IA', 'facheiro'); ?></a>
                <a href="<?php echo esc_url(self::settings_url()); ?>" class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Configurações', 'facheiro'); ?></a>
            </nav>
            <?php if ('' !== $tab) : ?>
                <?php
                if ('signatures' === $tab) {
                    self::render_signatures_tab();
                } elseif ('hardening' === $tab) {
                    Facheiro_Admin_Hardening::render();
                } elseif ('recovery' === $tab) {
                    Facheiro_Admin_Recovery::render();
                } elseif ('settings' === $tab) {
                    self::render_settings_tab();
                } else {
                    self::render_assistants_tab();
                }
                ?>
        </div>
                <?php return; ?>
            <?php endif; ?>
        <?php
        // The findings queries below are for the Scan tab only.


        $counts = array_fill_keys($severities, 0);
        $total = 0;
        $fp_total = 0;
        // phpcs:disable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table (name from the base prefix, never user input); values go through prepare(); results must not be cached.
        if (null !== $job) {
            $rows = $wpdb->get_results($wpdb->prepare("SELECT severity, fp, COUNT(*) AS n FROM `{$table}` WHERE job_id = %s GROUP BY severity, fp", $job['id']));
            foreach ((array) $rows as $row) {
                if (Facheiro_False_Positives::MATCHED === (int) $row->fp) {
                    $fp_total += (int) $row->n;
                    continue;
                }
                if (isset($counts[$row->severity])) {
                    $counts[$row->severity] += (int) $row->n;
                }
                $total += (int) $row->n;
            }
        }
        if ($fp_view) {
            $shown = $fp_total;
        } else {
            $shown = '' === $filter ? $total : $counts[$filter];
        }
        $pages = max(1, (int) ceil($shown / self::PER_PAGE));
        $paged = min($paged, $pages);

        $findings = array();
        if (null !== $job && $shown > 0) {
            $where = 'job_id = %s AND fp ' . ($fp_view ? '= 1' : '<> 1') . ('' === $filter ? '' : ' AND severity = %s');
            $params = '' === $filter ? array($job['id']) : array($job['id'], $filter);
            $params[] = self::PER_PAGE;
            $params[] = ($paged - 1) * self::PER_PAGE;
            $findings = $wpdb->get_results($wpdb->prepare(
                "SELECT id, severity, type, path, detail, context, sha256, fingerprint, fp FROM `{$table}` WHERE {$where} ORDER BY FIELD(severity,'HIGH','ERROR','MEDIUM','LOW','INFO'), id LIMIT %d OFFSET %d",
                $params
            ));
        }
        // phpcs:enable WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter

        $export_base = wp_nonce_url(admin_url('admin-post.php?action=facheiro_export'), self::NONCE_EXPORT);
        $settings = Facheiro_Settings::get();
        $running = null !== $job && 'running' === $job['status'];
        $datetime_format = get_option('date_format') . ' ' . get_option('time_format');
        $fp_rules = Facheiro_False_Positives::all_rules();
        $log_real = '' === $settings['log'] ? '' : Facheiro_Settings::resolve_log_path($settings['log']);
        ?>
            <div class="facheiro-card facheiro-run">
                <div class="facheiro-card-head">
                    <h2><?php esc_html_e('Fazer a varredura deste site', 'facheiro'); ?></h2>
                </div>
                <p class="facheiro-lead"><?php esc_html_e('Procura malware e sinais de invasão. Uma varredura só informa o que encontra: nada no seu site é alterado.', 'facheiro'); ?></p>
                <ul class="facheiro-scope">
                    <li><?php esc_html_e('Arquivos do WordPress, dos plugins e dos temas comparados com as cópias oficiais', 'facheiro'); ?></li>
                    <li><?php esc_html_e('Malware conhecido nos seus arquivos', 'facheiro'); ?></li>
                    <li><?php esc_html_e('Entradas suspeitas no banco de dados e contas de administrador', 'facheiro'); ?></li>
                    <li><?php esc_html_e('Arquivos com datas falsificadas e o crontab do servidor', 'facheiro'); ?></li>
                    <li>
                        <?php
                        if ('' === $settings['log']) {
                            printf(
                                /* translators: %s: link to the Settings tab */
                                esc_html__('Logs de acesso: não verificados (informe o local deles na aba %s)', 'facheiro'),
                                '<a href="' . esc_url(self::settings_url()) . '">' . esc_html__('Configurações', 'facheiro') . '</a>'
                            );
                        } elseif (is_wp_error($log_real)) {
                            /* translators: %s: access log path */
                            printf(esc_html__('Logs de acesso: não foi possível ler %s, então eles são pulados (veja Configurações)', 'facheiro'), '<code>' . esc_html($settings['log']) . '</code>');
                        } else {
                            /* translators: %s: access log path */
                            printf(esc_html__('Logs de acesso em %s', 'facheiro'), '<code>' . esc_html($settings['log']) . '</code>');
                        }
                        ?>
                    </li>
                </ul>
                <p class="facheiro-buttons">
                    <button type="button" class="button button-primary button-hero" id="facheiro-start" <?php disabled($running); ?>><?php esc_html_e('Iniciar varredura', 'facheiro'); ?></button>
                    <button type="button" class="button button-hero" id="facheiro-cancel" <?php disabled(!$running); ?>><?php esc_html_e('Cancelar', 'facheiro'); ?></button>
                </p>
                <div id="facheiro-progress" class="facheiro-progress" <?php echo $running ? '' : 'hidden'; ?>>
                    <div class="facheiro-bar"><div class="facheiro-bar-fill" style="width: <?php echo null === $job ? 0 : (int) Facheiro_Job::percent($job); ?>%"></div></div>
                    <p id="facheiro-status-text"><?php echo null === $job ? '' : esc_html($job['message']); ?></p>
                    <p id="facheiro-runner-note" class="description">
                        <?php
                        if ($running) {
                            echo !empty($job['background'])
                                ? esc_html__('Rodando em segundo plano: você pode sair desta página e voltar depois.', 'facheiro')
                                : esc_html__('Mantenha esta página aberta: a varredura roda em pequenas etapas a partir desta aba.', 'facheiro');
                        }
                        ?>
                    </p>
                </div>
                <?php if (null !== $job) : ?>
                    <p class="facheiro-last">
                        <?php
                        if (isset($job['origin']) && 'schedule' === $job['origin']) {
                            /* translators: 1: status word, 2: start date/time, 3: end date/time or dash */
                            $template = __('Última varredura automática: %1$s. Iniciada em %2$s, terminada em %3$s.', 'facheiro');
                        } else {
                            /* translators: 1: status word, 2: start date/time, 3: end date/time or dash */
                            $template = __('Última varredura: %1$s. Iniciada em %2$s, terminada em %3$s.', 'facheiro');
                        }
                        printf(
                            esc_html($template),
                            '<strong>' . esc_html(self::status_word($job['status'])) . '</strong>',
                            esc_html(wp_date($datetime_format, $job['started'])),
                            esc_html(null === $job['finished'] ? '—' : wp_date($datetime_format, $job['finished']))
                        );
                        if ('' !== $job['error']) {
                            echo ' <span class="facheiro-error">' . esc_html($job['error']) . '</span>';
                        }
                        ?>
                    </p>
                <?php endif; ?>
            </div>

            <?php if (null !== $job) : ?>
            <div class="facheiro-card facheiro-findings">
                <div class="facheiro-card-head">
                    <h2><?php esc_html_e('Achados', 'facheiro'); ?> <?php self::help_button('facheiro-help-findings'); ?></h2>
                    <div class="facheiro-head-actions">
                        <a class="button" href="<?php echo esc_url(add_query_arg('format', 'txt', $export_base)); ?>" title="<?php esc_attr_e('Um achado por linha: gravidade, tipo, caminho, detalhes', 'facheiro'); ?>"><?php esc_html_e('Exportar como texto', 'facheiro'); ?></a>
                        <a class="button" href="<?php echo esc_url(add_query_arg('format', 'json', $export_base)); ?>" title="<?php esc_attr_e('Um objeto JSON por linha (NDJSON), com contexto e hashes', 'facheiro'); ?>"><?php esc_html_e('Exportar como JSON', 'facheiro'); ?></a>
                    </div>
                </div>
                <?php
                self::help_text('facheiro-help-findings', array(
                    __('HIGH: quase certamente malicioso; trate primeiro. MEDIUM: suspeito; confira. LOW: vale saber. INFO: para registro (por exemplo, a lista de administradores). ERROR: uma verificação não pôde rodar, então essa área está desconhecida, não limpa.', 'facheiro'),
                    __('Achados de datas de arquivo e de logs são pistas, não provas: confirme antes de agir.', 'facheiro'),
                    __('Se você conferiu um achado e ele é inofensivo, marque-o como falso positivo: as próximas varreduras o escondem, mas só enquanto o arquivo continuar exatamente como você o revisou. "Baixar amostra" salva uma cópia protegida por senha de um arquivo sinalizado para um analista de malware.', 'facheiro'),
                ));
                ?>
                <ul class="facheiro-filters">
                    <li><a href="<?php echo esc_url($page_url); ?>" class="<?php echo ('' === $filter && !$fp_view) ? 'current' : ''; ?>"><?php esc_html_e('Todos', 'facheiro'); ?> <span class="count">(<?php echo (int) $total; ?>)</span></a></li>
                    <?php foreach ($severities as $severity) : ?>
                        <li><a href="<?php echo esc_url(add_query_arg('severity', strtolower($severity), $page_url)); ?>" class="<?php echo $filter === $severity ? 'current' : ''; ?>"><?php echo esc_html($severity); ?> <span class="count">(<?php echo (int) $counts[$severity]; ?>)</span></a></li>
                    <?php endforeach; ?>
                    <li><a href="<?php echo esc_url(add_query_arg('view', 'fp', $page_url)); ?>" class="<?php echo $fp_view ? 'current' : ''; ?>"><?php esc_html_e('Falsos positivos', 'facheiro'); ?> <span class="count">(<?php echo (int) $fp_total; ?>)</span></a></li>
                </ul>

                <div class="facheiro-table-scroll"><table class="widefat striped facheiro-table">
                    <thead>
                        <tr>
                            <th class="facheiro-col-sev"><?php esc_html_e('Gravidade', 'facheiro'); ?></th>
                            <th class="facheiro-col-type"><?php esc_html_e('Tipo', 'facheiro'); ?></th>
                            <th class="facheiro-col-path"><?php esc_html_e('Onde', 'facheiro'); ?></th>
                            <th><?php esc_html_e('Detalhes', 'facheiro'); ?></th>
                            <th class="facheiro-col-actions"><?php esc_html_e('Ações', 'facheiro'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if (empty($findings)) : ?>
                        <tr><td colspan="5">
                            <?php
                            if ($fp_view) {
                                esc_html_e('Nenhum achado destes resultados está marcado como falso positivo.', 'facheiro');
                            } else {
                                echo 'running' === $job['status'] ? esc_html__('Varredura em andamento…', 'facheiro') : esc_html__('Nada encontrado.', 'facheiro');
                            }
                            ?>
                        </td></tr>
                    <?php else : ?>
                        <?php foreach ($findings as $finding) : ?>
                            <?php
                            $path = (string) $finding->path;
                            $short = Facheiro_Plugin::relative_path($path);
                            $context = self::decode_context($finding->context);
                            $fp = (int) $finding->fp;
                            $fingerprint = '' !== (string) $finding->fingerprint ? $finding->fingerprint : Facheiro_False_Positives::fingerprint($finding->type, $finding->path, $finding->detail);
                            $sha256 = (null === $finding->sha256 || '' === $finding->sha256) ? '' : $finding->sha256;
                            ?>
                            <tr data-id="<?php echo (int) $finding->id; ?>" data-fingerprint="<?php echo esc_attr($fingerprint); ?>">
                                <td><span class="facheiro-sev facheiro-sev-<?php echo esc_attr(strtolower($finding->severity)); ?>"><?php echo esc_html($finding->severity); ?></span></td>
                                <td><span class="facheiro-type"><?php echo esc_html($finding->type); ?></span></td>
                                <td><code class="facheiro-path" title="<?php echo esc_attr($path); ?>"><?php echo esc_html($short); ?></code></td>
                                <td>
                                    <?php echo esc_html($finding->detail); ?>
                                    <?php if (!empty($context)) : ?>
                                        <details><summary><?php esc_html_e('Contexto', 'facheiro'); ?></summary>
                                            <pre><?php echo esc_html(implode("\n", $context)); ?></pre>
                                        </details>
                                    <?php endif; ?>
                                    <?php if ('' !== $sha256) : ?>
                                        <p class="facheiro-hash"><span>SHA-256</span> <code><?php echo esc_html($sha256); ?></code>
                                            <a href="<?php echo esc_url('https://www.virustotal.com/gui/file/' . $sha256); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Consultar no VirusTotal', 'facheiro'); ?><span class="screen-reader-text"> <?php esc_html_e('(abre em uma nova aba)', 'facheiro'); ?></span></a></p>
                                    <?php endif; ?>
                                    <?php if (Facheiro_False_Positives::CHANGED === $fp && Facheiro_False_Positives::is_file_type($finding->type)) : ?>
                                        <p class="facheiro-note"><?php esc_html_e('Marcado como falso positivo antes, mas o arquivo mudou desde que foi revisado, então volta a ser informado.', 'facheiro'); ?></p>
                                    <?php elseif (Facheiro_False_Positives::CHANGED === $fp) : ?>
                                        <p class="facheiro-note"><?php esc_html_e('Marcado como falso positivo antes, mas o valor armazenado mudou desde que foi revisado, então volta a ser informado.', 'facheiro'); ?></p>
                                    <?php elseif (Facheiro_False_Positives::MATCHED === $fp && isset($fp_rules[$fingerprint])) : ?>
                                        <p class="facheiro-fp-why"><?php echo esc_html(self::rule_summary($fp_rules[$fingerprint], $datetime_format)); ?></p>
                                    <?php endif; ?>
                                </td>
                                <td class="facheiro-actions">
                                    <?php if (Facheiro_False_Positives::MATCHED === $fp) : ?>
                                        <button type="button" class="button button-small" data-fp-action="unmark"><?php esc_html_e('Não é falso positivo', 'facheiro'); ?></button>
                                    <?php else : ?>
                                        <button type="button" class="button button-small" data-fp-action="mark"><?php esc_html_e('Marcar como falso positivo', 'facheiro'); ?></button>
                                    <?php endif; ?>
                                    <?php if ('' !== $sha256 && 1 !== preg_match('/^wp-config/i', basename($path))) : ?>
                                        <a class="button button-small" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=facheiro_sample&id=' . (int) $finding->id), self::NONCE_SAMPLE . (int) $finding->id)); ?>"><?php esc_html_e('Baixar amostra', 'facheiro'); ?></a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table></div>
                <?php if ($pages > 1) : ?>
                    <div class="tablenav bottom"><div class="tablenav-pages">
                        <?php
                        echo wp_kses_post(paginate_links(array(
                            'base'    => add_query_arg(array('paged' => '%#%', 'severity' => '' === $filter ? false : strtolower($filter), 'view' => $fp_view ? 'fp' : false), $page_url),
                            'format'  => '',
                            'current' => $paged,
                            'total'   => $pages,
                        )));
                        ?>
                    </div></div>
                <?php endif; ?>
                <p class="description facheiro-sample-help">
                    <?php
                    if (Facheiro_Sample::can_encrypt()) {
                        esc_html_e('"Baixar amostra" salva o arquivo em um zip protegido com a senha "infected", junto com uma nota de onde ele foi encontrado e por quê. Envie você mesmo a um analista de malware ou a um sandbox: o Facheiro nunca envia nada. O link do VirusTotal envia só o hash do arquivo, a partir do seu navegador.', 'facheiro');
                    } else {
                        esc_html_e('"Baixar amostra" salva o arquivo em um zip, junto com uma nota de onde ele foi encontrado e por quê. O PHP deste servidor não consegue proteger zips com senha, então seu antivírus pode bloquear o download. O Facheiro nunca envia nada. O link do VirusTotal envia só o hash do arquivo, a partir do seu navegador.', 'facheiro');
                    }
                    ?>
                </p>
            </div>

            <?php if ($fp_view) : ?>
                <?php self::render_fp_rules($fp_rules, $datetime_format); ?>
            <?php endif; ?>

            <div class="facheiro-card">
                <div class="facheiro-card-head">
                    <h2><?php esc_html_e('Limpeza', 'facheiro'); ?></h2>
                </div>
                <p><?php esc_html_e('Esta página nunca altera arquivos. A limpeza e a restauração rodam pela linha de comando, onde você pode fazer um backup antes e conferir cada alteração:', 'facheiro'); ?></p>
                <pre class="facheiro-cli"><span class="facheiro-cli-comment"><?php esc_html_e('# Conferir e depois remover malware conhecido dos arquivos infectados', 'facheiro'); ?></span>
wp facheiro scan --dryrun
wp facheiro scan

<span class="facheiro-cli-comment"><?php esc_html_e('# Conferir e depois restaurar arquivos modificados do WordPress, dos plugins e dos temas', 'facheiro'); ?></span>
wp facheiro integrity --restore --dryrun
wp facheiro integrity --restore --quarantine-dir=/path/outside/webroot</pre>
                <p class="description"><?php esc_html_e('Sem WP-CLI? As mesmas verificações rodam com php bin/facheiro.php a partir da pasta do plugin; veja o readme.', 'facheiro'); ?></p>
            </div>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function settings_url()
    {
        return add_query_arg('tab', 'settings', self::page_url());
    }

    /**
     * The Settings tab: how scans run, automatic scans, access logs.
     */
    private static function render_settings_tab()
    {
        $settings = Facheiro_Settings::get();
        $log_real = '' === $settings['log'] ? '' : Facheiro_Settings::resolve_log_path($settings['log']);
        self::render_settings($settings, get_option('date_format') . ' ' . get_option('time_format'), Facheiro_Cron::next_run(), $log_real);
    }

    /**
     * The settings card: how scans run, automatic scans, access logs.
     */
    private static function render_settings(array $settings, $datetime_format, $next_run, $log_real)
    {
        ?>
        <div class="facheiro-card facheiro-settings" id="facheiro-settings">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Configurações', 'facheiro'); ?></h2>
            </div>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="facheiro_save_settings" />
                <?php wp_nonce_field(self::NONCE_SETTINGS); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php esc_html_e('Executar varreduras', 'facheiro'); ?> <?php self::help_button('facheiro-help-runner'); ?></th>
                        <td>
                            <fieldset>
                                <legend class="screen-reader-text"><?php esc_html_e('Executar varreduras', 'facheiro'); ?></legend>
                                <label><input type="radio" name="facheiro[runner]" value="background" <?php checked($settings['runner'], 'background'); ?> /> <?php esc_html_e('Em segundo plano (recomendado)', 'facheiro'); ?></label>
                                <p class="description"><?php esc_html_e('A varredura continua depois que você sai desta página.', 'facheiro'); ?></p>
                                <label><input type="radio" name="facheiro[runner]" value="browser" <?php checked($settings['runner'], 'browser'); ?> /> <?php esc_html_e('Só com esta página aberta', 'facheiro'); ?></label>
                                <p class="description"><?php esc_html_e('Use se as varreduras em segundo plano nunca terminam na sua hospedagem.', 'facheiro'); ?></p>
                            </fieldset>
                            <?php
                            self::help_text('facheiro-help-runner', array(
                                __('As varreduras em segundo plano rodam em pequenas etapas pelo WP-Cron, o executor de tarefas do WordPress. Para isso, o site precisa conseguir fazer uma requisição ao próprio wp-cron.php; Ferramentas > Saúde do site mostra isso como "requisições de loopback". Se a página perceber que uma varredura em segundo plano parou, ela continua a partir da aba do seu navegador.', 'facheiro'),
                                __('"Só com esta página aberta" roda as mesmas etapas a partir da aba do seu navegador. Fechar a aba pausa a varredura; abrir a página de novo a retoma.', 'facheiro'),
                            ));
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="facheiro-schedule"><?php esc_html_e('Varreduras automáticas', 'facheiro'); ?></label> <?php self::help_button('facheiro-help-schedule'); ?></th>
                        <td>
                            <select id="facheiro-schedule" name="facheiro[schedule]">
                                <?php foreach (Facheiro_Settings::schedules() as $value => $label) : ?>
                                    <option value="<?php echo esc_attr($value); ?>" <?php selected($settings['schedule'], $value); ?>><?php echo esc_html($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <span class="facheiro-schedule-when" <?php echo 'off' === $settings['schedule'] ? 'hidden' : ''; ?>>
                                <label for="facheiro-time"><?php esc_html_e('às', 'facheiro'); ?></label>
                                <input type="time" id="facheiro-time" name="facheiro[time]" value="<?php echo esc_attr($settings['time']); ?>" required />
                                <span class="facheiro-schedule-day" <?php echo 'weekly' === $settings['schedule'] ? '' : 'hidden'; ?>>
                                    <label for="facheiro-day"><?php esc_html_e('de', 'facheiro'); ?></label>
                                    <select id="facheiro-day" name="facheiro[day]">
                                        <?php for ($day = 0; $day < 7; $day++) : ?>
                                            <option value="<?php echo (int) $day; ?>" <?php selected((int) $settings['day'], $day); ?>><?php echo esc_html($GLOBALS['wp_locale']->get_weekday($day)); ?></option>
                                        <?php endfor; ?>
                                    </select>
                                </span>
                            </span>
                            <p class="description">
                                <?php
                                /* translators: %s: the site's timezone, for example UTC+2 or Europe/Lisbon */
                                printf(esc_html__('Varreduras programadas, sem que você precise iniciá-las. Os horários seguem o fuso horário do site (%s).', 'facheiro'), esc_html(wp_timezone_string()));
                                if (null !== $next_run) {
                                    echo ' ';
                                    /* translators: %s: date and time of the next automatic scan */
                                    printf(esc_html__('Próxima varredura: %s.', 'facheiro'), '<strong>' . esc_html(wp_date($datetime_format, $next_run)) . '</strong>');
                                }
                                ?>
                            </p>
                            <?php
                            self::help_text('facheiro-help-schedule', array(
                                __('Uma varredura automática é a mesma do botão Iniciar varredura. Ela sempre roda em segundo plano, verifica os logs de acesso informados abaixo e é pulada se outra varredura ainda estiver em andamento. Os resultados dela substituem os desta página.', 'facheiro'),
                                __('O WP-Cron inicia tarefas quando alguém visita o site, então, em um site com pouco movimento, uma varredura pode começar um pouco atrasada. Para horários exatos, peça à hospedagem para chamar o wp-cron.php por uma tarefa cron de verdade.', 'facheiro'),
                            ));
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="facheiro-settings-log"><?php esc_html_e('Logs de acesso', 'facheiro'); ?></label> <?php self::help_button('facheiro-help-log'); ?></th>
                        <td>
                            <input type="text" id="facheiro-settings-log" name="facheiro[log]" class="regular-text code" placeholder="/var/log/apache2" autocomplete="off" value="<?php echo esc_attr($settings['log']); ?>" />
                            <p class="description">
                                <?php esc_html_e('Opcional. Um arquivo ou pasta de logs do servidor web, verificado em toda varredura.', 'facheiro'); ?>
                                <?php if (is_wp_error($log_real)) : ?>
                                    <span class="facheiro-error"><?php esc_html_e('Este caminho não existe ou o PHP não consegue lê-lo, então as varreduras pulam os logs.', 'facheiro'); ?></span>
                                <?php endif; ?>
                            </p>
                            <?php
                            self::help_text('facheiro-help-log', array(
                                __('Os logs mostram requisições a web shells, ataques ao login e aos uploads e quais arquivos os invasores usaram. As varreduras só os leem; eles nunca são alterados nem enviados a lugar nenhum.', 'facheiro'),
                                __('Locais comuns são /var/log/apache2, /var/log/nginx ou uma pasta logs ao lado do site; o painel ou o suporte da hospedagem sabe dizer. Uma pasta inclui os arquivos rotacionados .log.1 e .gz. O usuário do PHP precisa conseguir lê-los. Deixe o campo vazio para pular esta verificação.', 'facheiro'),
                            ));
                            ?>
                        </td>
                    </tr>
                </table>
                <?php if (Facheiro_Cron::trigger_disabled()) : ?>
                    <p class="facheiro-note"><?php esc_html_e('DISABLE_WP_CRON está definido neste site, então o WordPress não inicia o WP-Cron sozinho. As varreduras em segundo plano e as automáticas só avançam quando a tarefa cron do servidor chama o wp-cron.php (a cada um ou dois minutos é o ideal).', 'facheiro'); ?></p>
                <?php endif; ?>
                <?php submit_button(__('Salvar configurações', 'facheiro'), 'primary', 'submit', false); ?>
            </form>
        </div>
        <?php
    }

    /**
     * A "?" button that shows or hides the help text with the same id.
     */
    public static function help_button($id)
    {
        printf(
            '<button type="button" class="facheiro-help-toggle" aria-expanded="false" aria-controls="%1$s" title="%2$s"><span aria-hidden="true">?</span><span class="screen-reader-text">%2$s</span></button>',
            esc_attr($id),
            esc_attr__('Saiba mais', 'facheiro')
        );
    }

    public static function help_text($id, array $paragraphs)
    {
        echo '<div class="facheiro-help-text" id="' . esc_attr($id) . '" hidden>';
        foreach ($paragraphs as $paragraph) {
            echo '<p>' . esc_html($paragraph) . '</p>';
        }
        echo '</div>';
    }

    /**
     * "Reviewed by NAME on DATE: note" for a saved false positive.
     */
    private static function rule_summary(array $rule, $datetime_format)
    {
        $user = !empty($rule['user']) ? get_userdata((int) $rule['user']) : false;
        $name = $user ? $user->display_name : __('um usuário excluído', 'facheiro');
        $when = !empty($rule['time']) ? wp_date($datetime_format, (int) $rule['time']) : '—';
        if (isset($rule['via']) && Facheiro_False_Positives::VIA_ASSISTANT === $rule['via']) {
            /* translators: 1: user display name, 2: date and time */
            $text = sprintf(__('Marcado como falso positivo por um assistente de IA agindo como %1$s em %2$s.', 'facheiro'), $name, $when);
        } else {
            /* translators: 1: user display name, 2: date and time */
            $text = sprintf(__('Marcado como falso positivo por %1$s em %2$s.', 'facheiro'), $name, $when);
        }
        if (!empty($rule['note'])) {
            $text .= ' ' . $rule['note'];
        }
        return $text;
    }

    /**
     * Every saved false positive, including those for findings that are
     * not in the current results (file since deleted, check not run).
     */
    private static function render_fp_rules(array $rules, $datetime_format)
    {
        $seal = Facheiro_Seal::status();
        $diff = $seal['diff']['false_positives'];
        $tampered = array_flip(array_merge($diff['added'], $diff['changed']));
        ?>
        <div class="facheiro-card facheiro-fp-rules" id="facheiro-fp-rules">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Falsos positivos salvos', 'facheiro'); ?></h2>
            </div>
            <p class="description"><?php esc_html_e('Cada um esconde o mesmo achado (mesmo tipo, local e detalhes) nas próximas varreduras. Para um achado sobre um arquivo, ele só vale enquanto o arquivo for exatamente o que foi revisado.', 'facheiro'); ?></p>
            <?php if (empty($rules)) : ?>
                <p><?php esc_html_e('Nenhum salvo.', 'facheiro'); ?></p>
            <?php else : ?>
                <div class="facheiro-table-scroll"><table class="widefat striped facheiro-table">
                    <thead><tr>
                        <th class="facheiro-col-type"><?php esc_html_e('Tipo', 'facheiro'); ?></th>
                        <th class="facheiro-col-path"><?php esc_html_e('Onde', 'facheiro'); ?></th>
                        <th><?php esc_html_e('Detalhes', 'facheiro'); ?></th>
                        <th class="facheiro-col-actions"><?php esc_html_e('Ações', 'facheiro'); ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rules as $fingerprint => $rule) : ?>
                        <?php
                        $rule = is_array($rule) ? $rule : array();
                        $path = isset($rule['path']) ? (string) $rule['path'] : '';
                        $short = Facheiro_Plugin::relative_path($path);
                        ?>
                        <?php $is_tampered = isset($tampered[(string) $fingerprint]); ?>
                        <tr data-fingerprint="<?php echo esc_attr($fingerprint); ?>" class="<?php echo $is_tampered ? 'facheiro-tampered' : ''; ?>">
                            <td><span class="facheiro-type"><?php echo esc_html(isset($rule['type']) ? $rule['type'] : ''); ?></span></td>
                            <td><code class="facheiro-path" title="<?php echo esc_attr($path); ?>"><?php echo esc_html($short); ?></code></td>
                            <td><?php echo esc_html(isset($rule['detail']) ? $rule['detail'] : ''); ?>
                                <?php if ($is_tampered) : ?>
                                    <p class="facheiro-tamper-badge"><?php esc_html_e('Alterado fora do Facheiro, por isso é ignorado. Mantenha-o só se um administrador fez essa alteração.', 'facheiro'); ?></p>
                                <?php else : ?>
                                    <p class="facheiro-fp-why"><?php echo esc_html(self::rule_summary($rule, $datetime_format)); ?></p>
                                <?php endif; ?></td>
                            <td class="facheiro-actions">
                                <?php if ($is_tampered) : ?>
                                    <button type="button" class="button button-small" data-fp-action="keep"><?php esc_html_e('Manter', 'facheiro'); ?></button>
                                <?php endif; ?>
                                <button type="button" class="button button-small" data-fp-action="unmark"><?php esc_html_e('Remover', 'facheiro'); ?></button></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table></div>
                <p><button type="button" class="button" data-fp-action="forget_all"><?php esc_html_e('Esquecer todos os falsos positivos', 'facheiro'); ?></button></p>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function status_word($status)
    {
        switch ($status) {
            case 'running':
                return __('em andamento', 'facheiro');
            case 'done':
                return __('concluída', 'facheiro');
            case 'failed':
                return __('falhou', 'facheiro');
            case 'cancelled':
                return __('cancelada', 'facheiro');
        }
        return $status;
    }
}
