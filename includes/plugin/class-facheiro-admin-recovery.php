<?php
/**
 * The Recovery tab: create or revoke the key that unlocks recovery.php, and
 * explain how to use it when WordPress itself is broken.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Admin_Recovery
{
    const NONCE = 'facheiro_recovery';

    public static function init()
    {
        add_action('admin_post_facheiro_recovery', array(__CLASS__, 'action'));
        add_action('wp_ajax_facheiro_recovery_create', array(__CLASS__, 'ajax_create'));
    }

    public static function url()
    {
        return add_query_arg('tab', 'recovery', Facheiro_Admin::page_url());
    }

    public static function action()
    {
        if (!Facheiro_Plugin::can_manage()) {
            wp_die(esc_html__('Você não tem permissão para fazer isso.', 'facheiro'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE);
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        $notices = array();
        if ('revoke' === $op) {
            $notices[] = Facheiro_Recovery_Key::revoke()
                ? array('success', __('Chave de recuperação revogada. A página de recuperação agora responde "não encontrada".', 'facheiro'))
                : array('error', __('Não foi possível apagar o arquivo da chave. Apague wp-content/facheiro-recovery-key.php à mão.', 'facheiro'));
        }
        Facheiro_Admin::notify($notices);
        wp_safe_redirect(self::url());
        exit;
    }

    /**
     * Create a key and hand it back in this response only: the key itself
     * is never stored anywhere (not even briefly in a transient), only its
     * SHA-256 in the key file.
     */
    public static function ajax_create()
    {
        check_ajax_referer(self::NONCE, 'nonce');
        if (!Facheiro_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('Você não tem permissão para fazer isso.', 'facheiro')), 403);
        }
        $expiry = isset($_POST['expiry']) ? sanitize_key(wp_unslash($_POST['expiry'])) : '7';
        if (!array_key_exists($expiry, Facheiro_Recovery_Key::expiries())) {
            $expiry = '7';
        }
        $key = Facheiro_Recovery_Key::create($expiry, wp_get_current_user()->user_login);
        if (is_wp_error($key)) {
            wp_send_json_error(array('message' => $key->get_error_message()), 500);
        }
        nocache_headers();
        wp_send_json_success(array('key' => $key, 'status' => self::status_text(Facheiro_Recovery_Key::status())));
    }

    /**
     * One line describing the key file.
     */
    private static function status_text($status)
    {
        $datetime_format = get_option('date_format') . ' ' . get_option('time_format');
        $relative_file = Facheiro_Plugin::relative_path(Facheiro_Recovery_Key::path());
        if (null === $status) {
            return __('Ainda não há chave. Crie uma enquanto o site funciona, para que o modo de recuperação esteja pronto se ele quebrar.', 'facheiro');
        }
        if (!$status['valid']) {
            /* translators: %s: file path */
            return sprintf(__('%s existe, mas não contém uma chave válida (uma chave digitada à mão precisa ter pelo menos 24 caracteres). O modo de recuperação fica desligado até ele ser corrigido ou substituído.', 'facheiro'), $relative_file);
        }
        if ($status['manual']) {
            /* translators: %s: file path */
            return sprintf(__('Uma chave foi adicionada à mão em %s. Ela não expira: revogue-a quando não precisar mais dela.', 'facheiro'), $relative_file);
        }
        $text = sprintf(
            /* translators: 1: date and time, 2: user name, 3: expiry date and time or "never" */
            __('Criada em %1$s por %2$s. Expira: %3$s.', 'facheiro'),
            wp_date($datetime_format, $status['created']),
            '' === $status['by'] ? '—' : $status['by'],
            0 === $status['expires'] ? __('nunca (até ser revogada)', 'facheiro') : wp_date($datetime_format, $status['expires'])
        );
        if (0 !== $status['expires'] && $status['expires'] <= time()) {
            $text .= ' ' . __('Esta chave expirou.', 'facheiro');
        }
        return $text;
    }

    public static function render()
    {
        $status = Facheiro_Recovery_Key::status();
        $active = Facheiro_Recovery_Key::active();
        $url = Facheiro_Recovery_Key::url();
        $relative_file = Facheiro_Plugin::relative_path(Facheiro_Recovery_Key::path());
        ?>
        <p class="facheiro-intro"><?php esc_html_e('Se um malware ou uma atualização com defeito derrubar o site (tela branca, "Houve um erro crítico neste site", um painel que não abre), páginas do WordPress como esta também param de funcionar. O modo de recuperação é uma página separada que não carrega o WordPress: ela mostra os erros de PHP que quebraram o site e roda a varredura completa, só de relatório, incluindo o banco de dados.', 'facheiro'); ?></p>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Chave de recuperação', 'facheiro'); ?></h2>
                <span class="facheiro-check facheiro-check-<?php echo $active ? 'protected' : 'unknown'; ?>"><?php echo $active ? esc_html__('Modo de recuperação ligado', 'facheiro') : esc_html__('Modo de recuperação desligado', 'facheiro'); ?></span>
            </div>

            <div class="facheiro-key-reveal" id="facheiro-key-reveal" hidden>
                <p><strong><?php esc_html_e('Sua chave de recuperação', 'facheiro'); ?></strong> — <?php esc_html_e('guarde-a agora no seu gerenciador de senhas. O Facheiro guarda só uma impressão digital dela e não consegue mostrá-la de novo.', 'facheiro'); ?></p>
                <p class="facheiro-key-row"><input type="text" readonly id="facheiro-recovery-key" class="large-text code facheiro-copy" value="" />
                    <button type="button" class="button button-primary" data-copy="facheiro-recovery-key"><?php esc_html_e('Copiar chave', 'facheiro'); ?></button></p>
            </div>

            <p id="facheiro-recovery-status"><?php echo esc_html(self::status_text($status)); ?></p>

            <p class="facheiro-field-inline">
                <strong><?php esc_html_e('Página de recuperação:', 'facheiro'); ?></strong>
                <code id="facheiro-recovery-url"><?php echo esc_html($url); ?></code>
                <button type="button" class="button button-small" data-copy-text="<?php echo esc_attr($url); ?>"><?php esc_html_e('Copiar endereço', 'facheiro'); ?></button>
            </p>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="facheiro-recovery-form">
                <input type="hidden" name="action" value="facheiro_recovery" />
                <?php wp_nonce_field(self::NONCE); ?>
                <label for="facheiro-recovery-expiry"><?php esc_html_e('Válida por', 'facheiro'); ?></label>
                <select id="facheiro-recovery-expiry" name="expiry">
                    <?php foreach (Facheiro_Recovery_Key::expiries() as $value => $label) : ?>
                        <option value="<?php echo esc_attr($value); ?>" <?php selected('30', $value); ?>><?php echo esc_html($label); ?></option>
                    <?php endforeach; ?>
                </select>
                <button type="button" id="facheiro-recovery-create" class="button button-primary" data-nonce="<?php echo esc_attr(wp_create_nonce(self::NONCE)); ?>" <?php echo null !== $status ? 'data-replace="1"' : ''; ?>><?php echo null === $status ? esc_html__('Criar chave de recuperação', 'facheiro') : esc_html__('Criar uma nova chave', 'facheiro'); ?></button>
                <button type="submit" name="op" value="revoke" class="button" data-confirm="recovery-revoke" <?php echo null === $status ? 'hidden' : ''; ?>><?php esc_html_e('Revogar', 'facheiro'); ?></button>
            </form>
            <p class="description"><?php esc_html_e('Criar uma nova chave substitui a anterior. Guarde a chave e o endereço da página juntos, fora deste site: você vai precisar deles justamente quando este site não puder mostrá-los.', 'facheiro'); ?></p>
        </div>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Quando o site cair', 'facheiro'); ?></h2>
            </div>
            <ol class="facheiro-steps">
                <li><?php esc_html_e('Abra o endereço da página de recuperação e digite a chave.', 'facheiro'); ?></li>
                <li><?php esc_html_e('Leia "O que quebrou o site": os erros de PHP mais recentes, com o plugin ou tema de onde vêm. Renomear a pasta desse plugin (por FTP ou pelo gerenciador de arquivos da hospedagem) costuma trazer o site de volta.', 'facheiro'); ?></li>
                <li><?php esc_html_e('Rode a varredura para ver se há malware envolvido. Ela é só de relatório, como a varredura desta página, e cobre os arquivos e o banco de dados.', 'facheiro'); ?></li>
                <li><?php esc_html_e('Faça a limpeza pela linha de comando (wp facheiro scan, ou php bin/facheiro.php sem WordPress) e depois revogue a chave.', 'facheiro'); ?></li>
            </ol>
        </div>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Sem chave, e o WordPress já quebrou?', 'facheiro'); ?> <?php Facheiro_Admin::help_button('facheiro-help-manual-key'); ?></h2>
            </div>
            <p><?php esc_html_e('Crie você mesmo o arquivo da chave por FTP, SFTP ou pelo gerenciador de arquivos da hospedagem:', 'facheiro'); ?></p>
            <ol class="facheiro-steps">
                <li>
                    <?php
                    /* translators: %s: file path */
                    printf(esc_html__('Crie o arquivo %s (ao lado da pasta de plugins).', 'facheiro'), '<code>' . esc_html($relative_file) . '</code>');
                    ?>
                </li>
                <li><?php esc_html_e('Coloque isto nele, trocando a chave de exemplo por um texto aleatório seu de pelo menos 24 caracteres:', 'facheiro'); ?>
                    <pre class="facheiro-cli"><?php echo esc_html(Facheiro_Recovery_Key::manual_template(wp_generate_password(32, false, false))); ?></pre></li>
                <li><?php esc_html_e('Abra a página de recuperação e digite essa chave. Apague o arquivo quando terminar.', 'facheiro'); ?></li>
            </ol>
            <p><?php esc_html_e('Com o WP-CLI no servidor, isto faz o mesmo:', 'facheiro'); ?> <code>wp facheiro recovery-key create --expires=7</code></p>
            <?php
            Facheiro_Admin::help_text('facheiro-help-manual-key', array(
                __('O arquivo começa com "<?php exit; ?>", então, mesmo que alguém o peça pela web, o servidor o executa e não mostra nada.', 'facheiro'),
                __('Se o próprio WP-CLI falhar por causa do plugin quebrado, acrescente --skip-plugins=<nome da pasta desse plugin>, ou crie o arquivo à mão.', 'facheiro'),
            ));
            ?>
        </div>

        <div class="facheiro-card">
            <div class="facheiro-card-head">
                <h2><?php esc_html_e('Como a página de recuperação é protegida', 'facheiro'); ?></h2>
            </div>
            <ul class="facheiro-examples">
                <li><?php esc_html_e('Sem um arquivo de chave válido e dentro da validade, ela responde "não encontrada" e não faz mais nada.', 'facheiro'); ?></li>
                <li><?php esc_html_e('Só uma impressão digital (SHA-256) de uma chave criada aqui é guardada, e a chave é mostrada a você uma única vez, sem ser salva em lugar nenhum. As chaves têm 32 caracteres aleatórios, então um palpite errado é simplesmente recusado. Uma chave digitada à mão no arquivo pode ser mais fraca: cada tentativa errada custa um segundo, e um cliente fica bloqueado por 15 minutos depois de 10 tentativas erradas.', 'facheiro'); ?></li>
                <li><?php esc_html_e('Um acesso dura uma hora, termina quando a chave é revogada ou substituída e fica preso a um cookie que a página define só para si mesma.', 'facheiro'); ?></li>
                <li><?php esc_html_e('Ela lê as configurações do banco de dados do wp-config.php sem executá-lo, só lê arquivos e o banco de dados e nunca altera nem envia nada.', 'facheiro'); ?></li>
                <li><?php esc_html_e('Use-a por HTTPS: em HTTP simples, a chave atravessa a rede sem criptografia.', 'facheiro'); ?></li>
            </ul>
        </div>
        <?php
    }

    public static function i18n()
    {
        return array(
            'recoveryReplace' => __('Criar uma nova chave? A atual deixa de funcionar.', 'facheiro'),
            'recoveryRevoke'  => __('Revogar a chave de recuperação? A página de recuperação deixa de funcionar até uma nova chave ser criada.', 'facheiro'),
            'recoveryOn'      => __('Modo de recuperação ligado', 'facheiro'),
            'recoveryNew'     => __('Criar uma nova chave', 'facheiro'),
        );
    }
}
