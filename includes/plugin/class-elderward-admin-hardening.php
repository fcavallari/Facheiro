<?php
/**
 * The Hardening tab: pick the web server, a template or individual
 * protections, preview the exact rules, then apply them (Apache/LiteSpeed)
 * or download the configuration file (Nginx), and check what the live site
 * enforces.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Admin_Hardening
{
    const NONCE = 'elderward_hardening';

    public static function init()
    {
        add_action('admin_post_elderward_harden', array(__CLASS__, 'action'));
        add_action('wp_ajax_elderward_harden_preview', array(__CLASS__, 'ajax_preview'));
        add_action('wp_ajax_elderward_harden_check', array(__CLASS__, 'ajax_check'));
    }

    public static function url()
    {
        return add_query_arg('tab', 'hardening', Elderward_Admin::page_url());
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
        if (!array_key_exists($server, Elderward_Hardening::servers())) {
            $server = 'apache';
        }
        if (!array_key_exists($preset, Elderward_Hardening::presets())) {
            $preset = 'custom';
        }
        return array($server, $preset, Elderward_Hardening::clean_features($features));
    }

    private static function require_access()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
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
        Elderward_Hardening::remember($server, $preset, $features);

        if ('download' === $op) {
            nocache_headers();
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="elderward-nginx.conf"');
            header('X-Content-Type-Options: nosniff');
            echo Elderward_Hardening::nginx_rules($features); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain-text configuration download.
            exit;
        }

        $notices = array();
        if ('apply' === $op || 'remove' === $op) {
            if ('apache' !== $server) {
                $notices[] = array('error', __('Elderward can only write rules for Apache or LiteSpeed. For Nginx, download the configuration file.', 'elderward'));
            } else {
                $report = 'remove' === $op ? Elderward_Hardening::remove() : Elderward_Hardening::apply($features);
                $notices = self::report_notices($report, $op);
            }
        }
        if (empty($notices)) {
            $notices[] = array('success', __('Choices saved.', 'elderward'));
        }
        Elderward_Admin::notify($notices);
        wp_safe_redirect(self::url());
        exit;
    }

    private static function report_notices(array $report, $op)
    {
        $notices = array();
        if (!$report['ok']) {
            $notices[] = array('error', '' !== $report['message'] ? $report['message'] : __('The rules could not be written, so nothing was changed.', 'elderward'));
            return $notices;
        }
        $changed = array();
        foreach ($report['files'] as $file) {
            $changed[] = Elderward_Plugin::relative_path($file['file']) . ' (' . self::action_word($file['action']) . ')';
        }
        if (empty($changed)) {
            $notices[] = array('info', 'remove' === $op ? __('There were no Elderward rules to remove.', 'elderward') : __('Nothing to change.', 'elderward'));
            return $notices;
        }
        $notices[] = array('success', ('remove' === $op
            ? __('Elderward rules removed. The site still answers normally.', 'elderward')
            : __('Protections applied. The site still answers normally.', 'elderward')) . ' ' . implode(', ', $changed) . '.');
        if ('apply' === $op) {
            $notices[] = array('info', __('Use "Check now" below to confirm that the server enforces each rule.', 'elderward'));
        }
        return $notices;
    }

    private static function action_word($action)
    {
        switch ($action) {
            case 'created':
                return __('created', 'elderward');
            case 'removed':
                return __('rules removed', 'elderward');
        }
        return __('updated', 'elderward');
    }

    public static function ajax_preview()
    {
        check_ajax_referer(self::NONCE, 'nonce');
        if (!Elderward_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('You are not allowed to do that.', 'elderward')), 403);
        }
        list($server, , $features) = self::choices();
        wp_send_json_success(self::preview($server, $features));
    }

    public static function ajax_check()
    {
        check_ajax_referer(self::NONCE, 'nonce');
        if (!Elderward_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('You are not allowed to do that.', 'elderward')), 403);
        }
        $results = Elderward_Hardening::check();
        $labels = array();
        foreach (Elderward_Hardening::features() as $id => $feature) {
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
            return array(array('file' => 'elderward-nginx.conf', 'content' => Elderward_Hardening::nginx_rules($features)));
        }
        $out = array();
        foreach (Elderward_Hardening::apache_preview($features) as $file => $lines) {
            $out[] = array(
                'file'    => Elderward_Plugin::relative_path($file),
                'content' => "# BEGIN Elderward\n" . implode("\n", $lines) . "\n# END Elderward\n",
            );
        }
        if (empty($out)) {
            $out[] = array('file' => '', 'content' => __('No protection selected: applying removes any Elderward rules.', 'elderward'));
        }
        return $out;
    }

    public static function render()
    {
        $state = Elderward_Hardening::state();
        $detected = Elderward_Hardening::detect_server();
        $features = Elderward_Hardening::features();
        $checked = isset($state['checked']['results']) ? $state['checked']['results'] : array();
        $datetime_format = get_option('date_format') . ' ' . get_option('time_format');
        $status_words = array(
            'protected' => __('Protected', 'elderward'),
            'exposed'   => __('Not protected', 'elderward'),
            'unknown'   => __('Not checked', 'elderward'),
        );
        ?>
        <p class="elderward-intro"><?php esc_html_e('Hardening tells the web server to refuse requests it should never serve: PHP dropped into uploads, copies of wp-config.php, .git folders, WordPress internals. It does not remove malware, but it stops many attacks from working and keeps a planted web shell from running.', 'elderward'); ?></p>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" id="elderward-harden-form" data-nonce="<?php echo esc_attr(wp_create_nonce(self::NONCE)); ?>">
            <input type="hidden" name="action" value="elderward_harden" />
            <?php wp_nonce_field(self::NONCE); ?>

            <div class="elderward-card">
                <div class="elderward-card-head">
                    <h2><span class="elderward-step">1</span> <?php esc_html_e('Your web server', 'elderward'); ?> <?php Elderward_Admin::help_button('elderward-help-server'); ?></h2>
                </div>
                <?php
                Elderward_Admin::help_text('elderward-help-server', array(
                    __('Apache and LiteSpeed read rules from .htaccess files inside the site\'s folders, so Elderward can write them for you. Nginx reads its configuration only from the server\'s own files, which PHP cannot (and should not) change: Elderward gives you a file to add to it.', 'elderward'),
                    __('Not sure? Most shared hosting runs Apache or LiteSpeed. Your host\'s documentation or support can tell you.', 'elderward'),
                ));
                ?>
                <div class="elderward-choice-row" role="radiogroup" aria-label="<?php esc_attr_e('Web server', 'elderward'); ?>">
                    <?php foreach (Elderward_Hardening::servers() as $value => $label) : ?>
                        <label class="elderward-choice">
                            <input type="radio" name="server" value="<?php echo esc_attr($value); ?>" <?php checked($state['server'], $value); ?> />
                            <span><?php echo esc_html($label); ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
                <p class="description">
                    <?php
                    if (null === $detected) {
                        esc_html_e('Elderward could not tell which server this site runs on.', 'elderward');
                    } else {
                        /* translators: %s: web server name */
                        printf(esc_html__('This site appears to run on %s.', 'elderward'), '<strong>' . esc_html('nginx' === $detected ? 'Nginx' : 'Apache / LiteSpeed') . '</strong>');
                    }
                    ?>
                </p>
            </div>

            <div class="elderward-card">
                <div class="elderward-card-head">
                    <h2><span class="elderward-step">2</span> <?php esc_html_e('Choose the protections', 'elderward'); ?></h2>
                </div>
                <div class="elderward-choice-row" role="radiogroup" aria-label="<?php esc_attr_e('Template', 'elderward'); ?>">
                    <?php foreach (Elderward_Hardening::presets() as $value => $label) : ?>
                        <label class="elderward-choice">
                            <input type="radio" name="preset" value="<?php echo esc_attr($value); ?>" <?php checked($state['preset'], $value); ?> data-features="<?php echo esc_attr(wp_json_encode('custom' === $value ? null : Elderward_Hardening::preset_features($value))); ?>" />
                            <span><?php echo esc_html($label); ?></span>
                        </label>
                    <?php endforeach; ?>
                </div>
                <p class="description"><?php esc_html_e('Recommended is safe for almost every site. Strict adds protections that can break some themes and integrations. Change any switch to make your own selection.', 'elderward'); ?></p>

                <ul class="elderward-features">
                    <?php foreach ($features as $id => $feature) : ?>
                        <?php $on = in_array($id, $state['features'], true); ?>
                        <li class="elderward-feature">
                            <label class="elderward-switch">
                                <input type="checkbox" name="features[]" value="<?php echo esc_attr($id); ?>" <?php checked($on); ?> />
                                <span class="elderward-switch-track" aria-hidden="true"></span>
                                <span class="elderward-feature-name"><?php echo esc_html($feature['label']); ?></span>
                            </label>
                            <span class="elderward-feature-tags">
                                <?php if (in_array('recommended', $feature['presets'], true)) : ?>
                                    <span class="elderward-tag"><?php esc_html_e('Recommended', 'elderward'); ?></span>
                                <?php elseif (in_array('strict', $feature['presets'], true)) : ?>
                                    <span class="elderward-tag elderward-tag-strict"><?php esc_html_e('Strict', 'elderward'); ?></span>
                                <?php else : ?>
                                    <span class="elderward-tag elderward-tag-risky"><?php esc_html_e('Test carefully', 'elderward'); ?></span>
                                <?php endif; ?>
                                <?php if (isset($checked[$id])) : ?>
                                    <span class="elderward-check elderward-check-<?php echo esc_attr($checked[$id]['status']); ?>" data-feature="<?php echo esc_attr($id); ?>"><?php echo esc_html($status_words[$checked[$id]['status']]); ?></span>
                                <?php else : ?>
                                    <span class="elderward-check" data-feature="<?php echo esc_attr($id); ?>" hidden></span>
                                <?php endif; ?>
                            </span>
                            <p class="elderward-feature-help"><?php echo esc_html($feature['help']); ?></p>
                            <p class="elderward-feature-risk"><strong><?php esc_html_e('Can break:', 'elderward'); ?></strong> <?php echo esc_html($feature['risk']); ?></p>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>

            <div class="elderward-card">
                <div class="elderward-card-head">
                    <h2><span class="elderward-step">3</span> <?php esc_html_e('Review and apply', 'elderward'); ?></h2>
                </div>
                <div data-server-only="apache">
                    <p><?php esc_html_e('Elderward adds these rules between "# BEGIN Elderward" and "# END Elderward" lines and leaves everything else in each file alone. It checks the site before and after, and if the site stops answering normally it puts every file back.', 'elderward'); ?></p>
                    <?php if (!empty($state['applied'])) : ?>
                        <p class="description">
                            <?php
                            $user = get_userdata((int) $state['user']);
                            printf(
                                /* translators: 1: number of protections, 2: user name, 3: date and time */
                                esc_html__('%1$d protections applied by %2$s on %3$s.', 'elderward'),
                                (int) count($state['applied']),
                                esc_html($user ? $user->display_name : __('a deleted user', 'elderward')),
                                esc_html(wp_date($datetime_format, (int) $state['time']))
                            );
                            ?>
                        </p>
                    <?php endif; ?>
                </div>
                <div data-server-only="nginx">
                    <ol class="elderward-steps">
                        <li><?php esc_html_e('Download the file below and put it on the server, for example as /etc/nginx/snippets/elderward.conf.', 'elderward'); ?></li>
                        <li><?php esc_html_e('Inside this site\'s server { } block, add the line: include snippets/elderward.conf; above the block that hands .php files to PHP (location ~ \.php$).', 'elderward'); ?></li>
                        <li><?php esc_html_e('Run nginx -t to test the configuration, then reload Nginx (systemctl reload nginx).', 'elderward'); ?></li>
                        <li><?php esc_html_e('Come back here and use "Check now" to confirm.', 'elderward'); ?></li>
                    </ol>
                    <p class="description"><?php esc_html_e('On managed hosting without server access, send the file to your host\'s support and ask them to include it.', 'elderward'); ?></p>
                </div>
                <div id="elderward-harden-preview" class="elderward-preview" aria-live="polite"></div>
                <p class="elderward-buttons">
                    <button type="submit" name="op" value="apply" class="button button-primary" data-server-only="apache" data-confirm="harden-apply"><?php esc_html_e('Apply protections', 'elderward'); ?></button>
                    <?php if (!empty($state['applied']) || !empty($state['files'])) : ?>
                        <button type="submit" name="op" value="remove" class="button" data-server-only="apache" data-confirm="harden-remove"><?php esc_html_e('Remove Elderward rules', 'elderward'); ?></button>
                    <?php endif; ?>
                    <button type="submit" name="op" value="download" class="button button-primary" data-server-only="nginx"><?php esc_html_e('Download Nginx configuration', 'elderward'); ?></button>
                    <button type="button" class="button" data-server-only="nginx" id="elderward-harden-copy"><?php esc_html_e('Copy', 'elderward'); ?></button>
                </p>
            </div>
        </form>

        <div class="elderward-card" id="elderward-harden-check">
            <div class="elderward-card-head">
                <h2><span class="elderward-step">4</span> <?php esc_html_e('Check the live site', 'elderward'); ?> <?php Elderward_Admin::help_button('elderward-help-check'); ?></h2>
                <div class="elderward-head-actions">
                    <button type="button" class="button" id="elderward-harden-check-run"><?php esc_html_e('Check now', 'elderward'); ?></button>
                </div>
            </div>
            <?php
            Elderward_Admin::help_text('elderward-help-check', array(
                __('Elderward sends harmless test requests to this site, such as a request for a PHP file in uploads that does not exist, and looks at how the server answers. A refusal means the rule works. Nothing is created on the site.', 'elderward'),
                __('It works whoever added the rules, so use it after including the Nginx file or editing .htaccess by hand. A firewall or CDN in front of the site can make a protection look active when the refusal comes from the firewall.', 'elderward'),
            ));
            ?>
            <p class="description" id="elderward-harden-check-when">
                <?php
                if (isset($state['checked']['time'])) {
                    /* translators: %s: date and time */
                    printf(esc_html__('Last checked %s. The result of each protection is shown next to its switch above.', 'elderward'), esc_html(wp_date($datetime_format, (int) $state['checked']['time'])));
                } else {
                    esc_html_e('Not checked yet.', 'elderward');
                }
                ?>
            </p>
            <ul class="elderward-check-list" id="elderward-harden-check-list">
                <?php foreach ($checked as $id => $result) : ?>
                    <?php if (!isset($features[$id])) { continue; } ?>
                    <li><span class="elderward-check elderward-check-<?php echo esc_attr($result['status']); ?>"><?php echo esc_html($status_words[$result['status']]); ?></span> <strong><?php echo esc_html($features[$id]['label']); ?></strong> <?php echo esc_html($result['detail']); ?></li>
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
            'hardenApply'   => __('Write these rules to the .htaccess files shown? Elderward checks the site afterwards and undoes the change if the site stops working.', 'elderward'),
            'hardenRemove'  => __('Remove every Elderward rule from the .htaccess files?', 'elderward'),
            'hardenChecking' => __('Checking…', 'elderward'),
            'statusProtected' => __('Protected', 'elderward'),
            'statusExposed'   => __('Not protected', 'elderward'),
            'statusUnknown'   => __('Not checked', 'elderward'),
            'checkedNow'      => __('Checked just now. The result of each protection is shown next to its switch above.', 'elderward'),
        );
    }
}
