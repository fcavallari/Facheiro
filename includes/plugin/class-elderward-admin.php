<?php
/**
 * Tools > Elderward: start a report-only scan, watch it progress, read
 * and export the findings.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Admin
{
    const PAGE = 'elderward';
    const NONCE_SCAN = 'elderward_scan';
    const NONCE_EXPORT = 'elderward_export';
    const NONCE_SETTINGS = 'elderward_settings';
    const NONCE_SAMPLE = 'elderward_sample_';
    const NONCE_SIGNATURES = 'elderward_signatures';
    const PER_PAGE = 200;
    // Seconds without a saved step after which the page treats the
    // background runner as stalled: it kicks WP-Cron once, then steps from
    // the browser.
    const STALE_SECONDS = 120;

    private static $hook_suffix = '';

    public static function init()
    {
        if (is_multisite()) {
            add_action('network_admin_menu', array(__CLASS__, 'register_network_menu'));
        } else {
            add_action('admin_menu', array(__CLASS__, 'register_menu'));
        }
        add_action('admin_enqueue_scripts', array(__CLASS__, 'enqueue'));
        add_action('wp_ajax_elderward_start', array(__CLASS__, 'ajax_start'));
        add_action('wp_ajax_elderward_step', array(__CLASS__, 'ajax_step'));
        add_action('wp_ajax_elderward_status', array(__CLASS__, 'ajax_status'));
        add_action('wp_ajax_elderward_cancel', array(__CLASS__, 'ajax_cancel'));
        add_action('wp_ajax_elderward_kick', array(__CLASS__, 'ajax_kick'));
        add_action('wp_ajax_elderward_fp', array(__CLASS__, 'ajax_false_positive'));
        add_action('admin_post_elderward_export', array(__CLASS__, 'export'));
        add_action('admin_post_elderward_sample', array(__CLASS__, 'sample'));
        add_action('admin_post_elderward_signature', array(__CLASS__, 'signature_action'));
        add_action('admin_post_elderward_signatures_export', array(__CLASS__, 'signatures_export'));
        add_action('wp_ajax_elderward_sig_test', array(__CLASS__, 'ajax_signature_test'));
        add_action('admin_post_elderward_save_settings', array(__CLASS__, 'save_settings'));
    }

    public static function page_url()
    {
        return is_multisite() ? network_admin_url('settings.php?page=' . self::PAGE) : admin_url('tools.php?page=' . self::PAGE);
    }

    public static function register_menu()
    {
        self::$hook_suffix = add_management_page(
            __('Elderward', 'elderward'),
            __('Elderward', 'elderward'),
            'manage_options',
            self::PAGE,
            array(__CLASS__, 'render_page')
        );
    }

    public static function register_network_menu()
    {
        self::$hook_suffix = add_submenu_page(
            'settings.php',
            __('Elderward', 'elderward'),
            __('Elderward', 'elderward'),
            'manage_network',
            self::PAGE,
            array(__CLASS__, 'render_page')
        );
    }

    public static function enqueue($hook_suffix)
    {
        if ($hook_suffix !== self::$hook_suffix) {
            return;
        }
        wp_enqueue_style('elderward-admin', ELDERWARD_URL . 'assets/admin.css', array(), ELDERWARD_VERSION);
        wp_enqueue_script('elderward-admin', ELDERWARD_URL . 'assets/admin.js', array(), ELDERWARD_VERSION, true);
        $job = Elderward_Job::current();
        wp_localize_script('elderward-admin', 'elderwardAdmin', array(
            'ajaxUrl'    => admin_url('admin-ajax.php'),
            'nonce'      => wp_create_nonce(self::NONCE_SCAN),
            'status'     => null === $job ? '' : $job['status'],
            'background' => null !== $job && !empty($job['background']),
            'stale'      => self::STALE_SECONDS,
            'i18n'       => array(
                'starting'   => __('Starting scan…', 'elderward'),
                /* translators: %s: name of the scanner currently running */
                'running'    => __('Scanning: %s', 'elderward'),
                'done'       => __('Scan complete. Reloading…', 'elderward'),
                /* translators: %s: error message */
                'failed'     => __('Scan failed: %s', 'elderward'),
                'cancelled'  => __('Scan cancelled.', 'elderward'),
                'network'    => __('Lost contact with the server; retrying…', 'elderward'),
                'confirm'    => __('Cancel the running scan?', 'elderward'),
                /* translators: %d: seconds since the background runner last saved progress */
                'idle'       => __('last activity %d s ago', 'elderward'),
                'background' => __('Running in the background through WP-Cron: you can leave this page and come back later.', 'elderward'),
                'browser'    => __('Keep this page open: the scan runs in short steps from this tab.', 'elderward'),
                'fpPrompt'   => __('Mark this finding as a false positive? Optionally say why (kept with the decision):', 'elderward'),
                'fpMarked'   => __('Marked as a false positive. Later scans hide it until the file changes.', 'elderward'),
                'fpUndo'     => __('Undo', 'elderward'),
                'fpRemoved'  => __('No longer treated as a false positive; it shows again in the findings.', 'elderward'),
                'fpForget'   => __('Forget every saved false positive? Matching findings show again in the results.', 'elderward'),
                'sigNone'    => __('No signature matches.', 'elderward'),
                /* translators: %d: number of matching signatures */
                'sigHits'    => __('%d signature(s) match:', 'elderward'),
                'disabled'   => __('disabled', 'elderward'),
                'copied'     => __('Copied.', 'elderward'),
                'sigDelete'  => __('Delete this custom signature?', 'elderward'),
                'takeover'   => __('The background runner has not reported progress for a while, so the scan continues from this tab for as long as it stays open. Check that this site can reach its own wp-cron.php (Site Health), or switch the runner setting to this browser tab.', 'elderward'),
            ),
        ));
    }

    private static function require_access()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('You are not allowed to do that.', 'elderward')), 403);
        }
    }

    public static function ajax_start()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();

        $options = array();
        $log = isset($_POST['log']) ? sanitize_text_field(wp_unslash($_POST['log'])) : '';
        // The only free-text input: it must name an existing, readable log
        // file or directory. Nothing else is accepted.
        $real = Elderward_Settings::resolve_log_path($log);
        if (is_wp_error($real)) {
            wp_send_json_error(array('message' => $real->get_error_message()), 400);
        }
        if ('' !== $real) {
            $options['scanlog'] = $real;
        }

        $job = Elderward_Job::start($options, 'manual');
        if (is_wp_error($job)) {
            wp_send_json_error(array('message' => $job->get_error_message()), 409);
        }
        if (!empty($job['background'])) {
            Elderward_Cron::kick();
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
        $job = Elderward_Job::current();
        if (null !== $job && 'running' === $job['status'] && !empty($job['background'])) {
            Elderward_Cron::kick();
        }
        wp_send_json_success(self::status_payload($job));
    }

    public static function ajax_step()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        $job = Elderward_Job::step();
        wp_send_json_success(self::status_payload($job));
    }

    public static function ajax_status()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        wp_send_json_success(self::status_payload(Elderward_Job::current()));
    }

    public static function ajax_cancel()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        wp_send_json_success(self::status_payload(Elderward_Job::cancel()));
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
            $rule = Elderward_False_Positives::mark($id, $note);
            if (is_wp_error($rule)) {
                wp_send_json_error(array('message' => $rule->get_error_message()), 400);
            }
            wp_send_json_success(array('fingerprint' => Elderward_False_Positives::fingerprint($rule['type'], $rule['path'], $rule['detail'])));
        }
        if ('unmark' === $op) {
            $fingerprint = isset($_POST['fingerprint']) ? sanitize_key(wp_unslash($_POST['fingerprint'])) : '';
            if (1 !== preg_match('/^[0-9a-f]{40}$/', $fingerprint)) {
                wp_send_json_error(array('message' => __('Unknown false positive.', 'elderward')), 400);
            }
            Elderward_False_Positives::unmark($fingerprint);
            wp_send_json_success(array());
        }
        if ('forget_all' === $op) {
            Elderward_False_Positives::forget_all();
            wp_send_json_success(array());
        }
        wp_send_json_error(array('message' => __('Unknown request.', 'elderward')), 400);
    }

    /**
     * Download one flagged file as an encrypted sample zip for analysis.
     * The administrator submits it; the site never uploads anything.
     */
    public static function sample()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        $id = isset($_GET['id']) ? absint($_GET['id']) : 0;
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::NONCE_SAMPLE . $id)) {
            wp_die(esc_html__('Expired link, go back and try again.', 'elderward'), '', array('response' => 403));
        }
        $finding = Elderward_False_Positives::finding($id);
        if (null === $finding) {
            wp_die(esc_html__('That finding is not part of the current results.', 'elderward'), '', array('response' => 404, 'back_link' => true));
        }
        $zip = Elderward_Sample::build($finding);
        if (is_wp_error($zip)) {
            wp_die(esc_html($zip->get_error_message()), esc_html__('Sample not available', 'elderward'), array('response' => 409, 'back_link' => true));
        }
        nocache_headers();
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="elderward-sample-' . (int) $id . '-' . gmdate('Ymd-His') . '.zip"');
        header('Content-Length: ' . (int) filesize($zip));
        header('X-Content-Type-Options: nosniff');
        readfile($zip); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- streams our own temporary zip to the administrator.
        @unlink($zip); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- our own temporary file.
        exit;
    }

    private static function signatures_url($args = array())
    {
        return add_query_arg(array_merge(array('tab' => 'signatures'), $args), self::page_url());
    }

    private static function notify(array $notices)
    {
        set_transient('elderward_notice_' . get_current_user_id(), $notices, MINUTE_IN_SECONDS);
    }

    /**
     * Signature editor form target: save, delete, enable/disable, import.
     */
    public static function signature_action()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE_SIGNATURES);
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        $id = isset($_POST['id']) ? sanitize_text_field(wp_unslash($_POST['id'])) : '';
        $back = array();

        if ('save' === $op) {
            // Patterns are kept byte for byte (a signature for "<?php" must
            // survive), validated by the engine, and only ever printed escaped.
            $conditions_raw = isset($_POST['conditions']) ? (string) wp_unslash($_POST['conditions']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- regex/text patterns, validated by Elderward_Signatures and the engine; escaped on output.
            $input = array(
                'id'          => $id,
                'target'      => isset($_POST['target']) ? sanitize_key(wp_unslash($_POST['target'])) : 'file',
                'severity'    => isset($_POST['severity']) ? sanitize_key(wp_unslash($_POST['severity'])) : 'high',
                'description' => isset($_POST['description']) ? sanitize_text_field(wp_unslash($_POST['description'])) : '',
                'enabled'     => !empty($_POST['enabled']),
            );
            $original = isset($_POST['original_id']) ? sanitize_text_field(wp_unslash($_POST['original_id'])) : '';
            $conditions = Elderward_Signatures::parse_conditions($conditions_raw);
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
                $result = Elderward_Signatures::save($input, $original);
            }
            if (is_wp_error($result)) {
                self::notify(array(array('error', $result->get_error_message())));
                set_transient('elderward_sigform_' . get_current_user_id(), array_merge($input, array('conditions' => $conditions_raw, 'original_id' => $original)), MINUTE_IN_SECONDS);
                $back = array('edit' => '' === $original ? 'new' : $original);
            } else {
                /* translators: %s: signature id */
                self::notify(array(array('success', sprintf(__('Signature %s saved. It applies from the next scan.', 'elderward'), $result['id']))));
            }
        } elseif ('delete' === $op) {
            Elderward_Signatures::delete($id);
            /* translators: %s: signature id */
            self::notify(array(array('success', sprintf(__('Signature %s deleted.', 'elderward'), $id))));
        } elseif ('enable' === $op || 'disable' === $op) {
            $result = Elderward_Signatures::set_enabled($id, 'enable' === $op);
            self::notify(array(is_wp_error($result) ? array('error', $result->get_error_message()) : array('success', 'enable' === $op ? __('Signature enabled.', 'elderward') : __('Signature disabled.', 'elderward'))));
        } elseif ('import' === $op) {
            $json = isset($_POST['json']) ? (string) wp_unslash($_POST['json']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON signature file, parsed and validated entry by entry; escaped on output.
            $result = Elderward_Signatures::import($json);
            /* translators: %d: number of signatures */
            self::notify(array(is_wp_error($result) ? array('error', $result->get_error_message()) : array('success', sprintf(_n('%d signature imported.', '%d signatures imported.', $result, 'elderward'), $result))));
        }
        wp_safe_redirect(self::signatures_url($back));
        exit;
    }

    public static function signatures_export()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::NONCE_SIGNATURES)) {
            wp_die(esc_html__('Expired link, go back and try again.', 'elderward'), '', array('response' => 403));
        }
        nocache_headers();
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="elderward-signatures-' . gmdate('Ymd-His') . '.json"');
        echo Elderward_Signatures::export_json(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download.
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
            $text = Elderward_Signatures::read_site_file($path);
            if (is_wp_error($text)) {
                wp_send_json_error(array('message' => $text->get_error_message()), 400);
            }
        } else {
            $text = isset($_POST['text']) ? (string) wp_unslash($_POST['text']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sample text matched in memory, never stored or echoed.
        }
        wp_send_json_success(array('hits' => Elderward_Signatures::test($text)));
    }

    private static function render_signatures_tab()
    {
        $defs = Elderward_Signatures::all();
        $edit_id = isset($_GET['edit']) ? sanitize_text_field(wp_unslash($_GET['edit'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- selects which row to show in the form.
        $form = array('id' => '', 'target' => 'file', 'severity' => 'HIGH', 'description' => '', 'enabled' => true, 'conditions' => '', 'original_id' => '');
        if ('' !== $edit_id && 'new' !== $edit_id) {
            $def = Elderward_Signatures::get($edit_id);
            if (null !== $def) {
                $form = array_merge($form, $def, array('conditions' => Elderward_Signatures::conditions_text($def), 'original_id' => $def['id']));
            }
        }
        $key = 'elderward_sigform_' . get_current_user_id();
        $kept = get_transient($key);
        if (is_array($kept)) {
            delete_transient($key);
            $form = array_merge($form, $kept);
        }
        $targets = array('file' => __('Files', 'elderward'), 'db_option' => __('Database options', 'elderward'), 'db_post' => __('Database posts', 'elderward'));
        $builtin = Elderward_Signatures::builtin_listing();
        ?>
        <p class="description"><?php esc_html_e('Add signatures for threats specific to this site. Custom signatures only detect: a match is reported as a finding (SIGNATURE_MATCH for files), and nothing is ever cleaned or deleted because of one, not even by the command-line cleanup. Changes apply from the next scan.', 'elderward'); ?></p>

        <div class="elderward-card">
            <h2><?php esc_html_e('Custom signatures', 'elderward'); ?></h2>
            <?php if (empty($defs)) : ?>
                <p><?php esc_html_e('None yet.', 'elderward'); ?></p>
            <?php else : ?>
                <table class="widefat striped elderward-table elderward-sig-table">
                    <thead><tr>
                        <th><?php esc_html_e('Id', 'elderward'); ?></th>
                        <th><?php esc_html_e('Looks at', 'elderward'); ?></th>
                        <th class="elderward-col-sev"><?php esc_html_e('Severity', 'elderward'); ?></th>
                        <th><?php esc_html_e('Conditions', 'elderward'); ?></th>
                        <th class="elderward-col-actions"><?php esc_html_e('Actions', 'elderward'); ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($defs as $def) : ?>
                        <?php $enabled = !isset($def['enabled']) || $def['enabled']; ?>
                        <tr class="<?php echo $enabled ? '' : 'elderward-disabled'; ?>">
                            <td><code><?php echo esc_html($def['id']); ?></code><?php echo $enabled ? '' : ' <em>(' . esc_html__('disabled', 'elderward') . ')</em>'; ?>
                                <?php if ('' !== (string) $def['description']) : ?><p class="description"><?php echo esc_html($def['description']); ?></p><?php endif; ?></td>
                            <td><?php echo esc_html(isset($targets[$def['target']]) ? $targets[$def['target']] : $def['target']); ?></td>
                            <td><span class="elderward-sev elderward-sev-<?php echo esc_attr(strtolower($def['severity'])); ?>"><?php echo esc_html($def['severity']); ?></span></td>
                            <td><pre class="elderward-conditions"><?php echo esc_html(Elderward_Signatures::conditions_text($def)); ?></pre></td>
                            <td class="elderward-actions">
                                <a class="button button-small" href="<?php echo esc_url(self::signatures_url(array('edit' => $def['id']))); ?>#elderward-sig-form"><?php esc_html_e('Edit', 'elderward'); ?></a>
                                <?php self::signature_button($def['id'], $enabled ? 'disable' : 'enable', $enabled ? __('Disable', 'elderward') : __('Enable', 'elderward')); ?>
                                <?php self::signature_button($def['id'], 'delete', __('Delete', 'elderward')); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <div class="elderward-card" id="elderward-sig-form">
            <h2><?php echo '' === $form['original_id'] ? esc_html__('Add a signature', 'elderward') : esc_html__('Edit signature', 'elderward'); ?></h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="elderward_signature" />
                <input type="hidden" name="op" value="save" />
                <input type="hidden" name="original_id" value="<?php echo esc_attr($form['original_id']); ?>" />
                <?php wp_nonce_field(self::NONCE_SIGNATURES); ?>
                <table class="form-table" role="presentation">
                    <tr><th scope="row"><label for="elderward-sig-id"><?php esc_html_e('Id', 'elderward'); ?></label></th>
                        <td><input type="text" id="elderward-sig-id" name="id" class="regular-text code" value="<?php echo esc_attr($form['id']); ?>" pattern="[a-z0-9][a-z0-9._\-]{1,62}" required />
                            <p class="description"><?php esc_html_e('Lowercase letters, digits, dot, dash, underscore. Findings name it as custom.<id>.', 'elderward'); ?></p></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-target"><?php esc_html_e('Looks at', 'elderward'); ?></label></th>
                        <td><select id="elderward-sig-target" name="target">
                            <?php foreach ($targets as $value => $label) : ?>
                                <option value="<?php echo esc_attr($value); ?>" <?php selected($form['target'], $value); ?>><?php echo esc_html($label); ?></option>
                            <?php endforeach; ?>
                        </select></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-severity"><?php esc_html_e('Severity', 'elderward'); ?></label></th>
                        <td><select id="elderward-sig-severity" name="severity">
                            <?php foreach (array('HIGH', 'MEDIUM', 'LOW') as $severity) : ?>
                                <option value="<?php echo esc_attr(strtolower($severity)); ?>" <?php selected(strtoupper($form['severity']), $severity); ?>><?php echo esc_html($severity); ?></option>
                            <?php endforeach; ?>
                        </select></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-description"><?php esc_html_e('Description', 'elderward'); ?></label></th>
                        <td><input type="text" id="elderward-sig-description" name="description" class="large-text" value="<?php echo esc_attr($form['description']); ?>" maxlength="300" /></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-conditions"><?php esc_html_e('Conditions', 'elderward'); ?></label></th>
                        <td><textarea id="elderward-sig-conditions" name="conditions" class="large-text code" rows="5" required><?php echo esc_textarea($form['conditions']); ?></textarea>
                            <p class="description"><?php esc_html_e('One per line, starting with "text:" (exact text) or "regex:" (a PCRE pattern with delimiters, such as /eval\s*\(/i). For files every line must match, and the first is checked first, so make it a short text. Only files with the usual risky extensions and under 2 MB are scanned. Database signatures take a single regex line.', 'elderward'); ?></p></td></tr>
                    <tr><th scope="row"><?php esc_html_e('Status', 'elderward'); ?></th>
                        <td><label><input type="checkbox" name="enabled" value="1" <?php checked(!empty($form['enabled'])); ?> /> <?php esc_html_e('Enabled', 'elderward'); ?></label></td></tr>
                </table>
                <?php submit_button('' === $form['original_id'] ? __('Add signature', 'elderward') : __('Save signature', 'elderward'), 'primary', 'submit', false); ?>
                <?php if ('' !== $form['original_id']) : ?>
                    <a class="button" href="<?php echo esc_url(self::signatures_url()); ?>"><?php esc_html_e('Cancel', 'elderward'); ?></a>
                <?php endif; ?>
            </form>
        </div>

        <div class="elderward-card" id="elderward-sig-test">
            <h2><?php esc_html_e('Test signatures', 'elderward'); ?></h2>
            <p class="description"><?php esc_html_e('Paste a sample, or give a file of this site, and see which built-in and custom signatures match. Nothing is saved; only the names of matching signatures come back.', 'elderward'); ?></p>
            <p><label for="elderward-test-path"><?php esc_html_e('File on this site (path inside the WordPress folder)', 'elderward'); ?></label><br />
                <input type="text" id="elderward-test-path" class="large-text code" placeholder="wp-content/uploads/2026/shell.php" autocomplete="off" /></p>
            <p><label for="elderward-test-text"><?php esc_html_e('Or paste text', 'elderward'); ?></label><br />
                <textarea id="elderward-test-text" class="large-text code" rows="6"></textarea></p>
            <p><button type="button" class="button" id="elderward-test-run"><?php esc_html_e('Test', 'elderward'); ?></button></p>
            <div id="elderward-test-result" aria-live="polite"></div>
        </div>

        <div class="elderward-card">
            <h2><?php esc_html_e('Import and export', 'elderward'); ?></h2>
            <p><a class="button" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=elderward_signatures_export'), self::NONCE_SIGNATURES)); ?>"><?php esc_html_e('Export custom signatures (JSON)', 'elderward'); ?></a></p>
            <p class="description"><?php esc_html_e('The same file works with the standalone scanner: php bin/elderward.php scanall=1 signatures=signatures.json', 'elderward'); ?></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="elderward_signature" />
                <input type="hidden" name="op" value="import" />
                <?php wp_nonce_field(self::NONCE_SIGNATURES); ?>
                <p><label for="elderward-sig-import"><?php esc_html_e('Import: paste a signature file. Signatures with the same id are replaced; one invalid entry rejects the whole file.', 'elderward'); ?></label></p>
                <textarea id="elderward-sig-import" name="json" class="large-text code" rows="6" placeholder='{"elderward_signatures": 1, "signatures": [ ... ]}' required></textarea>
                <?php submit_button(__('Import', 'elderward'), 'secondary', 'submit', false); ?>
            </form>
        </div>

        <details class="elderward-card elderward-builtin">
            <summary><h2><?php
                /* translators: %d: number of built-in signatures */
                printf(esc_html__('Built-in signatures (%d)', 'elderward'), count($builtin));
            ?></h2></summary>
            <p class="description"><?php esc_html_e('Shipped with Elderward and read-only. Access log and crontab patterns are not listed here.', 'elderward'); ?></p>
            <table class="widefat striped elderward-table">
                <thead><tr>
                    <th><?php esc_html_e('Name', 'elderward'); ?></th>
                    <th><?php esc_html_e('Looks at', 'elderward'); ?></th>
                    <th class="elderward-col-sev"><?php esc_html_e('Severity', 'elderward'); ?></th>
                    <th><?php esc_html_e('Conditions', 'elderward'); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach ($builtin as $sig) : ?>
                    <tr>
                        <td><code><?php echo esc_html($sig['id']); ?></code><p class="description"><?php echo esc_html($sig['description']); ?></p></td>
                        <td><?php echo esc_html($targets[$sig['target']]); ?></td>
                        <td><span class="elderward-sev elderward-sev-<?php echo esc_attr(strtolower($sig['severity'])); ?>"><?php echo esc_html($sig['severity']); ?></span></td>
                        <td><pre class="elderward-conditions"><?php echo esc_html($sig['conditions']); ?></pre></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </details>
        <?php
    }

    private static function render_assistants_tab()
    {
        $abilities = function_exists('wp_register_ability');
        $adapter = class_exists('WP\\MCP\\Core\\McpAdapter');
        $login = wp_get_current_user()->user_login;
        $stdio = wp_json_encode(array('mcpServers' => array('elderward' => array(
            'command' => 'wp',
            'args'    => array('--path=' . untrailingslashit(ABSPATH), 'mcp-adapter', 'serve', '--server=mcp-adapter-default-server', '--user=' . $login),
        ))), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $remote = wp_json_encode(array('mcpServers' => array('elderward' => array(
            'command' => 'npx',
            'args'    => array('-y', '@automattic/mcp-wordpress-remote@latest'),
            'env'     => array(
                'WP_API_URL'      => rest_url('mcp/mcp-adapter-default-server'),
                'WP_API_USERNAME' => $login,
                'WP_API_PASSWORD' => 'paste-an-application-password-here',
            ),
        ))), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        ?>
        <p class="description"><?php esc_html_e('Connect Claude, ChatGPT, Antigravity, Cursor or any other assistant that speaks the Model Context Protocol (MCP), and it can run scans, explain the findings, read flagged files, draft and test signatures, and record false positives, as you, from the chat.', 'elderward'); ?></p>

        <div class="elderward-card">
            <h2><?php esc_html_e('1. Requirements', 'elderward'); ?></h2>
            <ul class="elderward-checklist">
                <li class="<?php echo $abilities ? 'is-ok' : 'is-missing'; ?>"><?php echo $abilities ? esc_html__('WordPress 6.9 or later: Elderward\'s abilities are registered.', 'elderward') : esc_html__('WordPress 6.9 or later is needed (it adds the Abilities API). Update WordPress, or use the brief at the bottom of this page.', 'elderward'); ?></li>
                <li class="<?php echo $adapter ? 'is-ok' : 'is-missing'; ?>">
                    <?php if ($adapter) : ?>
                        <?php esc_html_e('The MCP Adapter plugin is active.', 'elderward'); ?>
                    <?php else : ?>
                        <?php esc_html_e('Install and activate the official MCP Adapter plugin from the WordPress project:', 'elderward'); ?>
                        <a href="https://github.com/WordPress/mcp-adapter/releases" target="_blank" rel="noopener noreferrer">github.com/WordPress/mcp-adapter</a>
                    <?php endif; ?>
                </li>
            </ul>
        </div>

        <div class="elderward-card">
            <h2><?php esc_html_e('2. Add the server to your assistant', 'elderward'); ?></h2>
            <p><?php esc_html_e('Paste one of these into your assistant\'s MCP server settings (Claude Desktop: Settings, Developer, Edit Config; Claude Code: claude mcp add-json elderward with the inner object; Antigravity, Cursor and others: their MCP config file).', 'elderward'); ?></p>
            <h3><?php esc_html_e('The assistant runs on a machine with WP-CLI access to this site', 'elderward'); ?></h3>
            <p class="description"><?php esc_html_e('For example Claude Code on the server, or a local copy of the site. Nothing goes over the network.', 'elderward'); ?></p>
            <textarea class="large-text code elderward-copy" rows="11" readonly><?php echo esc_textarea($stdio); ?></textarea>
            <h3><?php esc_html_e('The assistant runs on your computer, the site is elsewhere', 'elderward'); ?></h3>
            <p class="description">
                <?php esc_html_e('Needs Node.js on your computer. Create an application password for your user and paste it in place of the placeholder; revoke it when the investigation is over.', 'elderward'); ?>
                <a href="<?php echo esc_url(admin_url('profile.php#application-passwords-section')); ?>"><?php esc_html_e('Create an application password', 'elderward'); ?></a>
            </p>
            <textarea class="large-text code elderward-copy" rows="14" readonly><?php echo esc_textarea($remote); ?></textarea>
            <p class="description"><?php esc_html_e('ChatGPT connects to MCP servers on the internet itself instead of running a local command, and only where your plan and its connector settings allow custom servers. If yours does not, use the brief below.', 'elderward'); ?></p>
        </div>

        <div class="elderward-card">
            <h2><?php esc_html_e('3. Ask', 'elderward'); ?></h2>
            <ul class="elderward-examples">
                <li><?php esc_html_e('"Use the Elderward triage prompt." (it is listed among the server\'s prompts)', 'elderward'); ?></li>
                <li><?php esc_html_e('"Scan my site with Elderward and tell me whether it is hacked."', 'elderward'); ?></li>
                <li><?php esc_html_e('"Explain the HIGH findings and what I should do about each."', 'elderward'); ?></li>
                <li><?php esc_html_e('"There is a backdoor Elderward missed in wp-content/plugins/acme/loader.php: write a signature for it, test it against that file and a clean plugin, then save it."', 'elderward'); ?></li>
            </ul>
            <p class="elderward-note"><?php esc_html_e('The assistant acts with your account but has no tool to clean, restore or change site files: cleanup stays a command you run yourself. Everything a scan reads from the site may have been written by the attacker, and Elderward labels it as untrusted data for the assistant. Still, do not let an assistant mark findings as false positives without checking its reasoning.', 'elderward'); ?></p>
        </div>

        <div class="elderward-card">
            <h2><?php esc_html_e('No MCP? Copy a brief for any chatbot', 'elderward'); ?></h2>
            <p class="description"><?php esc_html_e('The triage instructions and up to 100 of the most severe findings of the last scan, ready to paste into any chat. It contains file paths and snippets from this site; share it only with a service you trust with them.', 'elderward'); ?></p>
            <textarea id="elderward-brief" class="large-text code elderward-copy" rows="14" readonly><?php echo esc_textarea(Elderward_Abilities::brief()); ?></textarea>
            <p><button type="button" class="button" data-copy="elderward-brief"><?php esc_html_e('Copy brief', 'elderward'); ?></button></p>
        </div>
        <?php
    }

    private static function signature_button($id, $op, $label)
    {
        ?>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="elderward-inline-form" <?php echo 'delete' === $op ? 'data-confirm="sig-delete"' : ''; ?>>
            <input type="hidden" name="action" value="elderward_signature" />
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
            'percent'    => Elderward_Job::percent($job),
            'stage'      => Elderward_Job::stage_label($job),
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
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE_SETTINGS);

        $raw = isset($_POST['elderward']) && is_array($_POST['elderward']) ? wp_unslash($_POST['elderward']) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each scalar is sanitized below, then whitelisted in Elderward_Settings::sanitize().
        $input = array();
        foreach ($raw as $key => $value) {
            if (is_scalar($value)) {
                $input[sanitize_key($key)] = sanitize_text_field((string) $value);
            }
        }
        $settings = Elderward_Settings::save($input);

        $notices = array(array('success', __('Settings saved.', 'elderward')));
        if ('' !== $settings['log']) {
            $real = Elderward_Settings::resolve_log_path($settings['log']);
            if (is_wp_error($real)) {
                $notices[] = array('warning', __('The access log path for scheduled scans does not exist or is not readable by PHP; scheduled scans will skip the log check until it is.', 'elderward'));
            }
        }
        if ('background' === $settings['runner'] || 'off' !== $settings['schedule']) {
            if (Elderward_Cron::trigger_disabled()) {
                $notices[] = array('warning', __('DISABLE_WP_CRON is set on this site, so WordPress does not trigger WP-Cron on its own. Background and scheduled scans only advance when your server\'s cron job calls wp-cron.php.', 'elderward'));
            } else {
                $loopback = self::loopback_problem();
                if (null !== $loopback) {
                    $notices[] = array('warning', sprintf(
                        /* translators: %s: the Site Health loopback error */
                        __('This site could not reach its own wp-cron.php (%s). Background scans will only advance while the Elderward page is open, and scheduled scans may never start. Fix the loopback problem shown in Site Health, or switch the runner to the browser tab.', 'elderward'),
                        $loopback
                    ));
                }
            }
        }
        set_transient('elderward_notice_' . get_current_user_id(), $notices, MINUTE_IN_SECONDS);
        wp_safe_redirect(self::page_url());
        exit;
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
        return '' === $message ? __('loopback request failed', 'elderward') : $message;
    }

    private static function take_notices()
    {
        $key = 'elderward_notice_' . get_current_user_id();
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
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::NONCE_EXPORT)) {
            wp_die(esc_html__('Expired link, go back and try again.', 'elderward'), '', array('response' => 403));
        }
        $format = (isset($_GET['format']) && 'json' === $_GET['format']) ? 'json' : 'txt';
        $job = Elderward_Job::current();
        $job_id = null === $job ? '' : $job['id'];

        nocache_headers();
        header('Content-Type: ' . ('json' === $format ? 'application/x-ndjson' : 'text/plain') . '; charset=utf-8');
        header('Content-Disposition: attachment; filename="elderward-findings-' . gmdate('Ymd-His') . '.' . $format . '"');

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
                if (Elderward_False_Positives::MATCHED === $fp) {
                    $event['false_positive'] = true;
                } elseif (Elderward_False_Positives::CHANGED === $fp) {
                    $event['false_positive_changed'] = true;
                }
                echo wp_json_encode($event) . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- machine-readable download, JSON-encoded.
            } elseif (Elderward_False_Positives::MATCHED !== $fp) {
                $line = Elderward\Engine\BaseReporter::format_text_finding(array(
                    'severity' => $row->severity, 'type' => $row->type, 'path' => $row->path, 'detail' => $row->detail, 'context' => $context,
                ));
                echo $line; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain-text download; the formatter percent-encodes control characters.
            }
        }
        exit;
    }

    private static function iterate_findings($job_id)
    {
        global $wpdb;
        $table = Elderward_Plugin::findings_table();
        $last = 0;
        // phpcs:disable WordPress.DB -- the plugin's own table (name from the base prefix, never user input); values go through prepare(); results must not be cached.
        while (true) {
            $rows = $wpdb->get_results($wpdb->prepare(
                "SELECT id, severity, type, path, detail, context, sha256, fp FROM `{$table}` WHERE job_id = %s AND id > %d ORDER BY FIELD(severity,'HIGH','ERROR','MEDIUM','LOW','INFO'), id LIMIT 500",
                $job_id, $last
            ));
            if (empty($rows)) {
                return;
            }
            foreach ($rows as $row) {
                $last = max($last, (int) $row->id);
                yield $row;
            }
        }
        // phpcs:enable WordPress.DB
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
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        global $wpdb;
        $job = Elderward_Job::current();
        $table = Elderward_Plugin::findings_table();
        $severities = array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO');

        $filter = isset($_GET['severity']) ? sanitize_key(wp_unslash($_GET['severity'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter on a listing.
        $filter = in_array(strtoupper($filter), $severities, true) ? strtoupper($filter) : '';
        $paged = isset($_GET['paged']) ? max(1, (int) $_GET['paged']) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only pagination.
        $tab = (isset($_GET['tab']) && in_array($_GET['tab'], array('signatures', 'assistants'), true)) ? sanitize_key(wp_unslash($_GET['tab'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- selects a tab.
        $fp_view = isset($_GET['view']) && 'fp' === $_GET['view']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter on a listing.
        if ($fp_view) {
            $filter = '';
        }

        $counts = array_fill_keys($severities, 0);
        $total = 0;
        $fp_total = 0;
        // phpcs:disable WordPress.DB -- the plugin's own table (name from the base prefix, never user input); values go through prepare(); results must not be cached.
        if (null !== $job) {
            $rows = $wpdb->get_results($wpdb->prepare("SELECT severity, fp, COUNT(*) AS n FROM `{$table}` WHERE job_id = %s GROUP BY severity, fp", $job['id']));
            foreach ((array) $rows as $row) {
                if (Elderward_False_Positives::MATCHED === (int) $row->fp) {
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
        // phpcs:enable WordPress.DB

        $page_url = self::page_url();
        $export_base = wp_nonce_url(admin_url('admin-post.php?action=elderward_export'), self::NONCE_EXPORT);
        $root = untrailingslashit(ABSPATH);
        $settings = Elderward_Settings::get();
        $running = null !== $job && 'running' === $job['status'];
        $datetime_format = get_option('date_format') . ' ' . get_option('time_format');
        $next_run = Elderward_Cron::next_run();
        $fp_rules = Elderward_False_Positives::rules();
        ?>
        <div class="wrap elderward-wrap">
            <h1 class="screen-reader-text"><?php esc_html_e('Elderward', 'elderward'); ?></h1>
            <header class="elderward-brand">
                <img class="elderward-brand-mark" src="<?php echo esc_url(ELDERWARD_URL . 'assets/img/elderward-mark.svg'); ?>" alt="" width="64" height="64" />
                <div class="elderward-brand-text">
                    <img class="elderward-brand-word" src="<?php echo esc_url(ELDERWARD_URL . 'assets/img/elderward-wordmark.svg'); ?>" alt="<?php esc_attr_e('Elderward', 'elderward'); ?>" width="124" height="34" />
                    <p class="elderward-brand-tag"><?php esc_html_e('Malware scanner and incident response for WordPress', 'elderward'); ?></p>
                </div>
                <span class="elderward-brand-version"><?php echo esc_html('v' . ELDERWARD_VERSION); ?></span>
            </header>
            <hr class="wp-header-end" />
            <?php foreach (self::take_notices() as $notice) : ?>
                <div class="notice notice-<?php echo esc_attr($notice[0]); ?> is-dismissible"><p><?php echo esc_html($notice[1]); ?></p></div>
            <?php endforeach; ?>
            <nav class="nav-tab-wrapper elderward-tabs">
                <a href="<?php echo esc_url($page_url); ?>" class="nav-tab <?php echo '' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Scan', 'elderward'); ?></a>
                <a href="<?php echo esc_url(self::signatures_url()); ?>" class="nav-tab <?php echo 'signatures' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Signatures', 'elderward'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'assistants', $page_url)); ?>" class="nav-tab <?php echo 'assistants' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('AI assistants', 'elderward'); ?></a>
            </nav>
            <?php if ('' !== $tab) : ?>
                <?php
                if ('signatures' === $tab) {
                    self::render_signatures_tab();
                } else {
                    self::render_assistants_tab();
                }
                ?>
        </div>
                <?php return; ?>
            <?php endif; ?>
            <p class="description">
                <?php esc_html_e('A report-only look at this install: quick checks, core/plugin/theme integrity, timestamps, crontab, database and (optionally) access logs, then the malware signatures in dry-run mode. Nothing is modified.', 'elderward'); ?>
            </p>

            <div class="elderward-card">
                <form id="elderward-start-form" onsubmit="return false;">
                    <label for="elderward-log"><?php esc_html_e('Access log file or directory (optional)', 'elderward'); ?></label>
                    <input type="text" id="elderward-log" class="regular-text code" placeholder="/var/log/apache2" autocomplete="off" value="<?php echo esc_attr($settings['log']); ?>" />
                    <p class="description"><?php esc_html_e('Must be readable by the PHP user. Rotated .log.N and .gz files in a directory are included.', 'elderward'); ?></p>
                    <p>
                        <button type="button" class="button button-primary" id="elderward-start" <?php disabled($running); ?>><?php esc_html_e('Start scan', 'elderward'); ?></button>
                        <button type="button" class="button" id="elderward-cancel" <?php disabled(!$running); ?>><?php esc_html_e('Cancel', 'elderward'); ?></button>
                    </p>
                </form>
                <div id="elderward-progress" class="elderward-progress" <?php echo $running ? '' : 'hidden'; ?>>
                    <div class="elderward-bar"><div class="elderward-bar-fill" style="width: <?php echo null === $job ? 0 : (int) Elderward_Job::percent($job); ?>%"></div></div>
                    <p id="elderward-status-text"><?php echo null === $job ? '' : esc_html($job['message']); ?></p>
                    <p id="elderward-runner-note" class="description">
                        <?php
                        if ($running) {
                            echo !empty($job['background'])
                                ? esc_html__('Running in the background through WP-Cron: you can leave this page and come back later.', 'elderward')
                                : esc_html__('Keep this page open: the scan runs in short steps from this tab.', 'elderward');
                        }
                        ?>
                    </p>
                </div>
                <?php if (null !== $job) : ?>
                    <p class="elderward-last">
                        <?php
                        if (isset($job['origin']) && 'schedule' === $job['origin']) {
                            /* translators: 1: status word, 2: start date/time, 3: end date/time or dash */
                            $template = __('Last scheduled scan: %1$s. Started %2$s, finished %3$s.', 'elderward');
                        } else {
                            /* translators: 1: status word, 2: start date/time, 3: end date/time or dash */
                            $template = __('Last scan: %1$s. Started %2$s, finished %3$s.', 'elderward');
                        }
                        printf(
                            esc_html($template),
                            '<strong>' . esc_html(self::status_word($job['status'])) . '</strong>',
                            esc_html(wp_date($datetime_format, $job['started'])),
                            esc_html(null === $job['finished'] ? '—' : wp_date($datetime_format, $job['finished']))
                        );
                        if ('' !== $job['error']) {
                            echo ' <span class="elderward-error">' . esc_html($job['error']) . '</span>';
                        }
                        ?>
                    </p>
                <?php endif; ?>
            </div>

            <div class="elderward-card elderward-settings">
                <h2><?php esc_html_e('Settings', 'elderward'); ?></h2>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="elderward_save_settings" />
                    <?php wp_nonce_field(self::NONCE_SETTINGS); ?>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><?php esc_html_e('How scans run', 'elderward'); ?></th>
                            <td>
                                <fieldset>
                                    <legend class="screen-reader-text"><?php esc_html_e('How scans run', 'elderward'); ?></legend>
                                    <label><input type="radio" name="elderward[runner]" value="background" <?php checked($settings['runner'], 'background'); ?> /> <?php esc_html_e('In the background (WP-Cron)', 'elderward'); ?></label>
                                    <p class="description"><?php esc_html_e('The scan keeps going after you leave the page. WordPress drives it through WP-Cron, so the site must be able to request its own wp-cron.php, or a server cron job must call it.', 'elderward'); ?></p>
                                    <label><input type="radio" name="elderward[runner]" value="browser" <?php checked($settings['runner'], 'browser'); ?> /> <?php esc_html_e('In this browser tab', 'elderward'); ?></label>
                                    <p class="description"><?php esc_html_e('Steps run only while the Elderward page is open; a reload resumes. Use it when WP-Cron is unreliable on your host.', 'elderward'); ?></p>
                                </fieldset>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="elderward-schedule"><?php esc_html_e('Scheduled scan', 'elderward'); ?></label></th>
                            <td>
                                <select id="elderward-schedule" name="elderward[schedule]">
                                    <?php foreach (Elderward_Settings::schedules() as $value => $label) : ?>
                                        <option value="<?php echo esc_attr($value); ?>" <?php selected($settings['schedule'], $value); ?>><?php echo esc_html($label); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <span class="elderward-schedule-when" <?php echo 'off' === $settings['schedule'] ? 'hidden' : ''; ?>>
                                    <label for="elderward-time"><?php esc_html_e('at', 'elderward'); ?></label>
                                    <input type="time" id="elderward-time" name="elderward[time]" value="<?php echo esc_attr($settings['time']); ?>" required />
                                    <span class="elderward-schedule-day" <?php echo 'weekly' === $settings['schedule'] ? '' : 'hidden'; ?>>
                                        <label for="elderward-day"><?php esc_html_e('on', 'elderward'); ?></label>
                                        <select id="elderward-day" name="elderward[day]">
                                            <?php for ($day = 0; $day < 7; $day++) : ?>
                                                <option value="<?php echo (int) $day; ?>" <?php selected((int) $settings['day'], $day); ?>><?php echo esc_html($GLOBALS['wp_locale']->get_weekday($day)); ?></option>
                                            <?php endfor; ?>
                                        </select>
                                    </span>
                                </span>
                                <p class="description">
                                    <?php
                                    /* translators: %s: the site's timezone, for example UTC+2 or Europe/Lisbon */
                                    printf(esc_html__('Site time (%s). A scheduled scan always runs in the background, uses the access log below, and is skipped while another scan is in progress.', 'elderward'), esc_html(wp_timezone_string()));
                                    if (null !== $next_run) {
                                        echo ' ';
                                        /* translators: %s: date and time of the next scheduled scan */
                                        printf(esc_html__('Next run: %s.', 'elderward'), '<strong>' . esc_html(wp_date($datetime_format, $next_run)) . '</strong>');
                                    }
                                    ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="elderward-settings-log"><?php esc_html_e('Access log for scheduled scans', 'elderward'); ?></label></th>
                            <td>
                                <input type="text" id="elderward-settings-log" name="elderward[log]" class="regular-text code" placeholder="/var/log/apache2" value="<?php echo esc_attr($settings['log']); ?>" />
                                <p class="description"><?php esc_html_e('Optional. Also pre-fills the field above.', 'elderward'); ?></p>
                            </td>
                        </tr>
                    </table>
                    <?php if (Elderward_Cron::trigger_disabled()) : ?>
                        <p class="elderward-note"><?php esc_html_e('DISABLE_WP_CRON is set on this site, so WordPress does not trigger WP-Cron on its own. Background and scheduled scans only advance when your server\'s cron job calls wp-cron.php (every minute or two is ideal).', 'elderward'); ?></p>
                    <?php endif; ?>
                    <?php submit_button(__('Save settings', 'elderward'), 'secondary', 'submit', false); ?>
                </form>
            </div>

            <?php if (null !== $job) : ?>
            <h2><?php esc_html_e('Findings', 'elderward'); ?></h2>
            <ul class="subsubsub elderward-filters">
                <li><a href="<?php echo esc_url($page_url); ?>" class="<?php echo ('' === $filter && !$fp_view) ? 'current' : ''; ?>"><?php esc_html_e('All', 'elderward'); ?> <span class="count">(<?php echo (int) $total; ?>)</span></a></li>
                <?php foreach ($severities as $severity) : ?>
                    <li>| <a href="<?php echo esc_url(add_query_arg('severity', strtolower($severity), $page_url)); ?>" class="<?php echo $filter === $severity ? 'current' : ''; ?>"><?php echo esc_html($severity); ?> <span class="count">(<?php echo (int) $counts[$severity]; ?>)</span></a></li>
                <?php endforeach; ?>
                <li>| <a href="<?php echo esc_url(add_query_arg('view', 'fp', $page_url)); ?>" class="<?php echo $fp_view ? 'current' : ''; ?>"><?php esc_html_e('False positives', 'elderward'); ?> <span class="count">(<?php echo (int) $fp_total; ?>)</span></a></li>
            </ul>
            <p class="elderward-export">
                <a class="button" href="<?php echo esc_url(add_query_arg('format', 'txt', $export_base)); ?>"><?php esc_html_e('Export text (CSV lines)', 'elderward'); ?></a>
                <a class="button" href="<?php echo esc_url(add_query_arg('format', 'json', $export_base)); ?>"><?php esc_html_e('Export JSON (NDJSON)', 'elderward'); ?></a>
            </p>

            <table class="widefat striped elderward-table">
                <thead>
                    <tr>
                        <th class="elderward-col-sev"><?php esc_html_e('Severity', 'elderward'); ?></th>
                        <th class="elderward-col-type"><?php esc_html_e('Type', 'elderward'); ?></th>
                        <th><?php esc_html_e('Path', 'elderward'); ?></th>
                        <th><?php esc_html_e('Detail', 'elderward'); ?></th>
                        <th class="elderward-col-actions"><?php esc_html_e('Actions', 'elderward'); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($findings)) : ?>
                    <tr><td colspan="5">
                        <?php
                        if ($fp_view) {
                            esc_html_e('No finding in these results is marked as a false positive.', 'elderward');
                        } else {
                            echo 'running' === $job['status'] ? esc_html__('Scan in progress…', 'elderward') : esc_html__('No findings.', 'elderward');
                        }
                        ?>
                    </td></tr>
                <?php else : ?>
                    <?php foreach ($findings as $finding) : ?>
                        <?php
                        $path = (string) $finding->path;
                        $short = (0 === strpos($path, $root . '/')) ? substr($path, strlen($root) + 1) : $path;
                        $context = self::decode_context($finding->context);
                        $fp = (int) $finding->fp;
                        $fingerprint = '' !== (string) $finding->fingerprint ? $finding->fingerprint : Elderward_False_Positives::fingerprint($finding->type, $finding->path, $finding->detail);
                        $sha256 = (null === $finding->sha256 || '' === $finding->sha256) ? '' : $finding->sha256;
                        ?>
                        <tr data-id="<?php echo (int) $finding->id; ?>" data-fingerprint="<?php echo esc_attr($fingerprint); ?>">
                            <td><span class="elderward-sev elderward-sev-<?php echo esc_attr(strtolower($finding->severity)); ?>"><?php echo esc_html($finding->severity); ?></span></td>
                            <td><code><?php echo esc_html($finding->type); ?></code></td>
                            <td><code title="<?php echo esc_attr($path); ?>"><?php echo esc_html($short); ?></code></td>
                            <td>
                                <?php echo esc_html($finding->detail); ?>
                                <?php if (!empty($context)) : ?>
                                    <details><summary><?php esc_html_e('Context', 'elderward'); ?></summary>
                                        <pre><?php echo esc_html(implode("\n", $context)); ?></pre>
                                    </details>
                                <?php endif; ?>
                                <?php if ('' !== $sha256) : ?>
                                    <p class="elderward-hash">SHA-256 <code><?php echo esc_html($sha256); ?></code>
                                        <a href="<?php echo esc_url('https://www.virustotal.com/gui/file/' . $sha256); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Look up on VirusTotal', 'elderward'); ?></a></p>
                                <?php endif; ?>
                                <?php if (Elderward_False_Positives::CHANGED === $fp) : ?>
                                    <p class="elderward-note"><?php esc_html_e('Marked as a false positive before, but the file changed since it was reviewed, so it is reported again.', 'elderward'); ?></p>
                                <?php elseif (Elderward_False_Positives::MATCHED === $fp && isset($fp_rules[$fingerprint])) : ?>
                                    <p class="elderward-fp-why"><?php echo esc_html(self::rule_summary($fp_rules[$fingerprint], $datetime_format)); ?></p>
                                <?php endif; ?>
                            </td>
                            <td class="elderward-actions">
                                <?php if (Elderward_False_Positives::MATCHED === $fp) : ?>
                                    <button type="button" class="button button-small" data-fp-action="unmark"><?php esc_html_e('Not a false positive', 'elderward'); ?></button>
                                <?php else : ?>
                                    <button type="button" class="button button-small" data-fp-action="mark"><?php esc_html_e('False positive', 'elderward'); ?></button>
                                <?php endif; ?>
                                <?php if ('' !== $sha256 && 1 !== preg_match('/^wp-config/i', basename($path))) : ?>
                                    <a class="button button-small" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=elderward_sample&id=' . (int) $finding->id), self::NONCE_SAMPLE . (int) $finding->id)); ?>"><?php esc_html_e('Download sample', 'elderward'); ?></a>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
            <?php if ($pages > 1) : ?>
                <div class="tablenav"><div class="tablenav-pages">
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

            <?php if ($fp_view) : ?>
                <?php self::render_fp_rules($fp_rules, $datetime_format, $root); ?>
            <?php endif; ?>
            <p class="description elderward-sample-help">
                <?php
                if (Elderward_Sample::can_encrypt()) {
                    esc_html_e('Download sample packs the file into a zip encrypted with the password "infected", with a manifest of where it was found and why. Send it to your malware analyst or sandbox yourself: Elderward never uploads anything. The VirusTotal link only sends the file\'s hash, from your browser.', 'elderward');
                } else {
                    esc_html_e('Download sample packs the file into a zip with a manifest. This PHP cannot encrypt zips, so the sample is not password-protected and your antivirus may block the download. Elderward never uploads anything. The VirusTotal link only sends the file\'s hash, from your browser.', 'elderward');
                }
                ?>
            </p>

            <h2><?php esc_html_e('Acting on the results', 'elderward'); ?></h2>
            <p><?php esc_html_e('This page never changes files. Cleanup and restore run from the command line, where you can take a backup first and preview with a dry run:', 'elderward'); ?></p>
            <pre class="elderward-cli">wp elderward scan --dryrun          <?php esc_html_e('# preview the signature cleanup', 'elderward'); ?>

wp elderward scan                   <?php esc_html_e('# remove known malware from infected files', 'elderward'); ?>

wp elderward integrity --restore --dryrun
wp elderward integrity --restore --quarantine-dir=/path/outside/webroot</pre>
            <p class="description"><?php esc_html_e('Without WP-CLI, the same scanners run from php bin/elderward.php inside the plugin folder; see the readme.', 'elderward'); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * "Reviewed by NAME on DATE: note" for a saved false positive.
     */
    private static function rule_summary(array $rule, $datetime_format)
    {
        $user = !empty($rule['user']) ? get_userdata((int) $rule['user']) : false;
        $name = $user ? $user->display_name : __('a deleted user', 'elderward');
        $when = !empty($rule['time']) ? wp_date($datetime_format, (int) $rule['time']) : '—';
        /* translators: 1: user display name, 2: date and time */
        $text = sprintf(__('Marked as a false positive by %1$s on %2$s.', 'elderward'), $name, $when);
        if (!empty($rule['note'])) {
            $text .= ' ' . $rule['note'];
        }
        return $text;
    }

    /**
     * Every saved false positive, including those for findings that are
     * not in the current results (file since deleted, check not run).
     */
    private static function render_fp_rules(array $rules, $datetime_format, $root)
    {
        ?>
        <div class="elderward-card elderward-fp-rules">
            <h2><?php esc_html_e('Saved false positives', 'elderward'); ?></h2>
            <p class="description"><?php esc_html_e('A saved false positive hides the same finding (type, path and detail) in later scans. For a finding about a file it only applies while the file is byte-for-byte the one that was reviewed.', 'elderward'); ?></p>
            <?php if (empty($rules)) : ?>
                <p><?php esc_html_e('None saved.', 'elderward'); ?></p>
            <?php else : ?>
                <table class="widefat striped elderward-table">
                    <thead><tr>
                        <th class="elderward-col-type"><?php esc_html_e('Type', 'elderward'); ?></th>
                        <th><?php esc_html_e('Path', 'elderward'); ?></th>
                        <th><?php esc_html_e('Detail', 'elderward'); ?></th>
                        <th class="elderward-col-actions"><?php esc_html_e('Actions', 'elderward'); ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rules as $fingerprint => $rule) : ?>
                        <?php
                        $path = (string) $rule['path'];
                        $short = (0 === strpos($path, $root . '/')) ? substr($path, strlen($root) + 1) : $path;
                        ?>
                        <tr data-fingerprint="<?php echo esc_attr($fingerprint); ?>">
                            <td><code><?php echo esc_html($rule['type']); ?></code></td>
                            <td><code title="<?php echo esc_attr($path); ?>"><?php echo esc_html($short); ?></code></td>
                            <td><?php echo esc_html($rule['detail']); ?>
                                <p class="elderward-fp-why"><?php echo esc_html(self::rule_summary($rule, $datetime_format)); ?></p></td>
                            <td class="elderward-actions"><button type="button" class="button button-small" data-fp-action="unmark"><?php esc_html_e('Remove', 'elderward'); ?></button></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <p><button type="button" class="button" data-fp-action="forget_all"><?php esc_html_e('Forget all false positives', 'elderward'); ?></button></p>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function status_word($status)
    {
        switch ($status) {
            case 'running':
                return __('running', 'elderward');
            case 'done':
                return __('complete', 'elderward');
            case 'failed':
                return __('failed', 'elderward');
            case 'cancelled':
                return __('cancelled', 'elderward');
        }
        return $status;
    }
}
