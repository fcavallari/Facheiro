<?php
/**
 * The Elderward admin menu: start a report-only scan, watch it progress, read
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
    const NONCE_SEAL = 'elderward_seal';
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
        add_action('admin_post_elderward_seal', array(__CLASS__, 'seal_action'));
        add_action('admin_post_elderward_save_settings', array(__CLASS__, 'save_settings'));
        Elderward_Admin_Hardening::init();
        Elderward_Admin_Recovery::init();
    }

    public static function page_url()
    {
        return is_multisite() ? network_admin_url('admin.php?page=' . self::PAGE) : admin_url('admin.php?page=' . self::PAGE);
    }

    public static function register_menu()
    {
        self::$hook_suffix = add_menu_page(
            __('Elderward', 'elderward'),
            __('Elderward', 'elderward'),
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
            __('Elderward', 'elderward'),
            __('Elderward', 'elderward'),
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
            'elderward-overview'   => array(__('Overview', 'elderward'), array(
                __('Elderward checks this site for malware and signs of a break-in. Scans only report: nothing on the site is changed from this page.', 'elderward'),
                __('Start a scan on the Scan tab. When it finishes, the findings appear below it, most serious first.', 'elderward'),
            )),
            'elderward-findings'   => array(__('Reading findings', 'elderward'), array(
                __('HIGH: almost certainly malicious; deal with it first. MEDIUM: suspicious; check it. LOW: worth knowing. INFO: for the record. ERROR: a check could not run, so that part of the site is unknown rather than clean.', 'elderward'),
                __('Timestamp and log findings are leads, not proof. The SHA-256 of a flagged file can be looked up on VirusTotal; only the hash leaves your browser.', 'elderward'),
                __('Mark as false positive hides a finding you checked from later scans, with an optional note of why. For files, the mark only holds while the file stays exactly as you reviewed it. Download sample saves a password-protected copy (password: infected) for a malware analyst.', 'elderward'),
            )),
            'elderward-settings'   => array(__('Settings', 'elderward'), array(
                __('Run scans: in the background (through WP-Cron, so you can leave the page) or only while the page is open (if background scans never finish on your host).', 'elderward'),
                __('Automatic scans: run the same scan daily, twice daily or weekly. They always run in the background and are skipped while another scan is in progress.', 'elderward'),
                __('Access logs: optional location of the web server logs (a file or a folder, such as /var/log/apache2), checked by every scan for attack traffic.', 'elderward'),
            )),
            'elderward-signatures' => array(__('Signatures', 'elderward'), array(
                __('A signature describes something to look for. Built-in signatures ship with Elderward; on the Signatures tab you can add your own for a threat specific to this site, try them on a file or a pasted sample, and import or export them.', 'elderward'),
                __('Custom signatures only report matches. They never clean or delete anything.', 'elderward'),
            )),
            'elderward-hardening'  => array(__('Hardening', 'elderward'), array(
                __('The Hardening tab adds web server rules that refuse dangerous requests: PHP in uploads, wp-config copies, hidden files such as .git, WordPress internals. Pick your server, a template (Recommended or Strict) or individual protections, and review the exact rules before applying.', 'elderward'),
                __('On Apache and LiteSpeed, Elderward writes the rules into .htaccess files, checks the site afterwards and undoes the change if the site breaks. On Nginx, download the configuration file and include it in the server configuration. "Check now" confirms what the live site enforces.', 'elderward'),
            )),
            'elderward-recovery'   => array(__('Recovery', 'elderward'), array(
                __('Recovery mode scans the site when WordPress itself no longer loads (a white screen or a fatal error), from a page that does not depend on WordPress. It is locked by a key you create on the Recovery tab, with WP-CLI, or by uploading a key file.', 'elderward'),
            )),
            'elderward-assistants' => array(__('AI assistants', 'elderward'), array(
                __('The AI assistants tab explains how to let an assistant such as Claude run scans and explain the findings, through the MCP Adapter plugin, or how to copy a summary into any chat.', 'elderward'),
            )),
            'elderward-cleanup'    => array(__('Cleaning up', 'elderward'), array(
                __('Cleanup and restore run from WP-CLI (wp elderward scan, wp elderward integrity --restore), where you can take a backup and preview each change with --dryrun first.', 'elderward'),
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
            '<p><strong>' . esc_html__('More help', 'elderward') . '</strong></p>'
            . '<p><a href="https://github.com/fioa8c/elderward#readme" target="_blank" rel="noopener noreferrer">' . esc_html__('Elderward documentation', 'elderward') . '</a></p>'
        );
    }

    /**
     * The menu icon is the Elderward mark, drawn as a CSS mask so it takes
     * the admin colour scheme's colours (normal, hover, current) like the
     * core icons. WordPress's own SVG recolouring only rewrites fills, and
     * the mark is drawn with strokes.
     */
    public static function menu_icon()
    {
        if (!Elderward_Plugin::can_manage()) {
            return;
        }
        $url = esc_url_raw(ELDERWARD_URL . 'assets/img/elderward-menu.svg');
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
        wp_enqueue_style('elderward-admin', ELDERWARD_URL . 'assets/admin.css', array(), ELDERWARD_VERSION);
        wp_enqueue_script('elderward-admin', ELDERWARD_URL . 'assets/admin.js', array(), ELDERWARD_VERSION, true);
        $job = Elderward_Job::current();
        wp_localize_script('elderward-admin', 'elderwardAdmin', array(
            'ajaxUrl'    => admin_url('admin-ajax.php'),
            'nonce'      => wp_create_nonce(self::NONCE_SCAN),
            'status'     => null === $job ? '' : $job['status'],
            'background' => null !== $job && !empty($job['background']),
            'stale'      => self::STALE_SECONDS,
            'i18n'       => array_merge(Elderward_Admin_Hardening::i18n(), Elderward_Admin_Recovery::i18n(), array(
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
                'background' => __('Running in the background: you can leave this page and come back later.', 'elderward'),
                'browser'    => __('Keep this page open: the scan runs in short steps from this tab.', 'elderward'),
                'fpPrompt'   => __('Mark this finding as a false positive? Optionally note why; the note is kept with the decision.', 'elderward'),
                'fpMarked'   => __('Marked as a false positive. Later scans hide it until the file changes.', 'elderward'),
                'fpUndo'     => __('Undo', 'elderward'),
                'fpRemoved'  => __('No longer a false positive; it shows in the findings again.', 'elderward'),
                'fpForget'   => __('Remove every saved false positive? The findings they hid show again.', 'elderward'),
                'fpKeep'     => __('Trust this false positive again? Do this only if you or another administrator made the change.', 'elderward'),
                'sigNone'    => __('No signature matches.', 'elderward'),
                /* translators: %d: number of matching signatures */
                'sigHits'    => __('Matching signatures: %d', 'elderward'),
                'disabled'   => __('disabled', 'elderward'),
                'copied'     => __('Copied.', 'elderward'),
                'sigDelete'  => __('Delete this custom signature?', 'elderward'),
                'takeover'   => __('The background scan stopped making progress, so it continues from this tab for as long as the page stays open. Tools > Site Health shows whether this site can reach its own wp-cron.php; otherwise set Run scans to "Only while this page is open".', 'elderward'),
            )),
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
        if ('' === $log) {
            // The page's Start button: the saved access-log setting, skipped
            // (as by automatic scans) when it no longer resolves.
            $settings = Elderward_Settings::get();
            $real = Elderward_Settings::resolve_log_path($settings['log']);
            if (is_wp_error($real)) {
                $real = '';
            }
        } else {
            // An explicit path must name an existing, readable log file or
            // directory. Nothing else is accepted.
            $real = Elderward_Settings::resolve_log_path($log);
            if (is_wp_error($real)) {
                wp_send_json_error(array('message' => $real->get_error_message()), 400);
            }
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
        if ('keep' === $op) {
            $fingerprint = isset($_POST['fingerprint']) ? sanitize_key(wp_unslash($_POST['fingerprint'])) : '';
            if (1 !== preg_match('/^[0-9a-f]{40}$/', $fingerprint)) {
                wp_send_json_error(array('message' => __('Unknown false positive.', 'elderward')), 400);
            }
            Elderward_False_Positives::keep($fingerprint);
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
        header('Content-Disposition: attachment; filename="elderward-sample-' . (int) $id . '-' . gmdate('Ymd-His') . '.zip"');
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
        } elseif ('keep' === $op) {
            Elderward_Seal::accept('signatures', array($id));
            /* translators: %s: signature id */
            self::notify(array(array('success', sprintf(__('Signature %s is trusted again.', 'elderward'), $id))));
        } elseif ('acknowledge' === $op) {
            $removed = Elderward_Seal::diff('signatures');
            Elderward_Seal::accept('signatures', $removed['removed']);
            self::notify(array(array('success', __('Removed signatures acknowledged.', 'elderward'))));
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
        $sig_diff = Elderward_Seal::diff('signatures');
        $sig_tampered = array_flip(array_merge($sig_diff['added'], $sig_diff['changed']));
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
        <p class="elderward-intro"><?php esc_html_e('A signature describes something to look for. Add your own for a threat specific to this site; they run in every scan from the next one on. Custom signatures only report matches (as SIGNATURE_MATCH for files): nothing is ever cleaned or deleted because of one.', 'elderward'); ?></p>
        <p class="elderward-intro"><a href="https://github.com/fioa8c/elderward/blob/main/docs/writing-signatures.md" target="_blank" rel="noopener noreferrer"><?php esc_html_e('How to write a good signature', 'elderward'); ?><span class="screen-reader-text"> <?php esc_html_e('(opens in a new tab)', 'elderward'); ?></span></a></p>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('Your signatures', 'elderward'); ?></h2>
                <div class="elderward-head-actions">
                    <a class="button" href="<?php echo esc_url(self::signatures_url(array('edit' => 'new'))); ?>#elderward-sig-form"><?php esc_html_e('Add signature', 'elderward'); ?></a>
                </div>
            </div>
            <?php if (!empty($sig_diff['removed'])) : ?>
                <div class="notice notice-error inline elderward-tamper"><p><?php
                    printf(
                        /* translators: %s: comma-separated signature names */
                        esc_html__('Removed outside Elderward: %s. Re-import them from an export if they should still exist.', 'elderward'),
                        '<code>' . esc_html(implode(', ', $sig_diff['removed'])) . '</code>'
                    );
                ?></p><p><?php self::signature_button('', 'acknowledge', __('Acknowledge', 'elderward')); ?></p></div>
            <?php endif; ?>
            <?php if (empty($defs)) : ?>
                <p class="elderward-empty"><?php esc_html_e('No custom signatures yet. Built-in signatures are listed at the bottom of this page.', 'elderward'); ?></p>
            <?php else : ?>
                <div class="elderward-table-scroll"><table class="widefat striped elderward-table elderward-sig-table">
                    <thead><tr>
                        <th><?php esc_html_e('Signature', 'elderward'); ?></th>
                        <th class="elderward-col-target"><?php esc_html_e('Looks in', 'elderward'); ?></th>
                        <th class="elderward-col-sev"><?php esc_html_e('Severity', 'elderward'); ?></th>
                        <th><?php esc_html_e('Conditions', 'elderward'); ?></th>
                        <th class="elderward-col-actions"><?php esc_html_e('Actions', 'elderward'); ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($defs as $def) : ?>
                        <?php $enabled = !isset($def['enabled']) || $def['enabled']; ?>
                        <?php $is_tampered = isset($def['id']) && isset($sig_tampered[(string) $def['id']]); ?>
                        <tr class="<?php echo $enabled ? '' : 'elderward-disabled'; ?><?php echo $is_tampered ? ' elderward-tampered' : ''; ?>">
                            <td><code><?php echo esc_html($def['id']); ?></code><?php echo $enabled ? '' : ' <em>(' . esc_html__('disabled', 'elderward') . ')</em>'; ?>
                                <?php if ($is_tampered) : ?><p class="elderward-tamper-badge"><?php esc_html_e('Added or changed outside Elderward. Keep it only if an administrator made this change.', 'elderward'); ?></p><?php endif; ?>
                                <?php if ('' !== (string) $def['description']) : ?><p class="description"><?php echo esc_html($def['description']); ?></p><?php endif; ?></td>
                            <td><?php echo esc_html(isset($targets[$def['target']]) ? $targets[$def['target']] : $def['target']); ?></td>
                            <td><span class="elderward-sev elderward-sev-<?php echo esc_attr(strtolower($def['severity'])); ?>"><?php echo esc_html($def['severity']); ?></span></td>
                            <td><pre class="elderward-conditions"><?php echo esc_html(Elderward_Signatures::conditions_text($def)); ?></pre></td>
                            <td class="elderward-actions">
                                <a class="button button-small" href="<?php echo esc_url(self::signatures_url(array('edit' => $def['id']))); ?>#elderward-sig-form"><?php esc_html_e('Edit', 'elderward'); ?></a>
                                <?php self::signature_button($def['id'], $enabled ? 'disable' : 'enable', $enabled ? __('Disable', 'elderward') : __('Enable', 'elderward')); ?>
                                <?php if ($is_tampered) : ?>
                                    <?php self::signature_button($def['id'], 'keep', __('Keep', 'elderward')); ?>
                                <?php endif; ?>
                                <?php self::signature_button($def['id'], 'delete', __('Delete', 'elderward')); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table></div>
            <?php endif; ?>
        </div>

        <div class="elderward-card" id="elderward-sig-form">
            <div class="elderward-card-head">
                <h2><?php echo '' === $form['original_id'] ? esc_html__('Add a signature', 'elderward') : esc_html__('Edit signature', 'elderward'); ?></h2>
            </div>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="elderward_signature" />
                <input type="hidden" name="op" value="save" />
                <input type="hidden" name="original_id" value="<?php echo esc_attr($form['original_id']); ?>" />
                <?php wp_nonce_field(self::NONCE_SIGNATURES); ?>
                <table class="form-table" role="presentation">
                    <tr><th scope="row"><label for="elderward-sig-id"><?php esc_html_e('Name', 'elderward'); ?></label></th>
                        <td><input type="text" id="elderward-sig-id" name="id" class="regular-text code" value="<?php echo esc_attr($form['id']); ?>" placeholder="acme-loader" pattern="[a-z0-9][a-z0-9._\-]{1,62}" required />
                            <p class="description"><?php esc_html_e('A short name made of lowercase letters, digits, dots, dashes and underscores. Findings show it as custom.<name>.', 'elderward'); ?></p></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-target"><?php esc_html_e('Looks in', 'elderward'); ?></label></th>
                        <td><select id="elderward-sig-target" name="target">
                            <?php foreach ($targets as $value => $label) : ?>
                                <option value="<?php echo esc_attr($value); ?>" <?php selected($form['target'], $value); ?>><?php echo esc_html($label); ?></option>
                            <?php endforeach; ?>
                        </select>
                            <p class="description"><?php esc_html_e('Files: PHP, JavaScript and other code files under 2 MB. Database options and posts: values in the options table and post content.', 'elderward'); ?></p></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-severity"><?php esc_html_e('Severity', 'elderward'); ?></label></th>
                        <td><select id="elderward-sig-severity" name="severity">
                            <?php foreach (array('HIGH', 'MEDIUM', 'LOW') as $severity) : ?>
                                <option value="<?php echo esc_attr(strtolower($severity)); ?>" <?php selected(strtoupper($form['severity']), $severity); ?>><?php echo esc_html($severity); ?></option>
                            <?php endforeach; ?>
                        </select>
                            <p class="description"><?php esc_html_e('HIGH if a match is certainly malicious, MEDIUM if it needs checking, LOW if it is only worth knowing.', 'elderward'); ?></p></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-description"><?php esc_html_e('Description', 'elderward'); ?></label></th>
                        <td><input type="text" id="elderward-sig-description" name="description" class="large-text" value="<?php echo esc_attr($form['description']); ?>" placeholder="<?php esc_attr_e('ACME loader backdoor', 'elderward'); ?>" maxlength="300" />
                            <p class="description"><?php esc_html_e('Shown with every match.', 'elderward'); ?></p></td></tr>
                    <tr><th scope="row"><label for="elderward-sig-conditions"><?php esc_html_e('Conditions', 'elderward'); ?></label> <?php self::help_button('elderward-help-conditions'); ?></th>
                        <td><textarea id="elderward-sig-conditions" name="conditions" class="large-text code" rows="5" placeholder="text: acme_loader&#10;regex: /eval\s*\(\s*\$_POST/i" required><?php echo esc_textarea($form['conditions']); ?></textarea>
                            <p class="description"><?php esc_html_e('One per line, each starting with text: (exact text) or regex: (a pattern). A file matches when every line matches.', 'elderward'); ?></p>
                            <?php
                            self::help_text('elderward-help-conditions', array(
                                __('text: matches the exact characters that follow, including case. regex: takes a PHP (PCRE) regular expression with delimiters, such as /eval\s*\(/i. A regex that would match an empty file is refused, because it would flag everything.', 'elderward'),
                                __('For files, up to 10 lines, all of which must match. The first line is checked first on every file, so make it a short, distinctive text: it keeps scans fast. Database signatures take a single regex line.', 'elderward'),
                                __('Before saving, try the signature below on the malicious file (it must match) and on a clean file of the same kind (it must not).', 'elderward'),
                            ));
                            ?></td></tr>
                    <tr><th scope="row"><?php esc_html_e('Status', 'elderward'); ?></th>
                        <td><label><input type="checkbox" name="enabled" value="1" <?php checked(!empty($form['enabled'])); ?> /> <?php esc_html_e('Use in scans', 'elderward'); ?></label></td></tr>
                </table>
                <?php submit_button('' === $form['original_id'] ? __('Add signature', 'elderward') : __('Save changes', 'elderward'), 'primary', 'submit', false); ?>
                <?php if ('' !== $form['original_id']) : ?>
                    <a class="button" href="<?php echo esc_url(self::signatures_url()); ?>"><?php esc_html_e('Cancel', 'elderward'); ?></a>
                <?php endif; ?>
            </form>
        </div>

        <div class="elderward-card" id="elderward-sig-test">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('Try signatures', 'elderward'); ?></h2>
            </div>
            <p class="description"><?php esc_html_e('See which built-in and custom signatures match a file of this site or a pasted sample. Nothing is saved, and only the names of the matching signatures are shown.', 'elderward'); ?></p>
            <div class="elderward-field">
                <label for="elderward-test-path"><?php esc_html_e('File on this site', 'elderward'); ?></label>
                <input type="text" id="elderward-test-path" class="large-text code" placeholder="wp-content/uploads/2026/shell.php" autocomplete="off" />
                <p class="description"><?php esc_html_e('Path from the WordPress folder. wp-config.php cannot be used.', 'elderward'); ?></p>
            </div>
            <div class="elderward-field">
                <label for="elderward-test-text"><?php esc_html_e('Or paste a sample', 'elderward'); ?></label>
                <textarea id="elderward-test-text" class="large-text code" rows="6"></textarea>
            </div>
            <p><button type="button" class="button button-primary" id="elderward-test-run"><?php esc_html_e('Try', 'elderward'); ?></button></p>
            <div id="elderward-test-result" class="elderward-test-result" aria-live="polite"></div>
        </div>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('Import and export', 'elderward'); ?></h2>
                <div class="elderward-head-actions">
                    <a class="button" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=elderward_signatures_export'), self::NONCE_SIGNATURES)); ?>"><?php esc_html_e('Export custom signatures', 'elderward'); ?></a>
                </div>
            </div>
            <p class="description"><?php esc_html_e('The export is a JSON file. It also works with the standalone scanner: php bin/elderward.php scanall=1 signatures=signatures.json', 'elderward'); ?></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="elderward_signature" />
                <input type="hidden" name="op" value="import" />
                <?php wp_nonce_field(self::NONCE_SIGNATURES); ?>
                <div class="elderward-field">
                    <label for="elderward-sig-import"><?php esc_html_e('Import', 'elderward'); ?></label>
                    <textarea id="elderward-sig-import" name="json" class="large-text code" rows="6" placeholder='{"elderward_signatures": 1, "signatures": [ ... ]}' required></textarea>
                    <p class="description"><?php esc_html_e('Paste the contents of a signature file. Signatures with the same name are replaced. If any entry is invalid, nothing is imported.', 'elderward'); ?></p>
                </div>
                <?php submit_button(__('Import', 'elderward'), 'secondary', 'submit', false); ?>
            </form>
        </div>

        <details class="elderward-card elderward-builtin">
            <summary><h2><?php
                /* translators: %d: number of built-in signatures */
                printf(esc_html__('Built-in signatures (%d)', 'elderward'), count($builtin));
            ?></h2></summary>
            <p class="description"><?php esc_html_e('Shipped with Elderward; they cannot be changed here. Access log and crontab patterns are not listed.', 'elderward'); ?></p>
            <div class="elderward-table-scroll"><table class="widefat striped elderward-table">
                <thead><tr>
                    <th><?php esc_html_e('Signature', 'elderward'); ?></th>
                    <th class="elderward-col-target"><?php esc_html_e('Looks in', 'elderward'); ?></th>
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
            </table></div>
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
        <p class="elderward-intro"><?php esc_html_e('Connect an AI assistant such as Claude, ChatGPT, Antigravity or Cursor through the Model Context Protocol (MCP). It can then run scans, explain the findings, read flagged files, draft and try signatures, and record false positives, acting as you.', 'elderward'); ?></p>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><span class="elderward-step">1</span> <?php esc_html_e('Check the requirements', 'elderward'); ?></h2>
            </div>
            <ul class="elderward-checklist">
                <li class="<?php echo $abilities ? 'is-ok' : 'is-missing'; ?>"><?php echo $abilities ? esc_html__('WordPress 6.9 or later: Elderward\'s tools are available to assistants.', 'elderward') : esc_html__('WordPress 6.9 or later is needed (it adds the Abilities API). Update WordPress, or use the summary at the bottom of this page.', 'elderward'); ?></li>
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
            <div class="elderward-card-head">
                <h2><span class="elderward-step">2</span> <?php esc_html_e('Add Elderward to your assistant', 'elderward'); ?> <?php self::help_button('elderward-help-mcp'); ?></h2>
            </div>
            <p><?php esc_html_e('Copy the configuration that fits your setup into your assistant\'s MCP settings.', 'elderward'); ?></p>
            <?php
            self::help_text('elderward-help-mcp', array(
                __('Claude Desktop: Settings > Developer > Edit Config, and add the "elderward" entry under "mcpServers". Claude Code: run claude mcp add-json elderward followed by the inner object (the part after "elderward":). Antigravity, Cursor and others: add it to their MCP configuration file.', 'elderward'),
                __('Restart the assistant afterwards. It should then list Elderward\'s tools and the "elderward-triage" prompt.', 'elderward'),
            ));
            ?>
            <div class="elderward-config">
                <h3><?php esc_html_e('The assistant runs where WP-CLI can reach this site', 'elderward'); ?></h3>
                <p class="description"><?php esc_html_e('For example Claude Code on the server, or on a computer with a copy of the site. Nothing goes over the network.', 'elderward'); ?></p>
                <textarea id="elderward-config-stdio" class="large-text code elderward-copy" rows="14" readonly><?php echo esc_textarea($stdio); ?></textarea>
                <p><button type="button" class="button" data-copy="elderward-config-stdio"><?php esc_html_e('Copy', 'elderward'); ?></button></p>
            </div>
            <div class="elderward-config">
                <h3><?php esc_html_e('The assistant runs on your computer and the site is online', 'elderward'); ?></h3>
                <p class="description">
                    <?php esc_html_e('Needs Node.js on your computer. Create an application password, paste it in place of the placeholder, and revoke it when you are done.', 'elderward'); ?>
                    <a href="<?php echo esc_url(admin_url('profile.php#application-passwords-section')); ?>"><?php esc_html_e('Create an application password', 'elderward'); ?></a>
                </p>
                <textarea id="elderward-config-remote" class="large-text code elderward-copy" rows="17" readonly><?php echo esc_textarea($remote); ?></textarea>
                <p><button type="button" class="button" data-copy="elderward-config-remote"><?php esc_html_e('Copy', 'elderward'); ?></button></p>
            </div>
            <p class="description"><?php esc_html_e('ChatGPT connects to MCP servers over the internet rather than running a command, and only where your plan allows custom connectors. If yours does not, use the summary at the bottom of this page.', 'elderward'); ?></p>
        </div>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><span class="elderward-step">3</span> <?php esc_html_e('Ask', 'elderward'); ?></h2>
            </div>
            <ul class="elderward-examples">
                <li><?php esc_html_e('"Use the Elderward triage prompt." (listed among the server\'s prompts)', 'elderward'); ?></li>
                <li><?php esc_html_e('"Scan my site with Elderward and tell me whether it is hacked."', 'elderward'); ?></li>
                <li><?php esc_html_e('"Explain the HIGH findings and what I should do about each."', 'elderward'); ?></li>
                <li><?php esc_html_e('"Elderward missed a backdoor in wp-content/plugins/acme/loader.php: write a signature for it, try it on that file and on a clean plugin, then save it."', 'elderward'); ?></li>
            </ul>
            <p class="elderward-note"><?php esc_html_e('The assistant acts with your account but cannot clean, restore or change files: cleanup stays a command you run yourself. Anything a scan reads from the site may have been written by the attacker, and Elderward labels it as untrusted for the assistant. Still, check its reasoning before letting it mark a finding as a false positive.', 'elderward'); ?></p>
        </div>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('No MCP? Copy a summary into any chat', 'elderward'); ?></h2>
            </div>
            <p class="description"><?php esc_html_e('Instructions for the chatbot plus up to 100 of the most serious findings from the last scan. It includes file paths and snippets from this site, so share it only with a service you trust with them.', 'elderward'); ?></p>
            <textarea id="elderward-brief" class="large-text code elderward-copy" rows="14" readonly><?php echo esc_textarea(Elderward_Abilities::brief()); ?></textarea>
            <p><button type="button" class="button button-primary" data-copy="elderward-brief"><?php esc_html_e('Copy summary', 'elderward'); ?></button></p>
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
                $notices[] = array('warning', __('The access log path does not exist or PHP cannot read it. Scans skip the logs until it can be read.', 'elderward'));
            }
        }
        if ('background' === $settings['runner'] || 'off' !== $settings['schedule']) {
            if (Elderward_Cron::trigger_disabled()) {
                $notices[] = array('warning', __('DISABLE_WP_CRON is set on this site, so WordPress does not start WP-Cron on its own. Background and automatic scans only move forward when your server\'s cron job calls wp-cron.php.', 'elderward'));
            } else {
                $loopback = self::loopback_problem();
                if (null !== $loopback) {
                    $notices[] = array('warning', sprintf(
                        /* translators: %s: the Site Health loopback error */
                        __('This site could not reach its own wp-cron.php (%s). Background scans will only move forward while the Elderward page is open, and automatic scans may never start. Fix the loopback problem shown in Tools > Site Health, or set Run scans to "Only while this page is open".', 'elderward'),
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
     * Tamper seal: accept the current settings (after the seal went
     * missing) or the scan settings changed outside Elderward.
     */
    public static function seal_action()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE_SEAL);
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        if ('accept_all' === $op) {
            Elderward_Seal::accept();
            Elderward_False_Positives::reset_cache();
            self::notify(array(array('success', __('The current saved settings are trusted again.', 'elderward'))));
        } elseif ('accept_settings' === $op) {
            Elderward_Seal::accept('settings');
            self::notify(array(array('success', __('The current scan settings are trusted again.', 'elderward'))));
        }
        wp_safe_redirect(self::page_url());
        exit;
    }

    private static function seal_button($op, $label)
    {
        ?>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="elderward-inline-form">
            <input type="hidden" name="action" value="elderward_seal" />
            <input type="hidden" name="op" value="<?php echo esc_attr($op); ?>" />
            <?php wp_nonce_field(self::NONCE_SEAL); ?>
            <button type="submit" class="button button-small"><?php echo esc_html($label); ?></button>
        </form>
        <?php
    }

    /**
     * Tamper notices shown at the top of every Elderward tab: Elderward's
     * own files changed (from the last scan's self-check), and saved
     * settings changed outside Elderward (checked now).
     */
    private static function render_tamper_notices($job)
    {
        $self = (null !== $job && isset($job['summaries']['self']) && is_array($job['summaries']['self'])) ? $job['summaries']['self'] : array();
        $changed_files = (isset($self['MODIFIED']) ? (int) $self['MODIFIED'] : 0) + (isset($self['EXTRA']) ? (int) $self['EXTRA'] : 0);
        if ($changed_files > 0) {
            ?>
            <div class="notice notice-error elderward-tamper"><p><strong><?php esc_html_e('Elderward\'s own files were changed, so these results may not be trustworthy.', 'elderward'); ?></strong>
                <?php esc_html_e('Reinstall Elderward from wordpress.org, or run the standalone command-line tool from a fresh download, then scan again. The Elderward self-check findings list the files.', 'elderward'); ?></p></div>
            <?php
        }
        $status = Elderward_Seal::status();
        if (!$status['available']) {
            ?>
            <div class="notice notice-warning elderward-tamper"><p><?php
                /* translators: %s: folder path */
                printf(esc_html__('Tamper detection for the saved settings is off: PHP cannot write the seal file in %s.', 'elderward'), '<code>' . esc_html(Elderward_Plugin::content_dir()) . '</code>');
            ?></p></div>
            <?php
            return;
        }
        if ($status['lost'] > 0) {
            ?>
            <div class="notice notice-warning elderward-tamper"><p><?php
                printf(
                    /* translators: %s: date and time */
                    esc_html__('The tamper seal for the saved settings was missing on %s and has been recreated from the current settings. Something deleted it, or the site was moved without it. Check the saved false positives and custom signatures, then confirm them.', 'elderward'),
                    esc_html(wp_date(get_option('date_format') . ' ' . get_option('time_format'), $status['lost']))
                );
            ?></p><p><?php self::seal_button('accept_all', __('The saved settings are correct', 'elderward')); ?></p></div>
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
        <div class="notice notice-error elderward-tamper"><p><strong><?php esc_html_e('Some saved settings were changed outside Elderward, directly in the database.', 'elderward'); ?></strong>
            <?php esc_html_e('That is how an attacker hides from a scanner. Review each change: keep it only if you or another administrator made it on purpose.', 'elderward'); ?></p>
            <ul class="elderward-tamper-list">
                <?php if ($fp_count > 0) : ?>
                    <li><?php
                        printf(
                            /* translators: %d: number of false positives */
                            esc_html(_n('%d saved false positive is ignored until you review it.', '%d saved false positives are ignored until you review them.', $fp_count, 'elderward')),
                            (int) $fp_count
                        );
                    ?> <a href="<?php echo esc_url(add_query_arg('view', 'fp', self::page_url())); ?>#elderward-fp-rules"><?php esc_html_e('Review false positives', 'elderward'); ?></a></li>
                <?php endif; ?>
                <?php if ($sig_count > 0) : ?>
                    <li><?php
                        printf(
                            /* translators: %d: number of signatures */
                            esc_html(_n('%d custom signature was added, changed or removed.', '%d custom signatures were added, changed or removed.', $sig_count, 'elderward')),
                            (int) $sig_count
                        );
                    ?> <a href="<?php echo esc_url(self::signatures_url()); ?>"><?php esc_html_e('Review signatures', 'elderward'); ?></a></li>
                <?php endif; ?>
                <?php if ($set_count > 0) : ?>
                    <li><?php esc_html_e('The scan settings (how and when scans run, the access log path) were changed. Check them under Settings on the Scan tab.', 'elderward'); ?>
                        <?php self::seal_button('accept_settings', __('The scan settings are correct', 'elderward')); ?></li>
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

    /**
     * Every finding of the job, worst severity first. One pass per
     * severity, each paged by id: paging by id over a severity-sorted
     * result would skip every lower-id row after the first page, and an
     * export that silently drops findings is worse than none.
     */
    private static function iterate_findings($job_id)
    {
        global $wpdb;
        $table = Elderward_Plugin::findings_table();
        $known = array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO');
        // phpcs:disable WordPress.DB -- the plugin's own table (name from the base prefix, never user input); values go through prepare(); results must not be cached.
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
        $tab = (isset($_GET['tab']) && in_array($_GET['tab'], array('signatures', 'hardening', 'recovery', 'assistants'), true)) ? sanitize_key(wp_unslash($_GET['tab'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- selects a tab.
        $fp_view = isset($_GET['view']) && 'fp' === $_GET['view']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter on a listing.
        if ($fp_view) {
            $filter = '';
        }
        $page_url = self::page_url();
        ?>
        <div class="wrap elderward-wrap">
            <h1 class="screen-reader-text"><?php esc_html_e('Elderward', 'elderward'); ?></h1>
            <header class="elderward-brand">
                <img class="elderward-brand-mark" src="<?php echo esc_url(ELDERWARD_URL . 'assets/img/elderward-mark.svg'); ?>" alt="" width="64" height="64" />
                <div class="elderward-brand-text">
                    <img class="elderward-brand-word" src="<?php echo esc_url(ELDERWARD_URL . 'assets/img/elderward-wordmark.svg'); ?>" alt="<?php esc_attr_e('Elderward', 'elderward'); ?>" width="124" height="34" />
                    <p class="elderward-brand-tag"><?php esc_html_e('Malware scanner and incident response for WordPress', 'elderward'); ?></p>
                </div>
                <span class="elderward-brand-version"><?php
                    /* translators: %s: plugin version number */
                    printf(esc_html__('Version %s', 'elderward'), esc_html(ELDERWARD_VERSION));
                ?></span>
            </header>
            <hr class="wp-header-end" />
            <?php foreach (self::take_notices() as $notice) : ?>
                <div class="notice notice-<?php echo esc_attr($notice[0]); ?> is-dismissible"><p><?php echo esc_html($notice[1]); ?></p></div>
            <?php endforeach; ?>
            <?php self::render_tamper_notices($job); ?>
            <nav class="nav-tab-wrapper elderward-tabs">
                <a href="<?php echo esc_url($page_url); ?>" class="nav-tab <?php echo '' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Scan', 'elderward'); ?></a>
                <a href="<?php echo esc_url(self::signatures_url()); ?>" class="nav-tab <?php echo 'signatures' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Signatures', 'elderward'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'hardening', $page_url)); ?>" class="nav-tab <?php echo 'hardening' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Hardening', 'elderward'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'recovery', $page_url)); ?>" class="nav-tab <?php echo 'recovery' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Recovery', 'elderward'); ?></a>
                <a href="<?php echo esc_url(add_query_arg('tab', 'assistants', $page_url)); ?>" class="nav-tab <?php echo 'assistants' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('AI assistants', 'elderward'); ?></a>
            </nav>
            <?php if ('' !== $tab) : ?>
                <?php
                if ('signatures' === $tab) {
                    self::render_signatures_tab();
                } elseif ('hardening' === $tab) {
                    Elderward_Admin_Hardening::render();
                } elseif ('recovery' === $tab) {
                    Elderward_Admin_Recovery::render();
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

        $export_base = wp_nonce_url(admin_url('admin-post.php?action=elderward_export'), self::NONCE_EXPORT);
        $settings = Elderward_Settings::get();
        $running = null !== $job && 'running' === $job['status'];
        $datetime_format = get_option('date_format') . ' ' . get_option('time_format');
        $next_run = Elderward_Cron::next_run();
        $fp_rules = Elderward_False_Positives::all_rules();
        $log_real = '' === $settings['log'] ? '' : Elderward_Settings::resolve_log_path($settings['log']);
        ?>
            <div class="elderward-card elderward-run">
                <div class="elderward-card-head">
                    <h2><?php esc_html_e('Scan this site', 'elderward'); ?></h2>
                </div>
                <p class="elderward-lead"><?php esc_html_e('Looks for malware and signs of a break-in. A scan only reports what it finds: nothing on your site is changed.', 'elderward'); ?></p>
                <ul class="elderward-scope">
                    <li><?php esc_html_e('WordPress, plugin and theme files compared with the official copies', 'elderward'); ?></li>
                    <li><?php esc_html_e('Known malware in your files', 'elderward'); ?></li>
                    <li><?php esc_html_e('Suspicious entries in the database and admin accounts', 'elderward'); ?></li>
                    <li><?php esc_html_e('Files with faked dates, and the server crontab', 'elderward'); ?></li>
                    <li>
                        <?php
                        if ('' === $settings['log']) {
                            esc_html_e('Access logs: not checked (add their location under Settings)', 'elderward');
                        } elseif (is_wp_error($log_real)) {
                            /* translators: %s: access log path */
                            printf(esc_html__('Access logs: %s cannot be read, so they are skipped (see Settings)', 'elderward'), '<code>' . esc_html($settings['log']) . '</code>');
                        } else {
                            /* translators: %s: access log path */
                            printf(esc_html__('Access logs in %s', 'elderward'), '<code>' . esc_html($settings['log']) . '</code>');
                        }
                        ?>
                    </li>
                </ul>
                <p class="elderward-buttons">
                    <button type="button" class="button button-primary button-hero" id="elderward-start" <?php disabled($running); ?>><?php esc_html_e('Start scan', 'elderward'); ?></button>
                    <button type="button" class="button button-hero" id="elderward-cancel" <?php disabled(!$running); ?>><?php esc_html_e('Cancel', 'elderward'); ?></button>
                </p>
                <div id="elderward-progress" class="elderward-progress" <?php echo $running ? '' : 'hidden'; ?>>
                    <div class="elderward-bar"><div class="elderward-bar-fill" style="width: <?php echo null === $job ? 0 : (int) Elderward_Job::percent($job); ?>%"></div></div>
                    <p id="elderward-status-text"><?php echo null === $job ? '' : esc_html($job['message']); ?></p>
                    <p id="elderward-runner-note" class="description">
                        <?php
                        if ($running) {
                            echo !empty($job['background'])
                                ? esc_html__('Running in the background: you can leave this page and come back later.', 'elderward')
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
                            $template = __('Last automatic scan: %1$s. Started %2$s, finished %3$s.', 'elderward');
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

            <?php if (null !== $job) : ?>
            <div class="elderward-card elderward-findings">
                <div class="elderward-card-head">
                    <h2><?php esc_html_e('Findings', 'elderward'); ?> <?php self::help_button('elderward-help-findings'); ?></h2>
                    <div class="elderward-head-actions">
                        <a class="button" href="<?php echo esc_url(add_query_arg('format', 'txt', $export_base)); ?>" title="<?php esc_attr_e('One finding per line: severity, type, path, detail', 'elderward'); ?>"><?php esc_html_e('Export as text', 'elderward'); ?></a>
                        <a class="button" href="<?php echo esc_url(add_query_arg('format', 'json', $export_base)); ?>" title="<?php esc_attr_e('One JSON object per line (NDJSON), with context and hashes', 'elderward'); ?>"><?php esc_html_e('Export as JSON', 'elderward'); ?></a>
                    </div>
                </div>
                <?php
                self::help_text('elderward-help-findings', array(
                    __('HIGH: almost certainly malicious; deal with it first. MEDIUM: suspicious; check it. LOW: worth knowing. INFO: for the record (for example the list of administrators). ERROR: a check could not run, so that area is unknown rather than clean.', 'elderward'),
                    __('Timestamp and log findings are leads, not proof: confirm them before acting.', 'elderward'),
                    __('If you checked a finding and it is harmless, mark it as a false positive: later scans hide it, but only while the file stays exactly as you reviewed it. Download sample saves a password-protected copy of a flagged file for a malware analyst.', 'elderward'),
                ));
                ?>
                <ul class="elderward-filters">
                    <li><a href="<?php echo esc_url($page_url); ?>" class="<?php echo ('' === $filter && !$fp_view) ? 'current' : ''; ?>"><?php esc_html_e('All', 'elderward'); ?> <span class="count">(<?php echo (int) $total; ?>)</span></a></li>
                    <?php foreach ($severities as $severity) : ?>
                        <li><a href="<?php echo esc_url(add_query_arg('severity', strtolower($severity), $page_url)); ?>" class="<?php echo $filter === $severity ? 'current' : ''; ?>"><?php echo esc_html($severity); ?> <span class="count">(<?php echo (int) $counts[$severity]; ?>)</span></a></li>
                    <?php endforeach; ?>
                    <li><a href="<?php echo esc_url(add_query_arg('view', 'fp', $page_url)); ?>" class="<?php echo $fp_view ? 'current' : ''; ?>"><?php esc_html_e('False positives', 'elderward'); ?> <span class="count">(<?php echo (int) $fp_total; ?>)</span></a></li>
                </ul>

                <div class="elderward-table-scroll"><table class="widefat striped elderward-table">
                    <thead>
                        <tr>
                            <th class="elderward-col-sev"><?php esc_html_e('Severity', 'elderward'); ?></th>
                            <th class="elderward-col-type"><?php esc_html_e('Type', 'elderward'); ?></th>
                            <th class="elderward-col-path"><?php esc_html_e('Where', 'elderward'); ?></th>
                            <th><?php esc_html_e('Details', 'elderward'); ?></th>
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
                                echo 'running' === $job['status'] ? esc_html__('Scan in progress…', 'elderward') : esc_html__('Nothing found.', 'elderward');
                            }
                            ?>
                        </td></tr>
                    <?php else : ?>
                        <?php foreach ($findings as $finding) : ?>
                            <?php
                            $path = (string) $finding->path;
                            $short = Elderward_Plugin::relative_path($path);
                            $context = self::decode_context($finding->context);
                            $fp = (int) $finding->fp;
                            $fingerprint = '' !== (string) $finding->fingerprint ? $finding->fingerprint : Elderward_False_Positives::fingerprint($finding->type, $finding->path, $finding->detail);
                            $sha256 = (null === $finding->sha256 || '' === $finding->sha256) ? '' : $finding->sha256;
                            ?>
                            <tr data-id="<?php echo (int) $finding->id; ?>" data-fingerprint="<?php echo esc_attr($fingerprint); ?>">
                                <td><span class="elderward-sev elderward-sev-<?php echo esc_attr(strtolower($finding->severity)); ?>"><?php echo esc_html($finding->severity); ?></span></td>
                                <td><span class="elderward-type"><?php echo esc_html($finding->type); ?></span></td>
                                <td><code class="elderward-path" title="<?php echo esc_attr($path); ?>"><?php echo esc_html($short); ?></code></td>
                                <td>
                                    <?php echo esc_html($finding->detail); ?>
                                    <?php if (!empty($context)) : ?>
                                        <details><summary><?php esc_html_e('Context', 'elderward'); ?></summary>
                                            <pre><?php echo esc_html(implode("\n", $context)); ?></pre>
                                        </details>
                                    <?php endif; ?>
                                    <?php if ('' !== $sha256) : ?>
                                        <p class="elderward-hash"><span>SHA-256</span> <code><?php echo esc_html($sha256); ?></code>
                                            <a href="<?php echo esc_url('https://www.virustotal.com/gui/file/' . $sha256); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Look up on VirusTotal', 'elderward'); ?><span class="screen-reader-text"> <?php esc_html_e('(opens in a new tab)', 'elderward'); ?></span></a></p>
                                    <?php endif; ?>
                                    <?php if (Elderward_False_Positives::CHANGED === $fp) : ?>
                                        <p class="elderward-note"><?php esc_html_e('Marked as a false positive before, but the file has changed since it was reviewed, so it is reported again.', 'elderward'); ?></p>
                                    <?php elseif (Elderward_False_Positives::MATCHED === $fp && isset($fp_rules[$fingerprint])) : ?>
                                        <p class="elderward-fp-why"><?php echo esc_html(self::rule_summary($fp_rules[$fingerprint], $datetime_format)); ?></p>
                                    <?php endif; ?>
                                </td>
                                <td class="elderward-actions">
                                    <?php if (Elderward_False_Positives::MATCHED === $fp) : ?>
                                        <button type="button" class="button button-small" data-fp-action="unmark"><?php esc_html_e('Not a false positive', 'elderward'); ?></button>
                                    <?php else : ?>
                                        <button type="button" class="button button-small" data-fp-action="mark"><?php esc_html_e('Mark as false positive', 'elderward'); ?></button>
                                    <?php endif; ?>
                                    <?php if ('' !== $sha256 && 1 !== preg_match('/^wp-config/i', basename($path))) : ?>
                                        <a class="button button-small" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=elderward_sample&id=' . (int) $finding->id), self::NONCE_SAMPLE . (int) $finding->id)); ?>"><?php esc_html_e('Download sample', 'elderward'); ?></a>
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
                <p class="description elderward-sample-help">
                    <?php
                    if (Elderward_Sample::can_encrypt()) {
                        esc_html_e('Download sample saves the file in a zip protected with the password "infected", plus a note of where it was found and why. Send it to a malware analyst or sandbox yourself: Elderward never uploads anything. The VirusTotal link sends only the file\'s hash, from your browser.', 'elderward');
                    } else {
                        esc_html_e('Download sample saves the file in a zip with a note of where it was found and why. This server\'s PHP cannot password-protect zips, so your antivirus may block the download. Elderward never uploads anything. The VirusTotal link sends only the file\'s hash, from your browser.', 'elderward');
                    }
                    ?>
                </p>
            </div>

            <?php if ($fp_view) : ?>
                <?php self::render_fp_rules($fp_rules, $datetime_format); ?>
            <?php endif; ?>

            <div class="elderward-card">
                <div class="elderward-card-head">
                    <h2><?php esc_html_e('Cleaning up', 'elderward'); ?></h2>
                </div>
                <p><?php esc_html_e('This page never changes files. Cleanup and restore run from the command line, where you can take a backup first and preview every change:', 'elderward'); ?></p>
                <pre class="elderward-cli"><span class="elderward-cli-comment"><?php esc_html_e('# Preview, then remove known malware from infected files', 'elderward'); ?></span>
wp elderward scan --dryrun
wp elderward scan

<span class="elderward-cli-comment"><?php esc_html_e('# Preview, then restore modified WordPress, plugin and theme files', 'elderward'); ?></span>
wp elderward integrity --restore --dryrun
wp elderward integrity --restore --quarantine-dir=/path/outside/webroot</pre>
                <p class="description"><?php esc_html_e('No WP-CLI? The same scanners run with php bin/elderward.php from the plugin folder; see the readme.', 'elderward'); ?></p>
            </div>
            <?php endif; ?>

            <?php self::render_settings($settings, $datetime_format, $next_run, $log_real); ?>
        </div>
        <?php
    }

    /**
     * The settings card: how scans run, automatic scans, access logs.
     */
    private static function render_settings(array $settings, $datetime_format, $next_run, $log_real)
    {
        ?>
        <div class="elderward-card elderward-settings" id="elderward-settings">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('Settings', 'elderward'); ?></h2>
            </div>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="elderward_save_settings" />
                <?php wp_nonce_field(self::NONCE_SETTINGS); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php esc_html_e('Run scans', 'elderward'); ?> <?php self::help_button('elderward-help-runner'); ?></th>
                        <td>
                            <fieldset>
                                <legend class="screen-reader-text"><?php esc_html_e('Run scans', 'elderward'); ?></legend>
                                <label><input type="radio" name="elderward[runner]" value="background" <?php checked($settings['runner'], 'background'); ?> /> <?php esc_html_e('In the background (recommended)', 'elderward'); ?></label>
                                <p class="description"><?php esc_html_e('The scan keeps going after you leave this page.', 'elderward'); ?></p>
                                <label><input type="radio" name="elderward[runner]" value="browser" <?php checked($settings['runner'], 'browser'); ?> /> <?php esc_html_e('Only while this page is open', 'elderward'); ?></label>
                                <p class="description"><?php esc_html_e('Use this if background scans never finish on your host.', 'elderward'); ?></p>
                            </fieldset>
                            <?php
                            self::help_text('elderward-help-runner', array(
                                __('Background scans run in short steps through WP-Cron, WordPress\'s task runner. For that, the site must be able to make a request to its own wp-cron.php; Tools > Site Health reports it as "loopback requests". If the page notices that a background scan stopped moving, it carries on from your browser tab.', 'elderward'),
                                __('"Only while this page is open" runs the same steps from your browser tab instead. Closing the tab pauses the scan; opening the page again resumes it.', 'elderward'),
                            ));
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="elderward-schedule"><?php esc_html_e('Automatic scans', 'elderward'); ?></label> <?php self::help_button('elderward-help-schedule'); ?></th>
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
                                printf(esc_html__('Scans on a schedule, without you starting them. Times use the site\'s time zone (%s).', 'elderward'), esc_html(wp_timezone_string()));
                                if (null !== $next_run) {
                                    echo ' ';
                                    /* translators: %s: date and time of the next automatic scan */
                                    printf(esc_html__('Next scan: %s.', 'elderward'), '<strong>' . esc_html(wp_date($datetime_format, $next_run)) . '</strong>');
                                }
                                ?>
                            </p>
                            <?php
                            self::help_text('elderward-help-schedule', array(
                                __('An automatic scan is the same scan as the Start scan button. It always runs in the background, checks the access logs set below, and is skipped if another scan is still in progress. Its results replace the ones on this page.', 'elderward'),
                                __('WP-Cron starts tasks when someone visits the site, so on a quiet site a scan can start a little late. For exact times, have your host call wp-cron.php from a real cron job.', 'elderward'),
                            ));
                            ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="elderward-settings-log"><?php esc_html_e('Access logs', 'elderward'); ?></label> <?php self::help_button('elderward-help-log'); ?></th>
                        <td>
                            <input type="text" id="elderward-settings-log" name="elderward[log]" class="regular-text code" placeholder="/var/log/apache2" autocomplete="off" value="<?php echo esc_attr($settings['log']); ?>" />
                            <p class="description">
                                <?php esc_html_e('Optional. A web server log file or folder, checked by every scan.', 'elderward'); ?>
                                <?php if (is_wp_error($log_real)) : ?>
                                    <span class="elderward-error"><?php esc_html_e('This path does not exist or PHP cannot read it, so scans skip the logs.', 'elderward'); ?></span>
                                <?php endif; ?>
                            </p>
                            <?php
                            self::help_text('elderward-help-log', array(
                                __('The logs show requests to web shells, login and upload attacks, and which files the attackers used. Scans read them only; they are never changed or sent anywhere.', 'elderward'),
                                __('Common locations are /var/log/apache2, /var/log/nginx or a logs folder next to your site; your host\'s control panel or support can tell you. A folder includes rotated .log.1 and .gz files. The PHP user must be able to read them. Leave the field empty to skip this check.', 'elderward'),
                            ));
                            ?>
                        </td>
                    </tr>
                </table>
                <?php if (Elderward_Cron::trigger_disabled()) : ?>
                    <p class="elderward-note"><?php esc_html_e('DISABLE_WP_CRON is set on this site, so WordPress does not start WP-Cron on its own. Background and automatic scans only move forward when your server\'s cron job calls wp-cron.php (every minute or two is ideal).', 'elderward'); ?></p>
                <?php endif; ?>
                <?php submit_button(__('Save settings', 'elderward'), 'primary', 'submit', false); ?>
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
            '<button type="button" class="elderward-help-toggle" aria-expanded="false" aria-controls="%1$s" title="%2$s"><span aria-hidden="true">?</span><span class="screen-reader-text">%2$s</span></button>',
            esc_attr($id),
            esc_attr__('More about this', 'elderward')
        );
    }

    public static function help_text($id, array $paragraphs)
    {
        echo '<div class="elderward-help-text" id="' . esc_attr($id) . '" hidden>';
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
        $name = $user ? $user->display_name : __('a deleted user', 'elderward');
        $when = !empty($rule['time']) ? wp_date($datetime_format, (int) $rule['time']) : '—';
        if (isset($rule['via']) && Elderward_False_Positives::VIA_ASSISTANT === $rule['via']) {
            /* translators: 1: user display name, 2: date and time */
            $text = sprintf(__('Marked as a false positive by an AI assistant acting as %1$s on %2$s.', 'elderward'), $name, $when);
        } else {
            /* translators: 1: user display name, 2: date and time */
            $text = sprintf(__('Marked as a false positive by %1$s on %2$s.', 'elderward'), $name, $when);
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
        $diff = Elderward_Seal::diff('false_positives', $rules);
        $tampered = array_flip(array_merge($diff['added'], $diff['changed']));
        ?>
        <div class="elderward-card elderward-fp-rules" id="elderward-fp-rules">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('Saved false positives', 'elderward'); ?></h2>
            </div>
            <p class="description"><?php esc_html_e('Each one hides the same finding (same type, location and details) in later scans. For a finding about a file, it only applies while the file is exactly the one that was reviewed.', 'elderward'); ?></p>
            <?php if (empty($rules)) : ?>
                <p><?php esc_html_e('None saved.', 'elderward'); ?></p>
            <?php else : ?>
                <div class="elderward-table-scroll"><table class="widefat striped elderward-table">
                    <thead><tr>
                        <th class="elderward-col-type"><?php esc_html_e('Type', 'elderward'); ?></th>
                        <th class="elderward-col-path"><?php esc_html_e('Where', 'elderward'); ?></th>
                        <th><?php esc_html_e('Details', 'elderward'); ?></th>
                        <th class="elderward-col-actions"><?php esc_html_e('Actions', 'elderward'); ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rules as $fingerprint => $rule) : ?>
                        <?php
                        $rule = is_array($rule) ? $rule : array();
                        $path = isset($rule['path']) ? (string) $rule['path'] : '';
                        $short = Elderward_Plugin::relative_path($path);
                        ?>
                        <?php $is_tampered = isset($tampered[(string) $fingerprint]); ?>
                        <tr data-fingerprint="<?php echo esc_attr($fingerprint); ?>" class="<?php echo $is_tampered ? 'elderward-tampered' : ''; ?>">
                            <td><span class="elderward-type"><?php echo esc_html(isset($rule['type']) ? $rule['type'] : ''); ?></span></td>
                            <td><code class="elderward-path" title="<?php echo esc_attr($path); ?>"><?php echo esc_html($short); ?></code></td>
                            <td><?php echo esc_html(isset($rule['detail']) ? $rule['detail'] : ''); ?>
                                <?php if ($is_tampered) : ?>
                                    <p class="elderward-tamper-badge"><?php esc_html_e('Changed outside Elderward, so it is ignored. Keep it only if an administrator made this change.', 'elderward'); ?></p>
                                <?php else : ?>
                                    <p class="elderward-fp-why"><?php echo esc_html(self::rule_summary($rule, $datetime_format)); ?></p>
                                <?php endif; ?></td>
                            <td class="elderward-actions">
                                <?php if ($is_tampered) : ?>
                                    <button type="button" class="button button-small" data-fp-action="keep"><?php esc_html_e('Keep', 'elderward'); ?></button>
                                <?php endif; ?>
                                <button type="button" class="button button-small" data-fp-action="unmark"><?php esc_html_e('Remove', 'elderward'); ?></button></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table></div>
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
