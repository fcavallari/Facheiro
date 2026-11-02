<?php
/**
 * The Recovery tab: create or revoke the key that unlocks recovery.php, and
 * explain how to use it when WordPress itself is broken.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Admin_Recovery
{
    const NONCE = 'elderward_recovery';

    public static function init()
    {
        add_action('admin_post_elderward_recovery', array(__CLASS__, 'action'));
        add_action('wp_ajax_elderward_recovery_create', array(__CLASS__, 'ajax_create'));
    }

    public static function url()
    {
        return add_query_arg('tab', 'recovery', Elderward_Admin::page_url());
    }

    public static function action()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        check_admin_referer(self::NONCE);
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        $notices = array();
        if ('revoke' === $op) {
            $notices[] = Elderward_Recovery_Key::revoke()
                ? array('success', __('Recovery key revoked. The recovery page now answers "not found".', 'elderward'))
                : array('error', __('The key file could not be deleted. Delete wp-content/elderward-recovery-key.php by hand.', 'elderward'));
        }
        Elderward_Admin::notify($notices);
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
        if (!Elderward_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('You are not allowed to do that.', 'elderward')), 403);
        }
        $expiry = isset($_POST['expiry']) ? sanitize_key(wp_unslash($_POST['expiry'])) : '7';
        if (!array_key_exists($expiry, Elderward_Recovery_Key::expiries())) {
            $expiry = '7';
        }
        $key = Elderward_Recovery_Key::create($expiry, wp_get_current_user()->user_login);
        if (is_wp_error($key)) {
            wp_send_json_error(array('message' => $key->get_error_message()), 500);
        }
        nocache_headers();
        wp_send_json_success(array('key' => $key, 'status' => self::status_text(Elderward_Recovery_Key::status())));
    }

    /**
     * One line describing the key file.
     */
    private static function status_text($status)
    {
        $datetime_format = get_option('date_format') . ' ' . get_option('time_format');
        $relative_file = Elderward_Plugin::relative_path(Elderward_Recovery_Key::path());
        if (null === $status) {
            return __('No key yet. Create one while the site works, so recovery mode is ready if it ever breaks.', 'elderward');
        }
        if (!$status['valid']) {
            /* translators: %s: file path */
            return sprintf(__('%s exists but does not hold a usable key (a key typed by hand must be at least 24 characters). Recovery mode stays off until it is fixed or replaced.', 'elderward'), $relative_file);
        }
        if ($status['manual']) {
            /* translators: %s: file path */
            return sprintf(__('A key was added by hand in %s. It never expires: revoke it when you no longer need it.', 'elderward'), $relative_file);
        }
        $text = sprintf(
            /* translators: 1: date and time, 2: user name, 3: expiry date and time or "never" */
            __('Created on %1$s by %2$s. Expires: %3$s.', 'elderward'),
            wp_date($datetime_format, $status['created']),
            '' === $status['by'] ? '—' : $status['by'],
            0 === $status['expires'] ? __('never (until revoked)', 'elderward') : wp_date($datetime_format, $status['expires'])
        );
        if (0 !== $status['expires'] && $status['expires'] <= time()) {
            $text .= ' ' . __('This key has expired.', 'elderward');
        }
        return $text;
    }

    public static function render()
    {
        $status = Elderward_Recovery_Key::status();
        $active = Elderward_Recovery_Key::active();
        $url = Elderward_Recovery_Key::url();
        $relative_file = Elderward_Plugin::relative_path(Elderward_Recovery_Key::path());
        ?>
        <p class="elderward-intro"><?php esc_html_e('If malware or a broken update takes the site down (a white screen, "There has been a critical error", an admin you cannot open), WordPress pages such as this one stop working too. Recovery mode is a separate page that does not load WordPress: it shows the PHP errors that broke the site and runs the full report-only scan, database included.', 'elderward'); ?></p>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('Recovery key', 'elderward'); ?></h2>
                <span class="elderward-check elderward-check-<?php echo $active ? 'protected' : 'unknown'; ?>"><?php echo $active ? esc_html__('Recovery mode is on', 'elderward') : esc_html__('Recovery mode is off', 'elderward'); ?></span>
            </div>

            <div class="elderward-key-reveal" id="elderward-key-reveal" hidden>
                <p><strong><?php esc_html_e('Your recovery key', 'elderward'); ?></strong> — <?php esc_html_e('save it in your password manager now. Elderward keeps only a fingerprint of it and cannot show it again.', 'elderward'); ?></p>
                <p class="elderward-key-row"><input type="text" readonly id="elderward-recovery-key" class="large-text code elderward-copy" value="" />
                    <button type="button" class="button button-primary" data-copy="elderward-recovery-key"><?php esc_html_e('Copy key', 'elderward'); ?></button></p>
            </div>

            <p id="elderward-recovery-status"><?php echo esc_html(self::status_text($status)); ?></p>

            <p class="elderward-field-inline">
                <strong><?php esc_html_e('Recovery page:', 'elderward'); ?></strong>
                <code id="elderward-recovery-url"><?php echo esc_html($url); ?></code>
                <button type="button" class="button button-small" data-copy-text="<?php echo esc_attr($url); ?>"><?php esc_html_e('Copy address', 'elderward'); ?></button>
            </p>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="elderward-recovery-form">
                <input type="hidden" name="action" value="elderward_recovery" />
                <?php wp_nonce_field(self::NONCE); ?>
                <label for="elderward-recovery-expiry"><?php esc_html_e('Valid for', 'elderward'); ?></label>
                <select id="elderward-recovery-expiry" name="expiry">
                    <?php foreach (Elderward_Recovery_Key::expiries() as $value => $label) : ?>
                        <option value="<?php echo esc_attr($value); ?>" <?php selected('30', $value); ?>><?php echo esc_html($label); ?></option>
                    <?php endforeach; ?>
                </select>
                <button type="button" id="elderward-recovery-create" class="button button-primary" data-nonce="<?php echo esc_attr(wp_create_nonce(self::NONCE)); ?>" <?php echo null !== $status ? 'data-replace="1"' : ''; ?>><?php echo null === $status ? esc_html__('Create recovery key', 'elderward') : esc_html__('Create a new key', 'elderward'); ?></button>
                <button type="submit" name="op" value="revoke" class="button" data-confirm="recovery-revoke" <?php echo null === $status ? 'hidden' : ''; ?>><?php esc_html_e('Revoke', 'elderward'); ?></button>
            </form>
            <p class="description"><?php esc_html_e('Creating a new key replaces the old one. Keep the key and the page address together, outside this site: you will need them exactly when this site cannot show them.', 'elderward'); ?></p>
        </div>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('When the site is down', 'elderward'); ?></h2>
            </div>
            <ol class="elderward-steps">
                <li><?php esc_html_e('Open the recovery page address and enter the key.', 'elderward'); ?></li>
                <li><?php esc_html_e('Read "What broke the site": the latest PHP errors, with the plugin or theme they come from. Renaming that plugin\'s folder (over FTP or your host\'s file manager) usually brings the site back.', 'elderward'); ?></li>
                <li><?php esc_html_e('Run the scan to see whether malware is involved. It is report-only, like the scan on this page, and covers files and the database.', 'elderward'); ?></li>
                <li><?php esc_html_e('Clean up from the command line (wp elderward scan, or php bin/elderward.php without WordPress), then revoke the key.', 'elderward'); ?></li>
            </ol>
        </div>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('No key, and WordPress is already broken?', 'elderward'); ?> <?php Elderward_Admin::help_button('elderward-help-manual-key'); ?></h2>
            </div>
            <p><?php esc_html_e('Create the key file yourself over FTP, SFTP or your host\'s file manager:', 'elderward'); ?></p>
            <ol class="elderward-steps">
                <li>
                    <?php
                    /* translators: %s: file path */
                    printf(esc_html__('Create the file %s (next to the plugins folder).', 'elderward'), '<code>' . esc_html($relative_file) . '</code>');
                    ?>
                </li>
                <li><?php esc_html_e('Put this in it, replacing the example key with your own random text of at least 24 characters:', 'elderward'); ?>
                    <pre class="elderward-cli"><?php echo esc_html(Elderward_Recovery_Key::manual_template(wp_generate_password(32, false, false))); ?></pre></li>
                <li><?php esc_html_e('Open the recovery page and enter that key. Delete the file when you are done.', 'elderward'); ?></li>
            </ol>
            <p><?php esc_html_e('With WP-CLI on the server, this does the same:', 'elderward'); ?> <code>wp elderward recovery-key create --expires=7</code></p>
            <?php
            Elderward_Admin::help_text('elderward-help-manual-key', array(
                __('The file starts with "<?php exit; ?>", so even if someone requests it over the web, the server runs it and shows nothing.', 'elderward'),
                __('If WP-CLI itself fails because of the broken plugin, add --skip-plugins=<that plugin\'s folder name>, or create the file by hand.', 'elderward'),
            ));
            ?>
        </div>

        <div class="elderward-card">
            <div class="elderward-card-head">
                <h2><?php esc_html_e('How the recovery page is protected', 'elderward'); ?></h2>
            </div>
            <ul class="elderward-examples">
                <li><?php esc_html_e('Without a valid, unexpired key file it answers "not found" and does nothing else.', 'elderward'); ?></li>
                <li><?php esc_html_e('Only a fingerprint (SHA-256) of a key created here is stored, and the key is shown to you once without being saved anywhere. Keys are 32 random characters; every wrong guess costs a second. A key typed into the file by hand also gets a 15-minute lockout after 10 wrong tries.', 'elderward'); ?></li>
                <li><?php esc_html_e('A sign-in lasts one hour, ends when the key is revoked or replaced, and is tied to a cookie the page sets only for itself.', 'elderward'); ?></li>
                <li><?php esc_html_e('It reads the database settings from wp-config.php without running it, only reads files and the database, and never changes or uploads anything.', 'elderward'); ?></li>
                <li><?php esc_html_e('Use it over HTTPS: on plain HTTP the key crosses the network unencrypted.', 'elderward'); ?></li>
            </ul>
        </div>
        <?php
    }

    public static function i18n()
    {
        return array(
            'recoveryReplace' => __('Create a new key? The current one stops working.', 'elderward'),
            'recoveryRevoke'  => __('Revoke the recovery key? The recovery page stops working until a new key is created.', 'elderward'),
            'recoveryOn'      => __('Recovery mode is on', 'elderward'),
            'recoveryNew'     => __('Create a new key', 'elderward'),
        );
    }
}
