<?php
/**
 * Facheiro
 *
 * @package           Facheiro
 * @author            Fio Cavallari
 * @license           GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       Facheiro
 * Plugin URI:        https://github.com/fcavallari/Facheiro
 * Description:       Varredura de malware e resposta a incidentes: verificação de integridade, banco de dados e logs, blindagem do servidor e um modo de recuperação para sites que não carregam mais.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.2
 * Author:            Fio Cavallari
 * Author URI:        https://github.com/fcavallari
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       facheiro
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

define('FACHEIRO_VERSION', '1.0.0');
define('FACHEIRO_FILE', __FILE__);
define('FACHEIRO_DIR', plugin_dir_path(__FILE__));
define('FACHEIRO_URL', plugin_dir_url(__FILE__));

require_once FACHEIRO_DIR . 'includes/engine/load.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-plugin.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-wp-http.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-wp-db.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-seal.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-settings.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-cron.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-job.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-false-positives.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-sample.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-signatures.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-abilities.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-store-reporter.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-admin.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-hardening.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-admin-hardening.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-recovery-key.php';
require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-admin-recovery.php';

register_activation_hook(__FILE__, array('Facheiro_Plugin', 'activate'));
register_deactivation_hook(__FILE__, array('Facheiro_Plugin', 'deactivate'));
add_action('plugins_loaded', array('Facheiro_Plugin', 'init'));

if (defined('WP_CLI') && WP_CLI) {
    require_once FACHEIRO_DIR . 'includes/plugin/class-facheiro-cli.php';
    WP_CLI::add_command('facheiro', 'Facheiro_CLI');
}
