<?php
/**
 * Plugin settings: how scans run (browser steps or WP-Cron in the
 * background) and the optional scan schedule.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Settings
{
    const OPTION = 'facheiro_settings';

    public static function defaults()
    {
        return array(
            'runner'   => 'background',
            'schedule' => 'off',
            'time'     => '03:00',
            'day'      => 0,
            'log'      => '',
        );
    }

    /**
     * Human-readable choices for the settings form.
     */
    public static function runners()
    {
        return array(
            'background' => __('Em segundo plano (WP-Cron)', 'facheiro'),
            'browser'    => __('Nesta aba do navegador', 'facheiro'),
        );
    }

    public static function schedules()
    {
        return array(
            'off'        => __('Desligadas', 'facheiro'),
            'daily'      => __('Diárias', 'facheiro'),
            'twicedaily' => __('Duas vezes por dia', 'facheiro'),
            'weekly'     => __('Semanais', 'facheiro'),
        );
    }

    public static function get()
    {
        $stored = get_option(self::OPTION);
        return self::sanitize(is_array($stored) ? $stored : array());
    }

    /**
     * Whitelist every field; anything unexpected falls back to the default.
     */
    public static function sanitize(array $input)
    {
        $out = self::defaults();
        if (isset($input['runner']) && array_key_exists($input['runner'], self::runners())) {
            $out['runner'] = $input['runner'];
        }
        if (isset($input['schedule']) && array_key_exists($input['schedule'], self::schedules())) {
            $out['schedule'] = $input['schedule'];
        }
        if (isset($input['time']) && preg_match('/^([01][0-9]|2[0-3]):([0-5][0-9])$/', (string) $input['time'])) {
            $out['time'] = (string) $input['time'];
        }
        if (isset($input['day'])) {
            $day = (int) $input['day'];
            if ($day >= 0 && $day <= 6) {
                $out['day'] = $day;
            }
        }
        if (isset($input['log'])) {
            $out['log'] = sanitize_text_field((string) $input['log']);
        }
        return $out;
    }

    /**
     * Save and apply: the recurring event follows the stored schedule.
     */
    public static function save(array $input)
    {
        $settings = self::sanitize($input);
        Facheiro_Seal::update('settings', function () use ($settings) {
            return $settings;
        });
        Facheiro_Cron::sync_schedule($settings);
        return $settings;
    }

    /**
     * The only free-text input of the plugin: an access log path must name an
     * existing file or directory readable by PHP. Returns the resolved path,
     * '' for an empty input, or a WP_Error.
     */
    public static function resolve_log_path($log)
    {
        $log = trim((string) $log);
        if ('' === $log) {
            return '';
        }
        $real = realpath($log);
        if (false === $real || !is_readable($real) || !(is_file($real) || is_dir($real))) {
            return new WP_Error('facheiro_log_path', __('O caminho dos logs de acesso não existe ou o PHP não consegue lê-lo.', 'facheiro'));
        }
        return $real;
    }
}
