<?php
/**
 * WP-Cron side of the admin job: a background runner that keeps a scan
 * moving after the page is closed, and the recurring scheduled scan.
 *
 * The runner is a chain of single events. Each one runs job steps for a
 * chunk of time, then schedules the next event for "now" and spawns a new
 * wp-cron request. Before a chunk starts, a safety event is scheduled a
 * little after the chunk would end, so a request the server kills still
 * leaves something for the next cron trigger to pick up. The job's own lock
 * keeps a cron chunk and a browser step from running at the same time.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Cron
{
    const HOOK_STEP = 'facheiro_run_job';
    const HOOK_SCAN = 'facheiro_scheduled_scan';
    // Longest run of steps in one cron request.
    const CHUNK_SECONDS = 120;
    // Margin between the end of a chunk and its safety event.
    const SAFETY_SECONDS = 60;

    private static $respawn_registered = false;

    public static function init()
    {
        add_action(self::HOOK_STEP, array(__CLASS__, 'run_job'));
        add_action(self::HOOK_SCAN, array(__CLASS__, 'scheduled_scan'));
    }

    /**
     * True when WordPress's own trigger (a request to wp-cron.php at the end
     * of page loads) is turned off; a server cron job must then call it.
     */
    public static function trigger_disabled()
    {
        return defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
    }

    /**
     * Get the background runner going (or going again) for the running job:
     * an event due now plus a wp-cron request to run it.
     */
    public static function kick()
    {
        $job = Facheiro_Job::current();
        if (null === $job || 'running' !== $job['status']) {
            return;
        }
        self::schedule_step(time());
        if (wp_doing_cron()) {
            // spawn_cron() refuses to run inside a cron request; chain the
            // next one once this request has released WordPress's cron lock.
            if (!self::$respawn_registered) {
                self::$respawn_registered = true;
                register_shutdown_function(array(__CLASS__, 'respawn'));
            }
            return;
        }
        spawn_cron();
    }

    public static function clear_step()
    {
        wp_clear_scheduled_hook(self::HOOK_STEP);
    }

    private static function schedule_step($timestamp)
    {
        self::clear_step();
        wp_schedule_single_event($timestamp, self::HOOK_STEP);
    }

    /**
     * Cron handler: run steps until the job ends or the chunk is spent,
     * then hand over to the next event.
     */
    public static function run_job()
    {
        $job = Facheiro_Job::current();
        if (null === $job || 'running' !== $job['status'] || empty($job['background'])) {
            self::clear_step();
            return;
        }

        ignore_user_abort(true);
        $chunk = self::chunk_seconds();
        self::schedule_step(time() + (int) ceil($chunk) + self::SAFETY_SECONDS);
        $stop = microtime(true) + $chunk;

        while (microtime(true) < $stop) {
            $job = Facheiro_Job::step($stop);
            if (null === $job || 'running' !== $job['status']) {
                // complete() already removed the pending event.
                return;
            }
            if (!Facheiro_Job::last_step_ran()) {
                // The browser (or another cron request) holds the lock and is
                // stepping; the safety event covers the hand-back.
                return;
            }
        }
        self::kick();
    }

    /**
     * Seconds of steps one cron request may run. The request is not tied to
     * a browser, so a longer PHP limit is asked for when the host allows it.
     */
    private static function chunk_seconds()
    {
        $limit = (int) ini_get('max_execution_time');
        if ($limit > 0 && $limit < 300 && function_exists('set_time_limit')) {
            $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
            if (!in_array('set_time_limit', $disabled, true)) {
                @set_time_limit(300); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, Squiz.PHP.DiscouragedFunctions.Discouraged -- a background scan chunk needs more than the default 30 seconds; some hosts refuse, so the current limit is re-read below.
                $limit = (int) ini_get('max_execution_time');
            }
        }
        $chunk = (float) self::CHUNK_SECONDS;
        if ($limit > 0) {
            $chunk = min($chunk, max(2.0, $limit * 0.8));
        }
        /**
         * Seconds of scan work one WP-Cron request may do before it hands
         * over to the next one.
         *
         * @param float $chunk Seconds (default min(120, 0.8 x max_execution_time)).
         */
        $chunk = (float) apply_filters('facheiro_background_chunk_seconds', $chunk);
        return ($chunk > 0) ? $chunk : (float) self::CHUNK_SECONDS;
    }

    /**
     * Shutdown handler inside a cron request: ask for the next wp-cron run
     * the way spawn_cron() does, now that wp-cron.php has released its lock.
     */
    public static function respawn()
    {
        if (defined('ALTERNATE_WP_CRON') && ALTERNATE_WP_CRON) {
            return;
        }
        $job = Facheiro_Job::current();
        if (null === $job || 'running' !== $job['status']) {
            return;
        }
        $now = microtime(true);
        $lock = (float) get_transient('doing_cron');
        if ($lock > 0 && $lock + WP_CRON_LOCK_TIMEOUT > $now) {
            // Another cron request is still running; our event stays due
            // and the next trigger picks it up.
            return;
        }
        $key = sprintf('%.22F', $now);
        set_transient('doing_cron', $key);
        $request = array(
            'url'  => add_query_arg('doing_wp_cron', $key, site_url('wp-cron.php')),
            'key'  => $key,
            'args' => array(
                'timeout'   => 0.01,
                'blocking'  => false,
                // Same loopback request as WordPress core's spawn_cron().
                'sslverify' => apply_filters('https_local_ssl_verify', false), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter, applied as core does.
            ),
        );
        /** This filter is documented in wp-includes/cron.php */
        $request = apply_filters('cron_request', $request, $key); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter, so plugins that add auth to cron requests keep working.
        wp_remote_post($request['url'], $request['args']);
    }

    /**
     * Recurring event: start a scan with the saved options unless one is
     * already running. Scheduled scans always run in the background.
     */
    public static function scheduled_scan()
    {
        $current = Facheiro_Job::current();
        if (null !== $current && 'running' === $current['status']) {
            return;
        }
        $settings = Facheiro_Settings::get();
        $options = array();
        $log = Facheiro_Settings::resolve_log_path($settings['log']);
        if (is_string($log) && '' !== $log) {
            $options['scanlog'] = $log;
        }
        $job = Facheiro_Job::start($options, 'schedule', true);
        if (!is_wp_error($job)) {
            self::kick();
        }
    }

    /**
     * Make the recurring event match the settings.
     */
    public static function sync_schedule(?array $settings = null)
    {
        if (null === $settings) {
            $settings = Facheiro_Settings::get();
        }
        wp_clear_scheduled_hook(self::HOOK_SCAN);
        if ('off' === $settings['schedule']) {
            return;
        }
        wp_schedule_event(self::first_run($settings), $settings['schedule'], self::HOOK_SCAN);
    }

    public static function next_run()
    {
        $next = wp_next_scheduled(self::HOOK_SCAN);
        return false === $next ? null : (int) $next;
    }

    /**
     * First run: the configured time of day in the site's timezone (and
     * weekday for a weekly schedule), the next time it comes around.
     */
    public static function first_run(array $settings, $now = null)
    {
        $tz = wp_timezone();
        $base = new DateTimeImmutable(null === $now ? 'now' : '@' . (int) $now);
        $base = $base->setTimezone($tz);
        list($hour, $minute) = array_map('intval', explode(':', $settings['time']));
        $candidate = $base->setTime($hour, $minute, 0);

        if ('weekly' === $settings['schedule']) {
            $ahead = ((int) $settings['day'] - (int) $candidate->format('w') + 7) % 7;
            $candidate = $candidate->modify('+' . $ahead . ' days');
            if ($candidate <= $base) {
                $candidate = $candidate->modify('+7 days');
            }
            return $candidate->getTimestamp();
        }
        if ('twicedaily' === $settings['schedule']) {
            $second = $candidate->modify('+12 hours');
            if ($candidate > $base) {
                return $candidate->getTimestamp();
            }
            if ($second > $base) {
                return $second->getTimestamp();
            }
            return $candidate->modify('+1 day')->getTimestamp();
        }
        if ($candidate <= $base) {
            $candidate = $candidate->modify('+1 day');
        }
        return $candidate->getTimestamp();
    }

    /**
     * Deactivation: nothing of ours may stay in the cron table, and a scan
     * that can no longer run is not left "running".
     */
    public static function deactivate()
    {
        Facheiro_Job::cancel();
        wp_clear_scheduled_hook(self::HOOK_SCAN);
        wp_clear_scheduled_hook(self::HOOK_STEP);
    }
}
