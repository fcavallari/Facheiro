<?php
/**
 * Test-only hooks for the Facheiro admin job (TESTPLAN F6). Copy into
 * wp-content/mu-plugins/ on a test site, never on a real one.
 *
 *   wp option update facheiro_test_budget 0.05   # force many pauses/resumes
 *   wp option update facheiro_test_die 1         # next finding INSERT dies with a PHP fatal (one-shot)
 *   wp option update facheiro_test_exit 1        # every finding INSERT exits silently, like a cut-off request
 *   wp option update facheiro_test_chunk 3       # shorten the WP-Cron chunk (more hand-overs between cron requests)
 *   wp option update facheiro_test_no_loopback 1 # the site cannot reach its own wp-cron.php (blocked loopback)
 *
 * @package Facheiro
 */
add_filter('facheiro_step_budget_seconds', function ($budget) {
    $forced = get_option('facheiro_test_budget');
    return (false === $forced) ? $budget : (float) $forced;
});
add_filter('facheiro_background_chunk_seconds', function ($chunk) {
    $forced = get_option('facheiro_test_chunk');
    return (false === $forced) ? $chunk : (float) $forced;
});
// Simulate a host where loopback requests fail: every request to the
// site's own wp-cron.php errors out, as Site Health would report.
add_filter('pre_http_request', function ($pre, $args, $url) {
    if (false === strpos($url, 'wp-cron.php') || !get_option('facheiro_test_no_loopback')) {
        return $pre;
    }
    return new WP_Error('http_request_failed', 'facheiro test: loopback blocked');
}, 10, 3);
// Simulate a step dying with a PHP fatal while it writes a finding. The
// option lookup inside a 'query' filter runs a query itself, hence the guard.
add_filter('query', function ($sql) {
    static $inside = false;
    if ($inside || 0 !== stripos(ltrim($sql), 'INSERT') || false === strpos($sql, 'facheiro_findings')) {
        return $sql;
    }
    $inside = true;
    $die = get_option('facheiro_test_die');
    if ($die) {
        delete_option('facheiro_test_die');
    }
    $vanish = get_option('facheiro_test_exit');
    $inside = false;
    if ($die) {
        trigger_error('facheiro test fatal', E_USER_ERROR);
    }
    if ($vanish) {
        exit(0); // like a request the web server cut off: no error recorded
    }
    return $sql;
});
