<?php
namespace Elderward\Engine;

////////////////
// Filesystem helpers shared by the scanners.
//////////////

// Same rule as load.php: WordPress, the CLI or the recovery page, never a
// direct web request.
if (!defined('ABSPATH')) {
    if (!defined('ELDERWARD_RECOVERY') && PHP_SAPI !== 'cli') {
        exit;
    }
}

// File times are shown in the server's time zone on purpose: it is what
// `ls -l` and the access log show, so a finding lines up with them. Inside
// WordPress that zone is UTC, because WordPress sets it.
function local_time($format, $timestamp)
{
    return (date($format, $timestamp)); // phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date -- the server's time zone on purpose, see above.
}

function recursive_file_iterator($dir)
{
    // CATCH_GET_CHILD: an unreadable subdirectory is skipped instead of
    // aborting the whole walk.
    return new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
        \RecursiveIteratorIterator::LEAVES_ONLY,
        \RecursiveIteratorIterator::CATCH_GET_CHILD
    );
}

function under_plugin_dir(Context $ctx, $path)
{
    // Never scan (or correlate) the tool's own files: the signature strings
    // in the source would match themselves.
    if (null === $ctx->plugin_dir) {
        return (false);
    }
    $real = @realpath($path);
    if (false === $real) {
        return (false);
    }
    $real = str_replace('\\', '/', $real);
    return ($real === $ctx->plugin_dir || 0 === strpos($real, $ctx->plugin_dir . '/'));
}

function is_scannable_file(Context $ctx, $file)
{
    if (under_plugin_dir($ctx, $file->getPathname())) {
        return (false);
    }
    return ($ctx->has('allfiles')
        || in_array(strtolower($file->getExtension()), Signatures::extensions(), true));
}

function is_wordpress_root($dir)
{
    return (is_file(rtrim($dir, '/') . '/wp-includes/version.php'));
}

///////////////
// The folders a whole-tree walk covers: the scan directory, plus, when it
// is the WordPress root, any content or plugin folder that lives outside
// it (split-core layouts), which a walk of the root alone never reaches.
//////////////
function scan_roots(Context $ctx, $scan_dir)
{
    $dirs = array($scan_dir);
    if (rtrim($scan_dir, '/') === $ctx->root() && is_wordpress_root($scan_dir)) {
        $dirs = array_merge($dirs, Layout::of($ctx)->outside_root);
    }
    return ($dirs);
}

function require_wordpress_root($root)
{
    $root = rtrim($root, '/');
    if (!is_file($root . '/wp-includes/version.php')) {
        throw new Fatal($root . ' does not look like a WordPress root (wp-includes/version.php not found)');
    }
    return ($root);
}

function is_php_file($path)
{
    return (preg_match('@\.(?:ph(?:p[34578]?|t|tml|ps)|inc)$@i', $path) === 1);
}

function write_cleaned_file($file_path, $cleaned_content)
{
    // Write to a temp file and rename over the target so the original is never
    // truncated in place by a partial write (disk full, killed mid-write).
    $tmp_path = @tempnam(dirname($file_path), basename($file_path) . '.');
    if (false === $tmp_path) {
        return (false);
    }

    $written = @file_put_contents($tmp_path, $cleaned_content);
    if ($written !== strlen($cleaned_content)) {
        @unlink($tmp_path);
        return (false);
    }

    // tempnam creates the file 0600 and owned by whoever runs the tool;
    // carry over the target's owner, group and permissions. An operator
    // cleaning as root would otherwise leave a 0640 or 0600 file the web
    // server can no longer read (a white screen if it is wp-config.php).
    // Owner first: chown clears some mode bits. Without the privilege the
    // calls fail and the file stays with the current user, as before.
    $perms = @fileperms($file_path);
    if (false !== $perms) {
        $owner = @fileowner($file_path);
        $group = @filegroup($file_path);
        if (false !== $group && $group !== @filegroup($tmp_path) && function_exists('chgrp')) {
            @chgrp($tmp_path, $group);
        }
        if (false !== $owner && $owner !== @fileowner($tmp_path) && function_exists('chown')) {
            @chown($tmp_path, $owner);
        }
        @chmod($tmp_path, $perms & 0777);
    } else {
        // No existing target (restoring a deleted file): 0600 would be
        // unreadable to the web server.
        @chmod($tmp_path, 0644);
    }

    if (!@rename($tmp_path, $file_path)) {
        @unlink($tmp_path);
        return (false);
    }
    return (true);
}

function list_files_recursive($dir, $base)
{
    $relative_paths = array();
    $walker = recursive_file_iterator($dir);
    $base_length = strlen(rtrim($base, '/')) + 1;
    foreach ($walker as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $relative_paths[] = str_replace('\\', '/', substr($file->getPathname(), $base_length));
    }
    return $relative_paths;
}

function list_files_absolute($dir)
{
    $absolute_paths = array();
    foreach (list_files_recursive($dir, $dir) as $relative_path) {
        $absolute_paths[] = $dir . '/' . $relative_path;
    }
    return $absolute_paths;
}
