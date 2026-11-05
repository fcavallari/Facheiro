<?php
namespace Elderward\Engine;

////////////////
// Filesystem helpers shared by the scanners.
//////////////

// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- an exception message is data, not output: the entry layer that catches it (CLI, WP-CLI, admin page, recovery page) escapes it for the place it shows it.
// phpcs:disable WordPress.WP.AlternativeFunctions -- the engine also runs without WordPress (standalone CLI, recovery mode), where WP_Filesystem does not exist; it streams files and handles every failure itself.

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

///////////////
// Walks one or more folder trees and yields an SplFileInfo for every entry
// that is not a folder it went into, in the order the filesystem lists
// them. Two things PHP's RecursiveDirectoryIterator gets wrong for a
// scanner:
//
// - A symbolic link to a folder (uploads on shared storage, release-style
//   deploys) hides every file behind it. Here it is followed, but never
//   back up the tree and never twice: a link to the filesystem root, to a
//   parent of the folder it sits in, to a folder a walk already covers
//   ($covered and the roots themselves) or to one already followed is
//   passed over. A planted "x -> /" therefore cannot walk the disk or
//   loop. With $follow off (a run that can modify files) no link is
//   followed and the ones that would have been are listed in $refused.
// - A folder that cannot be opened either throws (the root) or is dropped
//   without a word (a nested one). Here it is listed in $unreadable.
//
// The caller reports both lists: a folder nobody looked into must never
// read as "nothing found".
//////////////
class TreeWalk implements \IteratorAggregate
{
    // Folders that could not be listed.
    public $unreadable = array();
    // Link path => the folder it points to, for links left alone because
    // $follow is off.
    public $refused = array();

    private $roots;
    private $follow;
    private $covered = array();

    public function __construct($roots, $follow = true, array $covered = array())
    {
        $this->roots = (array) $roots;
        $this->follow = (bool) $follow;
        foreach (array_merge($this->roots, $covered) as $dir) {
            $real = self::real($dir);
            if (null !== $real) {
                $this->covered[] = $real;
            }
        }
    }

    public static function real($path)
    {
        $real = @realpath($path);
        if (false === $real) {
            return (null);
        }
        $real = rtrim(str_replace('\\', '/', $real), '/');
        return ('' === $real ? '/' : $real);
    }

    // True when $path is $dir or lies inside it (both already real()).
    public static function within($path, $dir)
    {
        return ($path === $dir || 0 === strpos($path, rtrim($dir, '/') . '/'));
    }

    ///////////////
    // The folder a link leads to when it is safe to go there from
    // $from_real (the real path of the folder holding the link), else null.
    //////////////
    public static function enterable($link, $from_real, array $covered, array $followed = array())
    {
        $target = self::real($link);
        if (null === $target || '/' === $target || !is_dir($target)) {
            return (null);
        }
        // A parent of where we are (or that very folder): a loop.
        if (self::within($from_real, $target)) {
            return (null);
        }
        foreach ($covered as $dir) {
            if (self::within($target, $dir)) {
                return (null);
            }
        }
        foreach ($followed as $dir => $unused) {
            if (self::within($target, $dir)) {
                return (null);
            }
        }
        return ($target);
    }

    #[\ReturnTypeWillChange]
    public function getIterator()
    {
        $followed = array();
        foreach ($this->roots as $root) {
            $root_real = self::real($root);
            $handle = (null === $root_real) ? false : @opendir($root);
            if (false === $handle) {
                $this->unreadable[] = $root;
                continue;
            }
            // Open folders, deepest last: handle, path as given, real path.
            $stack = array(array($handle, rtrim($root, '/'), $root_real));
            while (count($stack) > 0) {
                list($handle, $dir, $dir_real) = $stack[count($stack) - 1];
                $entry = readdir($handle);
                if (false === $entry) {
                    closedir($handle);
                    array_pop($stack);
                    continue;
                }
                if ('.' === $entry || '..' === $entry) {
                    continue;
                }
                $path = $dir . '/' . $entry;
                // lstat: says "link" for a link, whatever it points to.
                $type = @filetype($path);
                $next_real = null;
                if ('dir' === $type) {
                    $next_real = rtrim($dir_real, '/') . '/' . $entry;
                    if (isset($followed[$next_real])) {
                        // Already walked through a link that points here.
                        continue;
                    }
                } elseif ('link' === $type && is_dir($path)) {
                    $next_real = self::enterable($path, $dir_real, $this->covered, $followed);
                    if (null !== $next_real && !$this->follow) {
                        $this->refused[$path] = $next_real;
                        $next_real = null;
                    }
                    if (null === $next_real) {
                        continue;
                    }
                    $followed[$next_real] = true;
                }
                if (null === $next_real) {
                    yield new \SplFileInfo($path);
                    continue;
                }
                $child = @opendir($path);
                if (false === $child) {
                    $this->unreadable[] = $path;
                    continue;
                }
                $stack[] = array($child, $path, $next_real);
            }
        }
    }
}

///////////////
// The tool's own folder is never scanned (see under_plugin_dir). When the
// folder to scan is that folder or sits inside it - bin/ and includes/
// uploaded next to the site, say into /home/user with the site in
// /home/user/public_html - every file would be skipped as the tool's own
// and the scan would call the site clean without reading one file. That
// is refused, with the way out.
//////////////
function require_outside_tool(Context $ctx, $dir)
{
    if (null === $ctx->plugin_dir || '' === $ctx->plugin_dir) {
        return;
    }
    $real = TreeWalk::real($dir);
    if (null === $real || !TreeWalk::within($real, $ctx->plugin_dir)) {
        return;
    }
    throw new Fatal($dir . ' is inside the folder Elderward runs from (' . $ctx->plugin_dir
        . '), whose files are never scanned: nothing would be checked. Move Elderward (bin/ and includes/) into a folder of its own, for example '
        . $ctx->plugin_dir . '/elderward, and run it from there');
}

function under_plugin_dir(Context $ctx, $path)
{
    // Never scan (or correlate) the tool's own files: the signature strings
    // in the source would match themselves.
    if (null === $ctx->plugin_dir || '' === $ctx->plugin_dir) {
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

// $unreadable collects the folders that could not be listed (see TreeWalk);
// the caller reports them.
function list_files_recursive($dir, $base, array &$unreadable = array())
{
    $relative_paths = array();
    $walker = new TreeWalk($dir);
    $base_length = strlen(rtrim($base, '/')) + 1;
    foreach ($walker as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $relative_paths[] = str_replace('\\', '/', substr($file->getPathname(), $base_length));
    }
    foreach ($walker->unreadable as $folder) {
        $unreadable[] = $folder;
    }
    return $relative_paths;
}

function list_files_absolute($dir, array &$unreadable = array())
{
    $absolute_paths = array();
    foreach (list_files_recursive($dir, $dir, $unreadable) as $relative_path) {
        $absolute_paths[] = $dir . '/' . $relative_path;
    }
    return $absolute_paths;
}
