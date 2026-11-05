<?php
namespace Elderward\Engine;

////////////////
// Where the content folder lives.
//
// Most sites keep plugins, themes and uploads in <root>/wp-content, but
// WP_CONTENT_DIR (and WP_PLUGIN_DIR) can move them anywhere, including
// outside the WordPress root (split-core and Bedrock-style layouts). A
// scanner that only looks at <root>/wp-content reports such a site clean
// for folders it never opened, so the layout is resolved once here and
// every scanner asks for it.
//
// Sources, most trusted first: the contentdir= / plugindir= options (set
// by the CLI user, or by the plugin and the recovery page from what
// WordPress itself resolved), then the defines in wp-config.php, parsed
// with a tiny grammar and never executed. wp-config.php is hostile data on
// a compromised host: a define that points at /, at the root itself or at
// one of its parents is refused, and <root>/wp-content is scanned too
// whenever it exists, so a define cannot steer the scan away from it.
//
// Anything that cannot be resolved is an ERROR finding (CONTENT_DIR_UNKNOWN)
// rather than a silent skip; a relocated folder that was found is an INFO
// finding (CONTENT_DIR) so the report says where it looked.
//////////////

// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- an exception message is data, not output: the entry layer that catches it (CLI, WP-CLI, admin page, recovery page) escapes it for the place it shows it.

final class Layout
{
    // Content folders to scan: the one WordPress loads first, then
    // <root>/wp-content when it is a different folder that also exists.
    public $content_dirs = array();
    // Plugin folders, in the same order.
    public $plugin_dirs = array();
    // Folders outside the root that a root-only walk would never reach.
    public $outside_root = array();
    // Findings describing the layout: array(severity, type, path, detail).
    public $notes = array();

    public static function of(Context $ctx)
    {
        if (null === $ctx->layout) {
            $ctx->layout = self::resolve($ctx);
        }
        return ($ctx->layout);
    }

    ///////////////
    // Report the layout findings. Inside scanall only the quick scan (the
    // first stage) reports them, so a scan says it once; a scanner run on
    // its own reports them itself.
    //////////////
    public static function report_notes(Context $ctx, $first_stage)
    {
        if ($ctx->has('scanall') && !$first_stage) {
            return;
        }
        foreach (self::of($ctx)->notes as $note) {
            $ctx->reporter->finding($note[0], $note[1], $note[2], $note[3]);
        }
    }

    // The primary content folder, or null when none was found.
    public function content_dir()
    {
        return (isset($this->content_dirs[0]) ? $this->content_dirs[0] : null);
    }

    public function plugin_dir()
    {
        return (isset($this->plugin_dirs[0]) ? $this->plugin_dirs[0] : null);
    }

    // True when $path is inside $sub (a folder name such as "uploads") of
    // any content folder.
    public function in_content_subdir($path, $sub)
    {
        foreach ($this->content_dirs as $dir) {
            if (0 === strpos($path, $dir . '/' . $sub . '/')) {
                return (true);
            }
        }
        return (false);
    }

    // True when a plugin folder named $slug exists in any plugin folder.
    public function has_plugin($slug)
    {
        foreach ($this->plugin_dirs as $dir) {
            if (is_dir($dir . '/' . $slug)) {
                return (true);
            }
        }
        return (false);
    }

    public function is_content_dir($path)
    {
        $real = self::real($path);
        foreach ($this->content_dirs as $dir) {
            if (null !== $real && self::real($dir) === $real) {
                return (true);
            }
        }
        return (false);
    }

    private static function resolve(Context $ctx)
    {
        $layout = new Layout();
        $root = $ctx->root();
        $default = $root . '/wp-content';
        $default_exists = is_dir($default);
        $config = self::read_config($root);

        $may_write = self::may_write($ctx);
        list($content, $content_source) = self::pick($ctx, 'contentdir', 'WP_CONTENT_DIR', $config, $root, $layout);
        $content = self::guard_write($content, $content_source, 'contentdir', $may_write, $root, $layout);
        if (null === $content) {
            if ($default_exists) {
                $content = $default;
            } elseif (empty($layout->notes)) {
                $layout->notes[] = array('ERROR', 'CONTENT_DIR_UNKNOWN', $root,
                    'no wp-content folder under the root and WP_CONTENT_DIR is not set in wp-config.php - plugins, themes, uploads and mu-plugins were NOT checked; pass contentdir=/path');
            }
        }
        if (null !== $content) {
            $layout->content_dirs[] = $content;
            if (self::real($content) !== self::real($default)) {
                $detail = 'content folder is ' . self::shown($content) . ' (' . $content_source . ')';
                if ($default_exists) {
                    $layout->content_dirs[] = $default;
                    $detail .= '; ' . $default . ' exists too and is also scanned - WordPress does not load it, so it is a leftover copy or a decoy';
                }
                $layout->notes[] = array('INFO', 'CONTENT_DIR', self::shown($content), $detail);
            }
        }

        list($plugins, $plugins_source) = self::pick($ctx, 'plugindir', 'WP_PLUGIN_DIR', $config, $root, $layout);
        $plugins = self::guard_write($plugins, $plugins_source, 'plugindir', $may_write, $root, $layout);
        if (null !== $plugins) {
            $layout->plugin_dirs[] = $plugins;
            if (null === $content || self::real($plugins) !== self::real($content . '/plugins')) {
                $layout->notes[] = array('INFO', 'CONTENT_DIR', self::shown($plugins), 'plugin folder is ' . self::shown($plugins) . ' (' . $plugins_source . ')');
            }
        }
        foreach ($layout->content_dirs as $dir) {
            if (is_dir($dir . '/plugins')) {
                $layout->plugin_dirs[] = $dir . '/plugins';
            }
        }
        $layout->content_dirs = self::unique(self::respell($layout->content_dirs, $root));
        $layout->plugin_dirs = self::unique(self::respell($layout->plugin_dirs, $root));

        foreach (array_merge($layout->content_dirs, $layout->plugin_dirs) as $dir) {
            if (!self::inside($dir, $root)) {
                $layout->outside_root[] = $dir;
            }
        }
        $layout->outside_root = self::unique($layout->outside_root);
        // A plugin folder inside an outside content folder is walked with it.
        $kept = array();
        foreach ($layout->outside_root as $dir) {
            $nested = false;
            foreach ($layout->outside_root as $other) {
                if ($other !== $dir && self::inside($dir, $other)) {
                    $nested = true;
                }
            }
            if (!$nested) {
                $kept[] = $dir;
            }
        }
        $layout->outside_root = $kept;
        return ($layout);
    }

    ///////////////
    // A run that may change files (signature cleanup without dryrun, or
    // restore) never follows a wp-config.php define out of the root: the
    // file is attacker-writable, and the operator may run the cleanup with
    // more privileges than the web user. Only an option the operator (or
    // WordPress itself, through the plugin) gave can take it there.
    //////////////
    public static function may_write(Context $ctx)
    {
        if ($ctx->has('dryrun')) {
            return (false);
        }
        if ($ctx->has('restore')) {
            return (true);
        }
        foreach (explode(',', Runner::MODES) as $mode) {
            if ($ctx->has($mode)) {
                return (false);
            }
        }
        // No mode: the signature scan, which cleans by default.
        return (true);
    }

    private static function guard_write($path, $source, $option, $may_write, $root, Layout $layout)
    {
        if (null === $path || !$may_write || $option . '=' === $source || self::inside($path, $root)) {
            return ($path);
        }
        $shown = self::shown($path);
        $layout->notes[] = array('ERROR', 'CONTENT_DIR_UNKNOWN', $shown,
            $source . ' points outside the WordPress root to ' . $shown . ' - cleanup and restore do not follow a wp-config.php define out of the root, so that folder was NOT checked; pass '
            . $option . '=' . $shown . ' to confirm it, or add dryrun=1 to only report');
        return (null);
    }

    ///////////////
    // One folder from the option or the wp-config define. Returns
    // array(path or null, where it came from); problems become notes.
    //////////////
    private static function pick(Context $ctx, $option, $constant, $config, $root, Layout $layout)
    {
        if ($ctx->has($option)) {
            $path = rtrim(str_replace('\\', '/', (string) $ctx->get($option)), '/');
            if ('' === $path || !is_dir($path)) {
                throw new Fatal($option . '=' . $path . ' is not a directory');
            }
            $refused = self::refuse($path, $root);
            if (null !== $refused) {
                throw new Fatal($option . '=' . $path . ' ' . $refused);
            }
            return (array($path, $option . '='));
        }
        if (null === $config) {
            return (array(null, null));
        }
        $expression = self::define_expression($config['content'], $constant);
        if (null === $expression) {
            return (array(null, null));
        }
        $path = self::evaluate($expression, $root, dirname($config['path']));
        $where = $constant . ' in ' . $config['path'];
        if (null === $path) {
            $layout->notes[] = array('ERROR', 'CONTENT_DIR_UNKNOWN', $config['path'],
                $constant . ' is set to an expression Elderward cannot evaluate without running wp-config.php: ' . substr($expression, 0, 200)
                . ' - that folder was NOT checked; pass ' . $option . '=/path');
            return (array(null, null));
        }
        if (!is_dir($path)) {
            $layout->notes[] = array('ERROR', 'CONTENT_DIR_UNKNOWN', $config['path'],
                $constant . ' points to ' . $path . ', which is not a readable directory - that folder was NOT checked; pass ' . $option . '=/path');
            return (array(null, null));
        }
        $refused = self::refuse($path, $root);
        if (null !== $refused) {
            $layout->notes[] = array('ERROR', 'CONTENT_DIR_UNKNOWN', $config['path'],
                $constant . ' points to ' . self::shown($path) . ', which ' . $refused . ' - refused (a tampered wp-config.php can point the scan anywhere); pass ' . $option . '=/path');
            return (array(null, null));
        }
        return (array($path, $where));
    }

    // Why a folder cannot be the content folder, or null when it can.
    private static function refuse($path, $root)
    {
        $real = self::real($path);
        $root_real = self::real($root);
        if (null === $real || '/' === $real) {
            return ('is the filesystem root');
        }
        if (null !== $root_real && ($real === $root_real || self::inside($root_real, $real))) {
            return ('is the WordPress root or one of its parents');
        }
        return (null);
    }

    private static function read_config($root)
    {
        // Same places WordPress looks: the root, or the folder above it.
        foreach (array($root . '/wp-config.php', dirname($root) . '/wp-config.php') as $candidate) {
            if (!is_file($candidate)) {
                continue;
            }
            // A real config is a few KB; never slurp an unbounded file.
            $content = @file_get_contents($candidate, false, null, 0, 65536);
            if (false === $content) {
                return (null);
            }
            // Drop comment lines, as the database credentials parser does.
            $content = preg_replace('@^[ \t]*(?://|#|/?\*).*$@m', '', $content);
            return (array('path' => $candidate, 'content' => (string) $content));
        }
        return (null);
    }

    // The raw value expression of the first define() of $constant, or null.
    private static function define_expression($content, $constant)
    {
        if (preg_match('/define\s*\(\s*[\'"]' . $constant . '[\'"]\s*,\s*(.*?)\s*\)\s*;/s', $content, $matches) !== 1) {
            return (null);
        }
        return ($matches[1]);
    }

    ///////////////
    // The value grammar: a plain absolute string literal, or __DIR__,
    // dirname(__FILE__) or ABSPATH followed by . and a string literal.
    // Anything else (variables, function calls, env lookups) needs PHP to
    // run, which the scanner never does with a hostile file.
    //////////////
    private static function evaluate($expression, $root, $config_dir)
    {
        $literal = '(?:\'((?:[^\'\\\\]|\\\\.)*)\'|"((?:[^"\\\\$]|\\\\.)*)")';
        if (preg_match('/^' . $literal . '$/s', $expression, $m) === 1) {
            $value = self::literal_value($m);
            return ('/' === substr($value, 0, 1) ? self::normalize($value) : null);
        }
        if (preg_match('/^(__DIR__|dirname\s*\(\s*__FILE__\s*\)|ABSPATH)\s*\.\s*' . $literal . '$/s', $expression, $m) === 1) {
            $base = ('ABSPATH' === $m[1]) ? $root . '/' : $config_dir;
            $value = self::literal_value(array($m[0], isset($m[2]) ? $m[2] : '', isset($m[3]) ? $m[3] : ''));
            return (self::normalize($base . $value));
        }
        return (null);
    }

    private static function literal_value(array $m)
    {
        if (isset($m[2]) && '' !== $m[2]) {
            return (MysqliDb::decode_php_string_literal('"', $m[2]));
        }
        return (MysqliDb::decode_php_string_literal("'", isset($m[1]) ? $m[1] : ''));
    }

    // Collapse duplicate slashes and "." segments; ".." is resolved by
    // realpath() where it matters (refuse/inside), never by string work.
    private static function normalize($path)
    {
        $path = preg_replace('@/+@', '/', str_replace('\\', '/', $path));
        $path = preg_replace('@/(?:\./)+@', '/', $path);
        $path = rtrim($path, '/');
        return ('' === $path) ? '/' : $path;
    }

    private static function shown($path)
    {
        $real = self::real($path);
        return (null === $real) ? $path : $real;
    }

    private static function real($path)
    {
        $real = @realpath($path);
        if (false === $real) {
            return (null);
        }
        $real = rtrim(str_replace('\\', '/', $real), '/');
        return ('' === $real) ? '/' : $real;
    }

    // True when $path is $dir or inside it (symlinks resolved).
    private static function inside($path, $dir)
    {
        $real = self::real($path);
        $dir_real = self::real($dir);
        if (null === $real || null === $dir_real) {
            return (false);
        }
        return ($real === $dir_real || 0 === strpos($real . '/', $dir_real . '/'));
    }

    ///////////////
    // Folders inside the root are spelled from the root, the way the root
    // walk spells the paths it finds, so prefix checks on walked paths work
    // even when the option or define named the folder through a symlink.
    // A folder outside the root (including a <root>/wp-content symlinked
    // out of it, which the root walk does not follow) is walked and shown
    // by its real path.
    //////////////
    private static function respell(array $dirs, $root)
    {
        $root_real = self::real($root);
        $spelled = array();
        foreach ($dirs as $dir) {
            $real = self::real($dir);
            if (null !== $root_real && null !== $real && 0 === strpos($real . '/', $root_real . '/') && $real !== $root_real) {
                $dir = $root . substr($real, strlen($root_real));
            } elseif (null !== $real) {
                // Outside the root nothing else spells it: show the real path.
                $dir = $real;
            }
            $spelled[] = $dir;
        }
        return ($spelled);
    }

    // Drop folders that resolve to the same place, keeping the first spelling.
    private static function unique(array $dirs)
    {
        $seen = array();
        $kept = array();
        foreach ($dirs as $dir) {
            $key = self::real($dir);
            if (null === $key) {
                $key = $dir;
            }
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $kept[] = $dir;
            }
        }
        return ($kept);
    }
}
