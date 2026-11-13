<?php
namespace Facheiro\Engine;

////////////////
// Self-check: verifies Facheiro's own files, which every other scanner
// skips (the signature strings in the source would match themselves).
//
// Reference, best first: the wordpress.org plugin checksums for this
// version (or plugin-facheiro-{version}.json in checksumdir=), else the
// checksums.json shipped with the plugin. The shipped list is only as
// trustworthy as the copy it came with: it catches mass injectors and
// dropped files, not an attacker who rewrites the list too, and the
// finding text says so.
//
// After the files, the stage runs the entry layer's preflight checks
// ($ctx->preflight), so checks that must run once per scan (the plugin's
// sealed settings) share this single-unit stage.
//
// Units: one per Facheiro copy (the running one, plus the copy installed
// in the scanned site when the standalone CLI runs from another folder),
// then one for the preflight checks.
//////////////

class SelfCheckScanner extends IntegrityScanner
{
    const SLUG = 'facheiro';
    const MANIFEST = 'checksums.json';

    // Top-level names that a release never contains (.distignore). A git
    // checkout has them: their tracked files are listed under "dev" in
    // checksums.json and verified when present; nothing is skipped.
    private static $dev_only = array(
        '.git', '.github', '.gitignore', '.gitattributes', '.distignore', '.wordpress-org', '.claude',
        'CLAUDE.md', 'TESTPLAN.md', 'composer.json', 'composer.lock', 'phpcs.xml.dist',
        'tests', 'vendor', 'node_modules', 'build', 'site', 'dist',
    );

    // Folders whose content no checksum list can cover: git's own data and
    // installed development dependencies. They are never silently skipped:
    // PHP inside .git is reported as an extra file, and a dependency folder
    // is reported as unverified.
    private static $unlisted = array('.git', 'vendor', 'node_modules');

    public function name()
    {
        return ('self');
    }

    public function init_state()
    {
        return array(
            'totals' => array('MODIFIED' => 0, 'MISSING' => 0, 'EXTRA' => 0, 'NO_REFERENCE' => 0, 'UNREADABLE' => 0),
            'reference' => array(),
        );
    }

    // The Facheiro copies to verify: the running one, and the one
    // installed in the scanned WordPress root if it is a different folder.
    public static function copies(Context $ctx)
    {
        $copies = array();
        if (null !== $ctx->plugin_dir && '' !== $ctx->plugin_dir && is_file($ctx->plugin_dir . '/facheiro.php')) {
            $copies[] = $ctx->plugin_dir;
        }
        // The copy installed in the scanned site, wherever its plugin folder is.
        $plugin_dirs = is_wordpress_root($ctx->root()) ? Layout::of($ctx)->plugin_dirs : array($ctx->root() . '/wp-content/plugins');
        foreach ($plugin_dirs as $plugins) {
            $installed = @realpath($plugins . '/' . self::SLUG);
            if (false !== $installed && is_file($installed . '/facheiro.php')) {
                $installed = rtrim(str_replace('\\', '/', $installed), '/');
                if (!in_array($installed, $copies, true)) {
                    $copies[] = $installed;
                }
            }
        }
        return ($copies);
    }

    public function plan(array &$state)
    {
        $units = array();
        foreach (self::copies($this->ctx) as $dir) {
            $units[] = array('copy' => $dir);
        }
        $units[] = array('preflight' => 1);
        return ($units);
    }

    public function run(array $unit, array &$state)
    {
        if (isset($unit['copy'])) {
            $state['reference'][$unit['copy']] = $this->check_copy($unit['copy'], $state['totals']);
        } elseif (isset($unit['preflight'])) {
            foreach ($this->ctx->preflight as $check) {
                call_user_func($check, $this->ctx->reporter);
            }
        }
        return (null);
    }

    public function finish(array &$state)
    {
        $totals = $state['totals'];
        $data = $totals;
        $data['reference'] = $state['reference'];
        $this->summary('self', $data,
            'Self-check complete: ' . $totals['MODIFIED'] . ' modified, ' . $totals['MISSING'] . ' missing, '
            . $totals['EXTRA'] . ' extra, ' . $totals['UNREADABLE'] . " unreadable\n");
    }

    // Returns which reference was used: wordpress.org, bundled, or none.
    private function check_copy($dir, array &$totals)
    {
        $version = self::read_plugin_version($dir);
        $name = 'Facheiro' . (null === $version ? '' : ' ' . $version);
        $present = array();
        $unlisted = array();
        foreach ($this->package_files($dir, $dir, $name, $totals) as $relative_path) {
            $top = strtok($relative_path, '/');
            if (in_array($top, self::$unlisted, true) && $top !== $relative_path) {
                $unlisted[$top][] = $relative_path;
                continue;
            }
            $present[] = $relative_path;
        }
        $this->report_unlisted($dir, $name, $unlisted, $totals);

        // The shipped list: release files, plus the development files of a
        // git checkout (only checked when they exist).
        $data = json_decode((string) @file_get_contents($dir . '/' . self::MANIFEST), true);
        $bundled = (is_array($data) && !empty($data['files']) && is_array($data['files'])) ? $data['files'] : null;
        $dev = (is_array($data) && isset($data['dev']) && is_array($data['dev'])) ? $data['dev'] : array();
        $present = array_values(array_diff($present, array(self::MANIFEST)));

        // 1. wordpress.org (or checksumdir=): the same lookup as any plugin.
        if (null !== $version) {
            list($status, $wporg) = $this->fetch_reference_checksums(
                'https://downloads.wordpress.org/plugin-checksums/' . self::SLUG . '/' . rawurlencode($version) . '.json',
                'plugin-' . self::SLUG . '-' . $version . '.json'
            );
            if ('ok' === $status && !empty($wporg['files']) && is_array($wporg['files'])) {
                $manifest = array();
                foreach ($wporg['files'] as $relative_path => $sums) {
                    $manifest[$relative_path] = isset($sums['md5']) ? $sums['md5'] : null;
                }
                // Development files of a git checkout are not in the release:
                // accepted only when they match the shipped list.
                $present = array_values(array_filter($present, function ($relative_path) use ($manifest, $dev, $dir) {
                    if (isset($manifest[$relative_path]) || !isset($dev[$relative_path]) || !is_string($dev[$relative_path])) {
                        return true;
                    }
                    $actual = @hash_file('sha256', $dir . '/' . $relative_path);
                    return !(false !== $actual && hash_equals(strtolower($dev[$relative_path]), $actual));
                }));
                if (null !== $bundled && !isset($manifest[self::MANIFEST])) {
                    $present[] = self::MANIFEST;
                    $manifest[self::MANIFEST] = md5_file($dir . '/' . self::MANIFEST);
                }
                $this->progress('Checking ' . $name . ' against wordpress.org (' . count($manifest) . " files)\n");
                $this->verify_against_manifest($dir, $manifest, $name, $present, $totals, 'md5', 'INFO');
                return ('wordpress.org');
            }
        }

        // 2. The list shipped with the plugin.
        if (null === $bundled) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $dir, $name . ': no checksum list to verify its own files against');
            $totals['NO_REFERENCE']++;
            return ('none');
        }
        $manifest = array();
        foreach ($bundled as $relative_path => $sha256) {
            $manifest[(string) $relative_path] = is_string($sha256) ? $sha256 : null;
        }
        foreach ($dev as $relative_path => $sha256) {
            // A missing development file is normal (a release has none).
            if (is_file($dir . '/' . $relative_path)) {
                $manifest[(string) $relative_path] = is_string($sha256) ? $sha256 : null;
            }
        }
        $label = $name . ' (its own checksum list; reinstall from wordpress.org to be sure)';
        $this->progress('Checking ' . $name . ' against its own checksum list (' . count($manifest) . " files)\n");
        $this->verify_against_manifest($dir, $manifest, $label, $present, $totals, 'sha256', 'INFO');
        return ('bundled');
    }

    private function report_unlisted($dir, $name, array $unlisted, array &$totals)
    {
        foreach ($unlisted as $top => $files) {
            if ('.git' === $top) {
                // Git never stores PHP files as such: one there is planted.
                foreach ($files as $relative_path) {
                    if (is_php_file($relative_path)) {
                        $this->report('HIGH', 'INTEGRITY_EXTRA', $dir . '/' . $relative_path, $name . ': PHP file inside the .git folder, which never holds one');
                        $totals['EXTRA']++;
                    }
                }
                continue;
            }
            $php = count(array_filter($files, __NAMESPACE__ . '\\is_php_file'));
            $this->report('MEDIUM', 'INTEGRITY_NO_REFERENCE', $dir . '/' . $top, $name . ': ' . $top . '/ holds ' . count($files) . ' files (' . $php
                . ' PHP) that no checksum list covers; a release has no such folder, so remove it from a live site');
            $totals['NO_REFERENCE']++;
        }
    }

    // The manifest format written by build/make-checksums.php, from the
    // given relative paths (git's tracked files): "files" is the release,
    // "dev" the development files a git checkout also has.
    public static function build_manifest($dir, $version, array $relative_paths)
    {
        $dir = rtrim($dir, '/');
        $files = array();
        $dev = array();
        foreach ($relative_paths as $relative_path) {
            $top = strtok($relative_path, '/');
            if (self::MANIFEST === $relative_path || !is_file($dir . '/' . $relative_path)
                || (in_array($top, self::$unlisted, true) && $top !== $relative_path)) {
                continue;
            }
            $hash = hash_file('sha256', $dir . '/' . $relative_path);
            if (in_array($top, self::$dev_only, true)) {
                $dev[$relative_path] = $hash;
            } else {
                $files[$relative_path] = $hash;
            }
        }
        ksort($files, SORT_STRING);
        ksort($dev, SORT_STRING);
        return array('plugin' => self::SLUG, 'version' => (string) $version, 'algorithm' => 'sha256', 'files' => $files, 'dev' => $dev);
    }

    public static function dev_only()
    {
        return (self::$dev_only);
    }
}
