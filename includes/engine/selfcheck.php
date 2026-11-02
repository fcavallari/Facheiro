<?php
namespace Elderward\Engine;

////////////////
// Self-check: verifies Elderward's own files, which every other scanner
// skips (the signature strings in the source would match themselves).
//
// Reference, best first: the wordpress.org plugin checksums for this
// version (or plugin-elderward-{version}.json in checksumdir=), else the
// checksums.json shipped with the plugin. The shipped list is only as
// trustworthy as the copy it came with: it catches mass injectors and
// dropped files, not an attacker who rewrites the list too, and the
// finding text says so.
//
// After the files, the stage runs the entry layer's preflight checks
// ($ctx->preflight), so checks that must run once per scan (the plugin's
// sealed settings) share this single-unit stage.
//
// Units: one per Elderward copy (the running one, plus the copy installed
// in the scanned site when the standalone CLI runs from another folder),
// then one for the preflight checks.
//////////////

class SelfCheckScanner extends IntegrityScanner
{
    const SLUG = 'elderward';
    const MANIFEST = 'checksums.json';

    // Top-level names that a release never contains (.distignore); a git
    // checkout has them, so a development copy skips them instead of
    // reporting thousands of extra files.
    private static $dev_only = array(
        '.git', '.github', '.gitignore', '.distignore', '.wordpress-org', '.claude',
        'CLAUDE.md', 'TESTPLAN.md', 'composer.json', 'composer.lock', 'phpcs.xml.dist',
        'tests', 'vendor', 'node_modules', 'build', 'site', 'dist',
    );

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

    // The Elderward copies to verify: the running one, and the one
    // installed in the scanned WordPress root if it is a different folder.
    public static function copies(Context $ctx)
    {
        $copies = array();
        if (null !== $ctx->plugin_dir && '' !== $ctx->plugin_dir && is_file($ctx->plugin_dir . '/elderward.php')) {
            $copies[] = $ctx->plugin_dir;
        }
        $installed = @realpath($ctx->root() . '/wp-content/plugins/' . self::SLUG);
        if (false !== $installed && is_file($installed . '/elderward.php')) {
            $installed = rtrim(str_replace('\\', '/', $installed), '/');
            if (!in_array($installed, $copies, true)) {
                $copies[] = $installed;
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
        $dev = is_dir($dir . '/.git');
        $present = array();
        foreach (list_files_recursive($dir, $dir) as $relative_path) {
            $top = strtok($relative_path, '/');
            if ($dev && in_array($top, self::$dev_only, true)) {
                continue;
            }
            $present[] = $relative_path;
        }

        // 1. wordpress.org (or checksumdir=): the same lookup as any plugin.
        if (null !== $version) {
            list($status, $data) = $this->fetch_reference_checksums(
                'https://downloads.wordpress.org/plugin-checksums/' . self::SLUG . '/' . rawurlencode($version) . '.json',
                'plugin-' . self::SLUG . '-' . $version . '.json'
            );
            if ('ok' === $status && !empty($data['files']) && is_array($data['files'])) {
                $manifest = array();
                foreach ($data['files'] as $relative_path => $sums) {
                    $manifest[$relative_path] = isset($sums['md5']) ? $sums['md5'] : null;
                }
                $this->progress('Checking Elderward ' . $version . ' against wordpress.org (' . count($manifest) . " files)\n");
                $this->verify_against_manifest($dir, $manifest, 'Elderward ' . $version, $present, $totals, 'md5', 'INFO');
                return ('wordpress.org');
            }
        }

        // 2. The list shipped with the plugin.
        $raw = @file_get_contents($dir . '/' . self::MANIFEST);
        $data = (false === $raw) ? null : json_decode($raw, true);
        if (!is_array($data) || empty($data['files']) || !is_array($data['files'])) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $dir, 'Elderward' . (null === $version ? '' : ' ' . $version)
                . ': no checksum list to verify its own files against' . ($dev ? ' (development copy)' : ''));
            $totals['NO_REFERENCE']++;
            return ('none');
        }
        $manifest = array();
        foreach ($data['files'] as $relative_path => $sha256) {
            $manifest[(string) $relative_path] = is_string($sha256) ? $sha256 : null;
        }
        $present = array_values(array_diff($present, array(self::MANIFEST)));
        $label = 'Elderward' . (null === $version ? '' : ' ' . $version) . ' (its own checksum list; reinstall from wordpress.org to be sure)';
        $this->progress('Checking Elderward' . (null === $version ? '' : ' ' . $version) . ' against its own checksum list (' . count($manifest) . " files)\n");
        $this->verify_against_manifest($dir, $manifest, $label, $present, $totals, 'sha256', 'INFO');
        return ('bundled');
    }

    // The manifest format written by build/make-checksums.php, from the
    // given relative paths (the release's files).
    public static function build_manifest($dir, $version, array $relative_paths)
    {
        $dir = rtrim($dir, '/');
        $files = array();
        foreach ($relative_paths as $relative_path) {
            $top = strtok($relative_path, '/');
            if (in_array($top, self::$dev_only, true) || self::MANIFEST === $relative_path || !is_file($dir . '/' . $relative_path)) {
                continue;
            }
            $files[$relative_path] = hash_file('sha256', $dir . '/' . $relative_path);
        }
        ksort($files, SORT_STRING);
        return array('plugin' => self::SLUG, 'version' => (string) $version, 'algorithm' => 'sha256', 'files' => $files);
    }

    public static function dev_only()
    {
        return (self::$dev_only);
    }
}
