<?php
////////////////
// Writes checksums.json: the SHA-256 of every file a release ships, which
// the self-check verifies Elderward's own files against when wordpress.org
// has no checksums for this version.
//
//   php build/make-checksums.php           write checksums.json
//   php build/make-checksums.php --check   exit 1 if it is out of date
//
// Run it after changing any tracked file. The file list comes from git
// (tracked and new, not ignored files): what .distignore leaves out of a
// release goes under "dev", checked only in a git checkout.
//////////////

if (PHP_SAPI !== 'cli') {
    exit(1);
}

require_once dirname(__DIR__) . '/includes/engine/load.php';

use Elderward\Engine\IntegrityScanner;
use Elderward\Engine\SelfCheckScanner;

$root = dirname(__DIR__);
$check = in_array('--check', array_slice($argv, 1), true);

// .distignore and the self-check's development-only list must agree, or a
// development copy would skip (or report) the wrong files.
$distignore = array_values(array_filter(array_map('trim', (array) @file($root . '/.distignore'))));
$missing = array_diff($distignore, SelfCheckScanner::dev_only());
if (count($missing) > 0) {
    fwrite(STDERR, "SelfCheckScanner::\$dev_only lacks .distignore entries: " . implode(', ', $missing) . "\n");
    exit(1);
}

$out = array();
$code = 1;
exec('git -C ' . escapeshellarg($root) . ' ls-files -z --cached --others --exclude-standard 2>/dev/null', $out, $code);
if (0 !== $code) {
    fwrite(STDERR, "git ls-files failed: run this from a git checkout\n");
    exit(1);
}
$paths = array_values(array_filter(explode("\0", implode("\n", $out)), 'strlen'));

$manifest = SelfCheckScanner::build_manifest($root, IntegrityScanner::read_plugin_version($root), $paths);
$json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
$target = $root . '/' . SelfCheckScanner::MANIFEST;

if ($check) {
    if ((string) @file_get_contents($target) !== $json) {
        fwrite(STDERR, SelfCheckScanner::MANIFEST . " is out of date: run php build/make-checksums.php\n");
        exit(1);
    }
    echo SelfCheckScanner::MANIFEST . ' is up to date (' . count($manifest['files']) . ' release files, ' . count($manifest['dev']) . " development files)\n";
    exit(0);
}
file_put_contents($target, $json);
echo 'Wrote ' . SelfCheckScanner::MANIFEST . ' (' . count($manifest['files']) . ' release files, ' . count($manifest['dev']) . " development files)\n";
