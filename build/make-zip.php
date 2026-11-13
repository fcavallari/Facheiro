<?php
////////////////
// Builds the release zip, dist/facheiro.zip: exactly the files listed
// under "files" in checksums.json plus checksums.json itself, inside an
// facheiro/ folder, each one checked against its listed SHA-256 as it is
// added. This is the package to upload to WordPress.org, to install on a
// test site and to run Plugin Check on.
//
//   php build/make-zip.php
//
// A git checkout is not a release: it also holds tests/, build/, .claude/
// and the like (see .distignore), which Plugin Check reports as
// application files, hidden files, unexpected Markdown and unguarded PHP.
// Refuses when checksums.json is out of date, when a listed file is
// missing or differs from its checksum, or when ZipArchive is missing.
//////////////

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$facheiro_root = dirname(__DIR__);
$facheiro_manifest_name = 'checksums.json';
$facheiro_target = $facheiro_root . '/dist/facheiro.zip';

function facheiro_zip_fail($message)
{
    fwrite(STDERR, 'make-zip: ' . $message . "\n");
    exit(1);
}

if (!class_exists('ZipArchive')) {
    facheiro_zip_fail('the zip extension (ZipArchive) is not available in this PHP');
}

// The manifest must describe the files as they are now, or the zip would
// ship a checksums.json the self-check then fails against.
$facheiro_check = array();
$facheiro_code = 1;
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/make-checksums.php') . ' --check 2>&1', $facheiro_check, $facheiro_code);
if (0 !== $facheiro_code) {
    facheiro_zip_fail(implode("\n", $facheiro_check));
}

$facheiro_manifest = json_decode((string) @file_get_contents($facheiro_root . '/' . $facheiro_manifest_name), true);
if (!is_array($facheiro_manifest) || !isset($facheiro_manifest['files']) || !is_array($facheiro_manifest['files'])
    || count($facheiro_manifest['files']) === 0) {
    facheiro_zip_fail($facheiro_manifest_name . ' has no "files" list');
}

if (!is_dir(dirname($facheiro_target)) && !@mkdir(dirname($facheiro_target), 0755, true)) {
    facheiro_zip_fail('cannot create ' . dirname($facheiro_target));
}
$facheiro_tmp = $facheiro_target . '.tmp';
@unlink($facheiro_tmp);
$facheiro_zip = new ZipArchive();
if (true !== $facheiro_zip->open($facheiro_tmp, ZipArchive::CREATE | ZipArchive::EXCL)) {
    facheiro_zip_fail('cannot create ' . $facheiro_tmp);
}

$facheiro_count = 0;
foreach ($facheiro_manifest['files'] as $facheiro_path => $facheiro_hash) {
    $facheiro_path = (string) $facheiro_path;
    // A release never holds a hidden file or a path that climbs out.
    if (1 === preg_match('@(?:^|/)\.@', $facheiro_path) || '' === $facheiro_path || '/' === $facheiro_path[0]) {
        $facheiro_zip->close();
        @unlink($facheiro_tmp);
        facheiro_zip_fail('refusing to package ' . $facheiro_path . ': a release holds no hidden or absolute path');
    }
    $facheiro_file = $facheiro_root . '/' . $facheiro_path;
    if (!is_file($facheiro_file) || hash_file('sha256', $facheiro_file) !== $facheiro_hash) {
        $facheiro_zip->close();
        @unlink($facheiro_tmp);
        facheiro_zip_fail($facheiro_path . ' is missing or differs from ' . $facheiro_manifest_name);
    }
    $facheiro_zip->addFile($facheiro_file, 'facheiro/' . $facheiro_path);
    $facheiro_count++;
}
$facheiro_zip->addFile($facheiro_root . '/' . $facheiro_manifest_name, 'facheiro/' . $facheiro_manifest_name);
if (true !== $facheiro_zip->close()) {
    @unlink($facheiro_tmp);
    facheiro_zip_fail('cannot write ' . $facheiro_tmp);
}
if (!@rename($facheiro_tmp, $facheiro_target)) {
    @unlink($facheiro_tmp);
    facheiro_zip_fail('cannot move the zip to ' . $facheiro_target);
}

echo 'Wrote dist/facheiro.zip: Facheiro ' . $facheiro_manifest['version'] . ', ' . ($facheiro_count + 1) . " files\n";
