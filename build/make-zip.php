<?php
////////////////
// Builds the release zip, dist/elderward.zip: exactly the files listed
// under "files" in checksums.json plus checksums.json itself, inside an
// elderward/ folder, each one checked against its listed SHA-256 as it is
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

$elderward_root = dirname(__DIR__);
$elderward_manifest_name = 'checksums.json';
$elderward_target = $elderward_root . '/dist/elderward.zip';

function elderward_zip_fail($message)
{
    fwrite(STDERR, 'make-zip: ' . $message . "\n");
    exit(1);
}

if (!class_exists('ZipArchive')) {
    elderward_zip_fail('the zip extension (ZipArchive) is not available in this PHP');
}

// The manifest must describe the files as they are now, or the zip would
// ship a checksums.json the self-check then fails against.
$elderward_check = array();
$elderward_code = 1;
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/make-checksums.php') . ' --check 2>&1', $elderward_check, $elderward_code);
if (0 !== $elderward_code) {
    elderward_zip_fail(implode("\n", $elderward_check));
}

$elderward_manifest = json_decode((string) @file_get_contents($elderward_root . '/' . $elderward_manifest_name), true);
if (!is_array($elderward_manifest) || !isset($elderward_manifest['files']) || !is_array($elderward_manifest['files'])
    || count($elderward_manifest['files']) === 0) {
    elderward_zip_fail($elderward_manifest_name . ' has no "files" list');
}

if (!is_dir(dirname($elderward_target)) && !@mkdir(dirname($elderward_target), 0755, true)) {
    elderward_zip_fail('cannot create ' . dirname($elderward_target));
}
$elderward_tmp = $elderward_target . '.tmp';
@unlink($elderward_tmp);
$elderward_zip = new ZipArchive();
if (true !== $elderward_zip->open($elderward_tmp, ZipArchive::CREATE | ZipArchive::EXCL)) {
    elderward_zip_fail('cannot create ' . $elderward_tmp);
}

$elderward_count = 0;
foreach ($elderward_manifest['files'] as $elderward_path => $elderward_hash) {
    $elderward_path = (string) $elderward_path;
    // A release never holds a hidden file or a path that climbs out.
    if (1 === preg_match('@(?:^|/)\.@', $elderward_path) || '' === $elderward_path || '/' === $elderward_path[0]) {
        $elderward_zip->close();
        @unlink($elderward_tmp);
        elderward_zip_fail('refusing to package ' . $elderward_path . ': a release holds no hidden or absolute path');
    }
    $elderward_file = $elderward_root . '/' . $elderward_path;
    if (!is_file($elderward_file) || hash_file('sha256', $elderward_file) !== $elderward_hash) {
        $elderward_zip->close();
        @unlink($elderward_tmp);
        elderward_zip_fail($elderward_path . ' is missing or differs from ' . $elderward_manifest_name);
    }
    $elderward_zip->addFile($elderward_file, 'elderward/' . $elderward_path);
    $elderward_count++;
}
$elderward_zip->addFile($elderward_root . '/' . $elderward_manifest_name, 'elderward/' . $elderward_manifest_name);
if (true !== $elderward_zip->close()) {
    @unlink($elderward_tmp);
    elderward_zip_fail('cannot write ' . $elderward_tmp);
}
if (!@rename($elderward_tmp, $elderward_target)) {
    @unlink($elderward_tmp);
    elderward_zip_fail('cannot move the zip to ' . $elderward_target);
}

echo 'Wrote dist/elderward.zip: Elderward ' . $elderward_manifest['version'] . ', ' . ($elderward_count + 1) . " files\n";
