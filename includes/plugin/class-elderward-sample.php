<?php
/**
 * Package a flagged file for manual submission to a malware analyst or
 * sandbox.
 *
 * Nothing is uploaded from the site: a compromised host must not decide on
 * its own what leaves it, and wp-config.php or customer data must never go
 * anywhere by accident. The administrator downloads a zip, encrypted with
 * the conventional sample password "infected" so antivirus on their own
 * machine does not quarantine it in transit, and submits it themselves.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Sample
{
    const PASSWORD = 'infected';
    const MAX_BYTES = 10485760;

    /**
     * Whether this PHP can write password-protected (AES-256) zips.
     */
    public static function can_encrypt()
    {
        return class_exists('ZipArchive') && method_exists('ZipArchive', 'setEncryptionName') && defined('ZipArchive::EM_AES_256');
    }

    /**
     * The real path of a finding's file if it may be packaged: a regular
     * file inside the WordPress root, not wp-config*, not too large.
     *
     * @return string|WP_Error
     */
    public static function resolve($finding)
    {
        if (!Elderward_False_Positives::is_file_type($finding->type)) {
            return new WP_Error('elderward_sample_type', __('This finding is not about a file.', 'elderward'));
        }
        $real = realpath((string) $finding->path);
        $root = realpath(ABSPATH);
        if (false === $real || false === $root || !@is_file($real) || !@is_readable($real)) {
            return new WP_Error('elderward_sample_missing', __('The file no longer exists or is not readable by PHP.', 'elderward'));
        }
        // realpath() resolves symlinks, so a link pointing outside the
        // WordPress root is refused here too.
        if (0 !== strpos($real, untrailingslashit($root) . '/')) {
            return new WP_Error('elderward_sample_outside', __('Only files inside the WordPress folder can be downloaded.', 'elderward'));
        }
        if (preg_match('/^wp-config/i', basename($real))) {
            return new WP_Error('elderward_sample_config', __('wp-config.php holds the database password and secret keys, so Elderward never packages it. Review it on the server instead.', 'elderward'));
        }
        $size = @filesize($real);
        if (false === $size || $size > self::MAX_BYTES) {
            return new WP_Error('elderward_sample_size', __('The file is larger than 10 MB; copy it off the server by hand.', 'elderward'));
        }
        return $real;
    }

    /**
     * Build the zip in a temporary file.
     *
     * @return string|WP_Error Path of the zip (caller deletes it).
     */
    public static function build($finding)
    {
        if (!class_exists('ZipArchive')) {
            return new WP_Error('elderward_sample_zip', __('The PHP zip extension is not available, so the sample cannot be packaged. Its SHA-256 is shown on the findings page.', 'elderward'));
        }
        $real = self::resolve($finding);
        if (is_wp_error($real)) {
            return $real;
        }
        $sha256 = hash_file('sha256', $real);
        if (false === $sha256) {
            return new WP_Error('elderward_sample_read', __('The file could not be read.', 'elderward'));
        }
        $root = untrailingslashit(realpath(ABSPATH));
        $encrypted = self::can_encrypt();
        // Named by hash so nothing in the zip runs or renders by
        // double-click; the original name is in the manifest.
        $entry = $sha256 . '.sample';
        $manifest = array(
            'generator'        => 'Elderward ' . ELDERWARD_VERSION,
            'created'          => gmdate('c'),
            'file'             => $entry,
            'original_path'    => Elderward_Plugin::relative_path($real, $root),
            'size'             => (int) @filesize($real),
            'mtime'            => gmdate('c', (int) @filemtime($real)),
            'sha256'           => $sha256,
            'sha256_at_scan'   => (null === $finding->sha256 || '' === $finding->sha256) ? null : $finding->sha256,
            'changed_since_scan' => (null !== $finding->sha256 && '' !== $finding->sha256 && $finding->sha256 !== $sha256),
            'finding'          => array(
                'severity' => (string) $finding->severity,
                'type'     => (string) $finding->type,
                'detail'   => (string) $finding->detail,
            ),
            'encrypted'        => $encrypted,
            'password'         => $encrypted ? self::PASSWORD : null,
        );

        $tmp = wp_tempnam('elderward-sample');
        $zip = new ZipArchive();
        if (true !== $zip->open($tmp, ZipArchive::OVERWRITE)) {
            @unlink($tmp); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- our own temporary file.
            return new WP_Error('elderward_sample_zip', __('Could not create the zip file.', 'elderward'));
        }
        $ok = $zip->addFile($real, $entry);
        if ($ok && $encrypted) {
            $ok = $zip->setEncryptionName($entry, ZipArchive::EM_AES_256, self::PASSWORD);
        }
        $ok = $ok && $zip->addFromString('manifest.json', wp_json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        $ok = $ok && $zip->addFromString('README.txt', self::readme($encrypted));
        $ok = $zip->close() && $ok;
        if (!$ok) {
            @unlink($tmp); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- our own temporary file.
            return new WP_Error('elderward_sample_zip', __('Could not write the zip file.', 'elderward'));
        }
        return $tmp;
    }

    private static function readme($encrypted)
    {
        $text = "Elderward sample package\n"
            . "========================\n\n"
            . "This zip holds one file flagged by Elderward, named by its SHA-256,\n"
            . "and manifest.json with where it was found and why it was flagged.\n\n";
        if ($encrypted) {
            $text .= "The sample is encrypted (AES-256) with the password: " . self::PASSWORD . "\n"
                . "Most sandboxes and analysts accept this convention as is. Use 7-Zip\n"
                . "or another AES-capable tool to open it; plain 'unzip' cannot.\n\n";
        } else {
            $text .= "WARNING: this PHP cannot write encrypted zips, so the sample is NOT\n"
                . "password-protected. Your antivirus may quarantine the download.\n\n";
        }
        $text .= "Treat the file as live malware: do not open it on a production\n"
            . "machine or upload it to a web server.\n";
        return $text;
    }
}
