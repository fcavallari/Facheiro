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
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Facheiro_Sample
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
        if (!Facheiro_False_Positives::is_file_type($finding->type)) {
            return new WP_Error('facheiro_sample_type', __('Este achado não é sobre um arquivo.', 'facheiro'));
        }
        $real = realpath((string) $finding->path);
        $root = realpath(ABSPATH);
        if (false === $real || false === $root || !@is_file($real) || !@is_readable($real)) {
            return new WP_Error('facheiro_sample_missing', __('O arquivo não existe mais ou o PHP não consegue lê-lo.', 'facheiro'));
        }
        // realpath() resolves symlinks, so a link pointing outside the
        // WordPress root is refused here too.
        if (0 !== strpos($real, untrailingslashit($root) . '/')) {
            return new WP_Error('facheiro_sample_outside', __('Só arquivos dentro da pasta do WordPress podem ser baixados.', 'facheiro'));
        }
        if (preg_match('/^wp-config/i', basename($real))) {
            return new WP_Error('facheiro_sample_config', __('O wp-config.php guarda a senha do banco de dados e as chaves secretas, então o Facheiro nunca o empacota. Revise-o direto no servidor.', 'facheiro'));
        }
        $size = @filesize($real);
        if (false === $size || $size > self::MAX_BYTES) {
            return new WP_Error('facheiro_sample_size', __('O arquivo tem mais de 10 MB; copie-o do servidor à mão.', 'facheiro'));
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
            return new WP_Error('facheiro_sample_zip', __('A extensão zip do PHP não está disponível, então a amostra não pode ser empacotada. O SHA-256 dela aparece na página de achados.', 'facheiro'));
        }
        $real = self::resolve($finding);
        if (is_wp_error($real)) {
            return $real;
        }
        $sha256 = hash_file('sha256', $real);
        if (false === $sha256) {
            return new WP_Error('facheiro_sample_read', __('Não foi possível ler o arquivo.', 'facheiro'));
        }
        $root = untrailingslashit(realpath(ABSPATH));
        $encrypted = self::can_encrypt();
        // Named by hash so nothing in the zip runs or renders by
        // double-click; the original name is in the manifest.
        $entry = $sha256 . '.sample';
        $manifest = array(
            'generator'        => 'Facheiro ' . FACHEIRO_VERSION,
            'created'          => gmdate('c'),
            'file'             => $entry,
            'original_path'    => Facheiro_Plugin::relative_path($real, $root),
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

        $tmp = wp_tempnam('facheiro-sample');
        $zip = new ZipArchive();
        if (true !== $zip->open($tmp, ZipArchive::OVERWRITE)) {
            @unlink($tmp); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- our own temporary file.
            return new WP_Error('facheiro_sample_zip', __('Não foi possível criar o arquivo zip.', 'facheiro'));
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
            return new WP_Error('facheiro_sample_zip', __('Não foi possível gravar o arquivo zip.', 'facheiro'));
        }
        return $tmp;
    }

    private static function readme($encrypted)
    {
        $text = "Facheiro sample package\n"
            . "========================\n\n"
            . "This zip holds one file flagged by Facheiro, named by its SHA-256,\n"
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
