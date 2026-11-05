<?php
namespace Elderward\Engine;

////////////////
// Outbound HTTP. The engine only ever talks to api.wordpress.org and
// downloads.wordpress.org (reference checksums and official packages).
// This tool runs on already-compromised hosts: never disable TLS
// verification, or the "all clean" answer can be attacker-supplied.
//
// Inside WordPress the plugin injects an implementation built on the
// WordPress HTTP API; the standalone CLI uses CurlHttp below.
//////////////

// phpcs:disable WordPress.WP.AlternativeFunctions -- CurlHttp is the adapter for running without WordPress (standalone CLI, recovery mode), where the HTTP API and WP_Filesystem do not exist; inside WordPress the plugin passes Elderward_WP_Http, which uses the HTTP API. TLS verification is never disabled.

interface Http
{
    // Returns array($status, $body); status 0 on transport failure.
    public function get($url);
    // Streams the response body into $dest. Returns the HTTP status code
    // (0 on transport failure).
    public function download($url, $dest);
}

class CurlHttp implements Http
{
    public function get($url)
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT        => 60,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => 'elderward',
            ));
            $body = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            self::close_curl($ch);
            return array((false === $body) ? 0 : $status, (string) $body);
        }

        $context = stream_context_create(array('http' => array(
            'timeout'       => 60,
            'user_agent'    => 'elderward',
            'ignore_errors' => true,
        )));
        // fopen rather than file_get_contents: the stream's wrapper_data
        // holds the response headers on every PHP version, while the magic
        // $http_response_header is deprecated in 8.5.
        $fh = @fopen($url, 'r', false, $context);
        if (false === $fh) {
            return array(0, '');
        }
        $status = self::status_from_stream($fh);
        $body = @stream_get_contents($fh);
        fclose($fh);
        return array($status, (false === $body) ? '' : $body);
    }

    public function download($url, $dest)
    {
        // Package zips can be tens of MB: stream to disk instead of buffering.
        if (function_exists('curl_init')) {
            $fh = @fopen($dest, 'w');
            if (false === $fh) {
                return (0);
            }
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_FILE           => $fh,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT        => 300,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => 'elderward',
            ));
            $ok = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            self::close_curl($ch);
            fclose($fh);
            return ((false !== $ok) ? $status : 0);
        }

        // No curl: stream through fopen so the zip never sits in memory.
        $context = stream_context_create(array('http' => array(
            'timeout'       => 300,
            'user_agent'    => 'elderward',
            'ignore_errors' => true,
        )));
        $src = @fopen($url, 'r', false, $context);
        if (false === $src) {
            return (0);
        }
        $status = self::status_from_stream($src);
        $dst = @fopen($dest, 'w');
        if (false === $dst) {
            fclose($src);
            return (0);
        }
        $copied = @stream_copy_to_stream($src, $dst);
        fclose($src);
        fclose($dst);
        return ((false === $copied) ? 0 : $status);
    }

    private static function close_curl($ch)
    {
        // A no-op since PHP 8.0 (the handle is freed with its last
        // reference) and deprecated in 8.5; still needed before 8.0.
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
    }

    private static function status_from_stream($fh)
    {
        // For the http wrapper, wrapper_data is the list of response header
        // lines, every redirect's block included.
        $meta = @stream_get_meta_data($fh);
        return (self::status_from_response_headers(isset($meta['wrapper_data']) ? $meta['wrapper_data'] : null));
    }

    public static function status_from_response_headers($headers)
    {
        // With redirects the array holds several header blocks; the last
        // status line is the one for the final response.
        $status = 0;
        if (is_array($headers)) {
            foreach ($headers as $header_line) {
                if (preg_match('@^HTTP/\S+\s(\d{3})@', $header_line, $matches)) {
                    $status = (int) $matches[1];
                }
            }
        }
        return ($status);
    }
}
