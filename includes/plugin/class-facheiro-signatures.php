<?php
/**
 * Custom signatures written in the signature editor (or by an assistant
 * through the abilities): stored as engine definitions, validated by the
 * engine, installed into every scan on this site (admin, WP-Cron, WP-CLI).
 *
 * Custom signatures only detect. File signatures report SIGNATURE_MATCH and
 * never clean or delete, even from `wp facheiro scan` without --dryrun.
 *
 * @package Facheiro
 */

if (!defined('ABSPATH')) {
    exit;
}

use Facheiro\Engine\Fatal;
use Facheiro\Engine\Signatures;
use Facheiro\Engine\SignatureScanner;

final class Facheiro_Signatures
{
    const OPTION = 'facheiro_signatures';
    const MAX = 200;
    const MAX_DESCRIPTION = 300;
    const TEST_MAX_BYTES = 2097152;

    /**
     * Stored definitions, in order.
     */
    public static function all()
    {
        $defs = get_option(self::OPTION, array());
        return is_array($defs) ? array_values($defs) : array();
    }

    public static function get($id)
    {
        foreach (self::all() as $def) {
            if (isset($def['id']) && $def['id'] === $id) {
                return $def;
            }
        }
        return null;
    }

    /**
     * Load the enabled custom signatures into the engine. An entry that
     * stopped validating (edited option, newer rules) is skipped rather
     * than breaking every scan.
     */
    public static function install()
    {
        $valid = array();
        foreach (self::all() as $def) {
            if (null === Signatures::validate_definition($def)) {
                $valid[] = $def;
            }
        }
        Signatures::set_custom(Signatures::from_definitions($valid));
    }

    /**
     * Coerce loosely typed input (form fields, ability arguments, imported
     * JSON) into a definition; validation happens afterwards.
     */
    public static function normalize(array $input)
    {
        $def = array(
            'id'          => isset($input['id']) ? strtolower(trim((string) $input['id'])) : '',
            'target'      => isset($input['target']) ? (string) $input['target'] : 'file',
            'severity'    => isset($input['severity']) ? strtoupper((string) $input['severity']) : 'HIGH',
            'description' => isset($input['description']) ? self::short_text($input['description']) : '',
            'enabled'     => !isset($input['enabled']) || (bool) $input['enabled'],
        );
        if ('file' === $def['target']) {
            $def['match'] = array();
            $match = (isset($input['match']) && is_array($input['match'])) ? $input['match'] : array();
            foreach ($match as $condition) {
                if (is_array($condition) && isset($condition['string']) && is_string($condition['string'])) {
                    $def['match'][] = array('string' => $condition['string']);
                } elseif (is_array($condition) && isset($condition['regex']) && is_string($condition['regex'])) {
                    $def['match'][] = array('regex' => $condition['regex']);
                } else {
                    $def['match'][] = $condition;
                }
            }
        } else {
            $def['pattern'] = isset($input['pattern']) && is_string($input['pattern']) ? $input['pattern'] : '';
        }
        return $def;
    }

    private static function short_text($text)
    {
        $text = sanitize_text_field((string) $text);
        return function_exists('mb_substr') ? mb_substr($text, 0, self::MAX_DESCRIPTION) : substr($text, 0, self::MAX_DESCRIPTION);
    }

    private static function check(array $def)
    {
        foreach (array_merge(isset($def['match']) ? $def['match'] : array(), isset($def['pattern']) ? array(array('regex' => $def['pattern'])) : array()) as $condition) {
            $value = is_array($condition) ? reset($condition) : '';
            if (is_string($value) && !wp_check_invalid_utf8($value)) {
                return new WP_Error('facheiro_signature', __('Os padrões precisam ser texto UTF-8 válido.', 'facheiro'));
            }
        }
        $problem = Signatures::validate_definition($def);
        if (null !== $problem) {
            return new WP_Error('facheiro_signature', $problem);
        }
        return true;
    }

    /**
     * Add or replace one signature. $original_id renames on edit.
     *
     * @return array|WP_Error The saved definition.
     */
    public static function save(array $input, $original_id = '')
    {
        $def = self::normalize($input);
        $ok = self::check($def);
        if (is_wp_error($ok)) {
            return $ok;
        }
        $saved = self::change(function ($defs) use ($def, $original_id) {
            $replaced = false;
            foreach ($defs as $existing) {
                if (isset($existing['id']) && $existing['id'] === $def['id'] && $def['id'] !== $original_id) {
                    return new WP_Error('facheiro_signature', __('Outra assinatura personalizada já usa esse nome.', 'facheiro'));
                }
            }
            foreach ($defs as $i => $existing) {
                if (isset($existing['id']) && $existing['id'] === ('' !== $original_id ? $original_id : $def['id'])) {
                    $defs[$i] = $def;
                    $replaced = true;
                    break;
                }
            }
            if (!$replaced) {
                if (count($defs) >= self::MAX) {
                    return new WP_Error('facheiro_signature', __('Assinaturas personalizadas demais.', 'facheiro'));
                }
                $defs[] = $def;
            }
            return array_values($defs);
        });
        if (is_wp_error($saved)) {
            return $saved;
        }
        return $def;
    }

    public static function delete($id)
    {
        $found = false;
        self::change(function ($defs) use ($id, &$found) {
            $kept = array();
            foreach ($defs as $def) {
                if (isset($def['id']) && $def['id'] === $id) {
                    $found = true;
                    continue;
                }
                $kept[] = $def;
            }
            return $found ? $kept : false;
        });
        return $found;
    }

    /**
     * Change the stored definitions through the tamper seal. $mutate gets
     * the current list and returns the new one (false or a WP_Error to
     * change nothing).
     */
    private static function change(callable $mutate)
    {
        return Facheiro_Seal::update('signatures', function ($defs) use ($mutate) {
            return call_user_func($mutate, is_array($defs) ? array_values($defs) : array());
        });
    }

    public static function set_enabled($id, $enabled)
    {
        $def = self::get($id);
        if (null === $def) {
            return new WP_Error('facheiro_signature', __('Não há assinatura personalizada com esse nome.', 'facheiro'));
        }
        $def['enabled'] = (bool) $enabled;
        return self::save($def, $id);
    }

    /**
     * Import a signature file (the export format). All or nothing: one
     * invalid entry rejects the file. Same ids are replaced.
     *
     * @return int|WP_Error Number of signatures imported.
     */
    public static function import($json)
    {
        try {
            $incoming = Signatures::parse_file((string) $json);
        } catch (Fatal $e) {
            return new WP_Error('facheiro_signature', $e->getMessage());
        }
        $defs = array();
        foreach ($incoming as $raw) {
            $def = self::normalize(is_array($raw) ? $raw : array());
            $ok = self::check($def);
            if (is_wp_error($ok)) {
                return $ok;
            }
            $defs[$def['id']] = $def;
        }
        $saved = self::change(function ($existing_defs) use ($defs) {
            $merged = array();
            foreach ($existing_defs as $i => $existing) {
                $merged[isset($existing['id']) ? $existing['id'] : '#' . $i] = $existing;
            }
            foreach ($defs as $id => $def) {
                $merged[$id] = $def;
            }
            if (count($merged) > self::MAX) {
                return new WP_Error('facheiro_signature', __('Assinaturas personalizadas demais.', 'facheiro'));
            }
            return array_values($merged);
        });
        if (is_wp_error($saved)) {
            return $saved;
        }
        return count($defs);
    }

    public static function export_json()
    {
        return wp_json_encode(array('facheiro_signatures' => 1, 'signatures' => self::all()), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }

    /**
     * Editor textarea <-> conditions: one per line, "text: ..." or
     * "regex: ...".
     *
     * @return array|WP_Error
     */
    public static function parse_conditions($text)
    {
        $conditions = array();
        foreach (preg_split('/\r\n|\r|\n/', (string) $text) as $line) {
            if ('' === trim($line)) {
                continue;
            }
            if (1 === preg_match('/^\s*(text|string|regex)\s*:\s?(.*)$/i', $line, $m)) {
                $kind = 'regex' === strtolower($m[1]) ? 'regex' : 'string';
                $conditions[] = array($kind => rtrim($m[2], "\r"));
                continue;
            }
            return new WP_Error('facheiro_signature', sprintf(
                /* translators: %s: the offending line */
                __('Cada linha de condição precisa começar com "text:" ou "regex:" (recebido: %s).', 'facheiro'),
                $line
            ));
        }
        return $conditions;
    }

    public static function conditions_text(array $def)
    {
        if (isset($def['pattern'])) {
            return 'regex: ' . $def['pattern'];
        }
        $lines = array();
        foreach (isset($def['match']) ? $def['match'] : array() as $condition) {
            $lines[] = isset($condition['regex']) ? 'regex: ' . $condition['regex'] : 'text: ' . $condition['string'];
        }
        return implode("\n", $lines);
    }

    /**
     * Which signatures (built-in and custom, enabled or not) match a piece
     * of text. Nothing is written or stored.
     *
     * @return array List of array(id, source, target, severity).
     */
    public static function test($text)
    {
        $text = (string) $text;
        $hits = array();
        foreach (Signatures::builtin_cleanup() as $name => $signature) {
            if (SignatureScanner::signature_matches($text, $signature)) {
                $hits[] = array('id' => $name, 'source' => 'built-in', 'target' => 'file', 'severity' => 'HIGH', 'enabled' => true);
            }
        }
        // The detection set, with the same second look the scan gives it.
        $normalized = Signatures::normalize_code($text);
        foreach (Signatures::builtin_detection() as $name => $signature) {
            if (SignatureScanner::signature_matches($text, $signature) || ($normalized !== $text && SignatureScanner::signature_matches($normalized, $signature))) {
                $hits[] = array('id' => $name, 'source' => 'built-in', 'target' => 'file', 'severity' => $signature['action']['detect'], 'enabled' => true);
            }
        }
        foreach (array('db_option' => Signatures::builtin_db_options(), 'db_post' => Signatures::builtin_db_posts()) as $target => $set) {
            foreach ($set as $signature) {
                if (1 === preg_match($signature['pattern'], $text)) {
                    $hits[] = array('id' => $signature['name'], 'source' => 'built-in', 'target' => $target, 'severity' => $signature['severity'], 'enabled' => true);
                }
            }
        }
        $defs = self::all();
        $by_id = array();
        foreach ($defs as $def) {
            $by_id[$def['id']] = $def;
        }
        foreach (Signatures::test_definitions($defs, $text) as $id) {
            $hits[] = array('id' => $id, 'source' => 'custom', 'target' => $by_id[$id]['target'], 'severity' => $by_id[$id]['severity'], 'enabled' => !isset($by_id[$id]['enabled']) || (bool) $by_id[$id]['enabled']);
        }
        return $hits;
    }

    /**
     * Read a site file for testing: inside the WordPress root, at most 2 MB.
     * Only match names leave this function, never the content.
     *
     * @return string|WP_Error
     */
    public static function read_site_file($path)
    {
        $path = (string) $path;
        $root = realpath(ABSPATH);
        if ('' !== $path && '/' !== $path[0]) {
            $path = trailingslashit($root) . $path;
        }
        $real = realpath($path);
        if (false === $real || false === $root || 0 !== strpos($real, untrailingslashit($root) . '/') || !is_file($real) || !is_readable($real)) {
            return new WP_Error('facheiro_signature', __('Informe um arquivo legível dentro da pasta do WordPress.', 'facheiro'));
        }
        // Match results leak content one regex at a time, so the file with
        // the database credentials is off limits, as for sample downloads.
        if (1 === preg_match('/^wp-config/i', basename($real))) {
            return new WP_Error('facheiro_signature', __('Arquivos wp-config guardam a senha do banco de dados e não podem ser testados.', 'facheiro'));
        }
        if (filesize($real) > self::TEST_MAX_BYTES) {
            return new WP_Error('facheiro_signature', __('O arquivo tem mais de 2 MB, tamanho que a varredura de arquivos também pula.', 'facheiro'));
        }
        $content = file_get_contents($real); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file, matched in memory, never echoed.
        return false === $content ? new WP_Error('facheiro_signature', __('Não foi possível ler o arquivo.', 'facheiro')) : $content;
    }

    /**
     * Built-in signatures for the read-only listing.
     */
    public static function builtin_listing()
    {
        $list = array();
        foreach (Signatures::builtin_cleanup() as $name => $signature) {
            $conditions = array_merge(array($signature['prefilter']), $signature['triggers']);
            $list[] = array('id' => $name, 'target' => 'file', 'severity' => 'HIGH', 'description' => __('Assinatura de limpeza (remove o código injetado em uma limpeza)', 'facheiro'), 'conditions' => self::conditions_text(array('match' => $conditions)));
        }
        foreach (Signatures::builtin_detection() as $name => $signature) {
            $conditions = array_merge(array($signature['prefilter']), $signature['triggers']);
            $list[] = array('id' => $name, 'target' => 'file', 'severity' => $signature['action']['detect'], 'description' => $signature['action']['description'], 'conditions' => self::conditions_text(array('match' => $conditions)));
        }
        foreach (array('db_option' => Signatures::builtin_db_options(), 'db_post' => Signatures::builtin_db_posts()) as $target => $set) {
            foreach ($set as $signature) {
                $list[] = array('id' => $signature['name'], 'target' => $target, 'severity' => $signature['severity'], 'description' => $signature['description'], 'conditions' => 'regex: ' . $signature['pattern']);
            }
        }
        return $list;
    }
}
