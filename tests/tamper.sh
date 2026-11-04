#!/usr/bin/env bash
# Tamper detection on a WordPress test site with Elderward active.
#
#   WP_PATH=/path/to/wordpress WP_CLI="wp --allow-root" tests/tamper.sh
#
# Changes made through Elderward keep the seal valid; the same changes made
# with update_option() (what a database-only attacker can do) are reported,
# and a false positive added that way stops hiding its finding. Leaves the
# site's false positives, custom signatures and settings as it found them.

set -u
WP_PATH="${WP_PATH:?set WP_PATH to the WordPress root}"
WP_CLI="${WP_CLI:-wp}"
wp() { (cd "$WP_PATH" && $WP_CLI "$@"); }
pass=0
fail=0
check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1)); echo "ok   $1"
    else
        fail=$((fail + 1)); echo "FAIL $1: expected [$3], got [$2]"
    fi
}
has_finding() { # $1 type, $2 json lines
    if grep -q "\"type\":\"$1\"" <<<"$2"; then echo yes; else echo no; fi
}

SEAL="$WP_PATH/wp-content/elderward-seal.php"
backup=$(wp eval 'echo base64_encode(serialize(array(get_option("elderward_false_positives", null), get_option("elderward_signatures", null), get_option("elderward_settings", null))));')
restore() {
    T_ARG="$backup" wp eval '$b = unserialize(base64_decode(getenv("T_ARG")));
        foreach (array("elderward_false_positives", "elderward_signatures", "elderward_settings") as $i => $o) {
            if (null === $b[$i]) { delete_option($o); } else { update_option($o, $b[$i], false); }
        }
        Elderward_Seal::accept();' >/dev/null
}
trap restore EXIT

wp elderward seal accept >/dev/null
wp elderward seal status >/dev/null; check "clean seal" "$?" 0

# A rule saved through Elderward keeps the seal valid and applies.
FP_OK=$(printf 'ok%038d' 1)
T_ARG="$FP_OK" wp eval '$fp = getenv("T_ARG");
    Elderward_Seal::update("false_positives", function ($rules) use ($fp) {
        $rules = is_array($rules) ? $rules : array();
        $rules[$fp] = array("type" => "UPLOADS_PHP", "severity" => "HIGH", "path" => "/x/ok.php", "detail" => "d", "sha256" => null, "note" => "", "user" => 1, "via" => "admin", "time" => 1);
        return $rules;
    });'
wp elderward seal status >/dev/null; check "rule saved through Elderward" "$?" 0
check "sealed rule applies" "$(T_ARG="$FP_OK" wp eval 'echo Elderward_False_Positives::classify(getenv("T_ARG"), null);')" 1

# The same kind of rule written straight into the option.
FP_BAD=$(printf 'ba%038d' 2)
T_ARG="$FP_BAD" wp eval '$r = get_option("elderward_false_positives"); $r[getenv("T_ARG")] = array("type" => "UPLOADS_PHP", "severity" => "HIGH", "path" => "/x/shell.php", "detail" => "d", "sha256" => null, "note" => "", "user" => 1, "via" => "admin", "time" => 1); update_option("elderward_false_positives", $r, false);'
wp elderward seal status >/dev/null; check "injected rule detected" "$?" 3
check "injected rule ignored" "$(T_ARG="$FP_BAD" wp eval 'echo Elderward_False_Positives::classify(getenv("T_ARG"), null);')" 0
check "sealed rule still applies" "$(T_ARG="$FP_OK" wp eval 'echo Elderward_False_Positives::classify(getenv("T_ARG"), null);')" 1
out=$(wp elderward selfcheck --format=json)
check "scan reports TAMPER_FALSE_POSITIVE" "$(has_finding TAMPER_FALSE_POSITIVE "$out")" yes
grep -q 'shell.php' <<<"$out"; check "finding names the rule's path" "$?" 0

# Keeping it after review trusts it.
T_ARG="$FP_BAD" wp eval 'Elderward_False_Positives::keep(getenv("T_ARG"));'
check "kept rule applies" "$(T_ARG="$FP_BAD" wp eval 'echo Elderward_False_Positives::classify(getenv("T_ARG"), null);')" 1
wp elderward seal status >/dev/null; check "seal clean after keep" "$?" 0

# A legitimate change to one rule leaves another tampered rule reported.
T_ARG="$FP_BAD" wp eval '$r = get_option("elderward_false_positives"); $r[getenv("T_ARG")]["note"] = "edited in the database"; update_option("elderward_false_positives", $r, false);'
T_ARG="$FP_OK" wp eval 'Elderward_False_Positives::unmark(getenv("T_ARG"));'
wp elderward seal status >/dev/null; check "untouched tampered rule stays reported" "$?" 3
check "changed rule ignored" "$(T_ARG="$FP_BAD" wp eval 'echo Elderward_False_Positives::classify(getenv("T_ARG"), null);')" 0
T_ARG="$FP_BAD" wp eval 'Elderward_False_Positives::unmark(getenv("T_ARG"));'
wp elderward seal status >/dev/null; check "removing the tampered rule clears it" "$?" 0

# Custom signatures: removed, then changed (disabled) in the database.
wp eval 'Elderward_Signatures::save(array("id" => "tamper-test", "target" => "file", "severity" => "HIGH", "match" => array(array("string" => "tamper_test_marker"))));' >/dev/null
wp elderward seal status >/dev/null; check "signature saved through Elderward" "$?" 0
wp eval '$d = get_option("elderward_signatures"); foreach ($d as $i => $s) { if ("tamper-test" === $s["id"]) { $d[$i]["enabled"] = false; } } update_option("elderward_signatures", $d, false);'
out=$(wp elderward selfcheck --format=json)
grep -q '"custom signature tamper-test".*changed' <<<"$out"; check "disabled signature reported" "$?" 0
wp eval '$d = array_values(array_filter(get_option("elderward_signatures"), function ($s) { return "tamper-test" !== $s["id"]; })); update_option("elderward_signatures", $d, false);'
out=$(wp elderward selfcheck --format=json)
grep -q '"custom signature tamper-test".*removed' <<<"$out"; check "removed signature reported" "$?" 0
wp elderward seal accept --collection=signatures >/dev/null
wp elderward seal status >/dev/null; check "acknowledged removal" "$?" 0

# Settings.
wp eval '$s = get_option("elderward_settings", array()); $s = is_array($s) ? $s : array(); $s["schedule"] = "off"; $s["log"] = "/tmp/attacker-" . mt_rand(); update_option("elderward_settings", $s, false);'
out=$(wp elderward selfcheck --format=json)
check "settings change reported" "$(has_finding TAMPER_SETTINGS "$out")" yes
wp elderward seal accept --collection=settings >/dev/null

# Seal file deleted: reported once recreated, until accepted.
rm -f "$SEAL"
out=$(wp elderward selfcheck --format=json)
check "missing seal reported" "$(has_finding TAMPER_SEAL_MISSING "$out")" yes
[ -f "$SEAL" ]; check "seal recreated" "$?" 0
wp elderward seal accept >/dev/null
out=$(wp elderward selfcheck --format=json)
check "missing-seal notice cleared by accept" "$(has_finding TAMPER_SEAL_MISSING "$out")" no

# Garbled seal file counts as missing.
echo 'garbage' > "$SEAL"
out=$(wp elderward selfcheck --format=json)
check "garbled seal reported" "$(has_finding TAMPER_SEAL_MISSING "$out")" yes
wp elderward seal accept >/dev/null

# Two writers at once: the lock keeps option and seal in step.
add_rules='for ($i = 0; $i < 15; $i++) { $fp = sprintf("%s%038d", getenv("T_ARG"), $i);
    Elderward_Seal::update("false_positives", function ($rules) use ($fp) {
        $rules = is_array($rules) ? $rules : array();
        $rules[$fp] = array("type" => "UPLOADS_PHP", "severity" => "HIGH", "path" => "/x/" . $fp, "detail" => "d", "sha256" => null, "note" => "", "user" => 1, "via" => "admin", "time" => 1);
        return $rules;
    }); }'
T_ARG=aa wp eval "$add_rules" & T_ARG=bb wp eval "$add_rules" & wait
check "parallel writers: all rules saved" "$(wp eval 'echo count(preg_grep("/^(aa|bb)0/", array_keys(get_option("elderward_false_positives"))));')" 30
wp elderward seal status >/dev/null; check "parallel writers: seal matches" "$?" 0

echo "tamper: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
