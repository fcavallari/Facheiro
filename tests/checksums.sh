#!/usr/bin/env bash
# Self-check and checksums.json.
#
#   tests/checksums.sh
#
# 1. checksums.json matches the shipped files (run php build/make-checksums.php
#    after changing any of them).
# 2. On a release-like copy of the plugin (no .git, no development files),
#    the self-check is clean, then reports a modified file, a dropped PHP
#    file and a deleted file, prefers checksumdir=/wordpress.org over the
#    bundled list, and says so when there is no list at all.

set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0
fail=0
check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1)); echo "ok   $1"
    else
        fail=$((fail + 1)); echo "FAIL $1: expected [$3], got [$2]"
    fi
}
finding() { # $1 severity, $2 type, $3 path suffix, $4 output
    if grep -q "^$1,$2,.*$3," <<<"$4"; then echo yes; else echo no; fi
}

php "$REPO/build/make-checksums.php" --check >/dev/null; check "checksums.json is up to date" "$?" 0

COPY="$WORK/elderward"
mkdir -p "$COPY"
(cd "$REPO" && php -r '
    require "includes/engine/load.php";
    foreach (array_keys(json_decode(file_get_contents("checksums.json"), true)["files"]) as $f) { echo $f, "\n"; }
    echo "checksums.json\n";' | tar -cf - -T -) | tar -xf - -C "$COPY"
run() { (cd "$WORK" && php "$COPY/bin/elderward.php" selfcheck=1 "checksumdir=$WORK/none" "$@" 2>/dev/null); }
mkdir -p "$WORK/none"

out=$(run); rc=$?
check "release copy: clean" "$rc" 0
grep -q "INTEGRITY_" <<<"$out"; check "release copy: no findings" "$?" 1

echo '// appended' >> "$COPY/includes/engine/signatures.php"
printf '<?php // dropped\n' > "$COPY/includes/zz.php"
rm "$COPY/LICENSE"
out=$(run); rc=$?
check "modified PHP is HIGH" "$(finding HIGH INTEGRITY_MODIFIED includes/engine/signatures.php "$out")" yes
check "dropped PHP is HIGH" "$(finding HIGH INTEGRITY_EXTRA includes/zz.php "$out")" yes
check "deleted file is INFO" "$(finding INFO INTEGRITY_MISSING LICENSE "$out")" yes
check "exit code 3" "$rc" 3

# A wordpress.org-style manifest wins over the bundled list.
mkdir -p "$WORK/cs"
printf '{"files":{"elderward.php":{"md5":"%s"}}}\n' "$(md5sum "$COPY/elderward.php" | cut -d' ' -f1)" > "$WORK/cs/plugin-elderward-1.0.0.json"
out=$(cd "$WORK" && php "$COPY/bin/elderward.php" selfcheck=1 "checksumdir=$WORK/cs" 2>&1)
grep -q "against wordpress.org" <<<"$out"; check "checksumdir manifest preferred" "$?" 0
check "files outside that manifest are extra" "$(finding HIGH INTEGRITY_EXTRA includes/zz.php "$out")" yes

rm "$COPY/checksums.json"
out=$(run)
check "no list: INFO no reference" "$(finding INFO INTEGRITY_NO_REFERENCE "" "$out")" yes

# scanall runs it first; noselfcheck=1 skips it.
WP="$WORK/wp"
mkdir -p "$WP/wp-includes" "$WP/wp-content/plugins"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$WP/wp-includes/version.php"
out=$(cd "$WORK" && php "$COPY/bin/elderward.php" scanall=1 "scandirectory=$WP" "checksumdir=$WORK/none" 2>&1)
grep -q "== Elderward self-check ==" <<<"$out"; check "scanall runs the self-check" "$?" 0
out=$(cd "$WORK" && php "$COPY/bin/elderward.php" scanall=1 noselfcheck=1 "scandirectory=$WP" "checksumdir=$WORK/none" 2>&1)
grep -q "self-check" <<<"$out"; check "noselfcheck=1 skips it" "$?" 1

# The copy installed in the scanned site is checked too, and left out of
# the integrity stage.
cp -r "$COPY" "$WP/wp-content/plugins/elderward"
cp "$REPO/checksums.json" "$WP/wp-content/plugins/elderward/"
out=$(cd "$WORK" && php "$REPO/bin/elderward.php" scanintegrity=1 "scandirectory=$WP" "checksumdir=$WORK/none" 2>&1)
check "installed copy checked" "$(finding HIGH INTEGRITY_EXTRA wp-content/plugins/elderward/includes/zz.php "$out")" yes
grep -q "plugin elderward" <<<"$out"; check "installed copy not in the integrity stage" "$?" 1

echo "checksums: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
