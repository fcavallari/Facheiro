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

COPY="$WORK/facheiro"
mkdir -p "$COPY"
(cd "$REPO" && php -r '
    require "includes/engine/load.php";
    foreach (array_keys(json_decode(file_get_contents("checksums.json"), true)["files"]) as $f) { echo $f, "\n"; }
    echo "checksums.json\n";' | tar -cf - -T -) | tar -xf - -C "$COPY"
run() { (cd "$WORK" && php "$COPY/bin/facheiro.php" selfcheck=1 "checksumdir=$WORK/none" "$@" 2>/dev/null); }
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
printf '{"files":{"facheiro.php":{"md5":"%s"}}}\n' "$(md5sum "$COPY/facheiro.php" | cut -d' ' -f1)" > "$WORK/cs/plugin-facheiro-1.0.0.json"
out=$(cd "$WORK" && php "$COPY/bin/facheiro.php" selfcheck=1 "checksumdir=$WORK/cs" 2>&1)
grep -q "against wordpress.org" <<<"$out"; check "checksumdir manifest preferred" "$?" 0
check "files outside that manifest are extra" "$(finding HIGH INTEGRITY_EXTRA includes/zz.php "$out")" yes

rm "$COPY/checksums.json"
out=$(run)
check "no list: INFO no reference" "$(finding INFO INTEGRITY_NO_REFERENCE "" "$out")" yes

# scanall runs it first; noselfcheck=1 skips it.
WP="$WORK/wp"
mkdir -p "$WP/wp-includes" "$WP/wp-content/plugins"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$WP/wp-includes/version.php"
out=$(cd "$WORK" && php "$COPY/bin/facheiro.php" scanall=1 "scandirectory=$WP" "checksumdir=$WORK/none" 2>&1)
grep -q "== Facheiro self-check ==" <<<"$out"; check "scanall runs the self-check" "$?" 0
out=$(cd "$WORK" && php "$COPY/bin/facheiro.php" scanall=1 noselfcheck=1 "scandirectory=$WP" "checksumdir=$WORK/none" 2>&1)
grep -q "self-check" <<<"$out"; check "noselfcheck=1 skips it" "$?" 1

# The copy installed in the scanned site is checked too, and left out of
# the integrity stage.
cp -r "$COPY" "$WP/wp-content/plugins/facheiro"
cp "$REPO/checksums.json" "$WP/wp-content/plugins/facheiro/"
out=$(cd "$WORK" && php "$REPO/bin/facheiro.php" scanintegrity=1 "scandirectory=$WP" "checksumdir=$WORK/none" 2>&1)
check "installed copy checked" "$(finding HIGH INTEGRITY_EXTRA wp-content/plugins/facheiro/includes/zz.php "$out")" yes
grep -q "plugin facheiro" <<<"$out"; check "installed copy not in the integrity stage" "$?" 1

# A git checkout: development files are verified too, nothing is skipped.
DEV="$WORK/dev"
mkdir -p "$DEV"
(cd "$REPO" && git ls-files --cached --others --exclude-standard | tar -cf - -T -) | tar -xf - -C "$DEV"
mkdir -p "$DEV/.git/objects"
printf 'blob\n' > "$DEV/.git/objects/ab"
devrun() { (cd "$WORK" && php "$DEV/bin/facheiro.php" selfcheck=1 "checksumdir=$WORK/none" 2>/dev/null); }
out=$(devrun)
grep -q "INTEGRITY_\(MODIFIED\|EXTRA\)" <<<"$out"; check "git checkout: clean" "$?" 1
printf '<?php // planted\n' > "$DEV/tests/zz.php"
echo '// appended' >> "$DEV/tests/chunking.php"
printf '<?php // planted\n' > "$DEV/.git/objects/zz.php"
mkdir -p "$DEV/vendor/acme"
printf '<?php // dependency\n' > "$DEV/vendor/acme/a.php"
out=$(devrun)
check "git checkout: PHP added to tests/ is HIGH" "$(finding HIGH INTEGRITY_EXTRA tests/zz.php "$out")" yes
check "git checkout: modified test file is HIGH" "$(finding HIGH INTEGRITY_MODIFIED tests/chunking.php "$out")" yes
check "git checkout: PHP inside .git is HIGH" "$(finding HIGH INTEGRITY_EXTRA .git/objects/zz.php "$out")" yes
check "git checkout: vendor/ reported unverified" "$(finding MEDIUM INTEGRITY_NO_REFERENCE /vendor "$out")" yes
grep -q '\.git/objects/ab' <<<"$out"; check "git checkout: git data not listed" "$?" 1
mkdir -p "$WORK/cs-dev"
printf '{"files":{"facheiro.php":{"md5":"%s"}}}\n' "$(md5sum "$DEV/facheiro.php" | cut -d' ' -f1)" > "$WORK/cs-dev/plugin-facheiro-1.0.0.json"
out=$(cd "$WORK" && php "$DEV/bin/facheiro.php" selfcheck=1 "checksumdir=$WORK/cs-dev" 2>/dev/null)
check "wordpress.org reference: modified test file still extra" "$(finding HIGH INTEGRITY_EXTRA tests/chunking.php "$out")" yes
grep -q 'tests/regress.sh' <<<"$out"; check "wordpress.org reference: unchanged dev files accepted" "$?" 1

echo "checksums: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
