#!/usr/bin/env bash
# Old-vs-new regression harness for the engine refactor.
#
# Runs the pre-refactor single-file script (taken from git) and the new
# bin/elderward.php with identical arguments over synthetic fixtures, and
# diffs stdout (sorted: unit ordering inside a scanner is not a contract)
# and exit codes. Any difference fails the run.
#
#   tests/regress.sh [git-ref-of-old-script]   (default: 1f5abde, main when the
#   single-file script was merged)
#
# The database cases need the MariaDB fixture from TESTPLAN E (database
# wp_test reachable through /run/mysqld/mysqld.sock); they are skipped
# with a note when the server is not running.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OLD_REF="${1:-1f5abde}"
WORK="$(mktemp -d)"
OLD="$WORK/old-elderward.php"
NEW="$REPO/bin/elderward.php"
PASS=0
FAIL=0
SKIP=0

git -C "$REPO" show "$OLD_REF:elderward.php" > "$OLD" || { echo "cannot extract $OLD_REF:elderward.php"; exit 1; }
# The old script names $http_response_header, which PHP 8.5 deprecates at
# compile time; its notices are not part of the output contract being
# compared (E_ALL & ~E_DEPRECATED, old script only).
OLD_INI="-d error_reporting=24575"

###############
# Fixtures
##############
SITE="$WORK/site"
mkdir -p "$SITE/sub"
cat > "$SITE/ndsw.js" <<'EOF'
var legit=1;
if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};
console.log(legit);
EOF
printf 'if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};\n' > "$SITE/sub/payload.txt"
printf 'clean file\n' > "$SITE/sub/clean.php"

LOGS="$WORK/logs"
mkdir -p "$LOGS"
cat > "$LOGS/access.log" <<'EOF'
203.0.113.5 - - [20/Sep/2026:10:05:01 +0000] "POST /wp-content/uploads/2026/09/wp-cache.php HTTP/1.1" 200 312 "-" "python-requests/2.31"
192.0.2.44 - - [20/Sep/2026:10:08:30 +0000] "GET /.env HTTP/1.1" 404 210 "-" "Mozilla/5.0"
192.0.2.44 - - [20/Sep/2026:10:09:00 +0000] "GET /?q=eval(base64_decode($_POST[1])) HTTP/1.1" 200 100 "-" "Mozilla/5.0"
EOF
ln -sf /nonexistent/access.log.1.gz "$LOGS/access.log.1.gz"
printf 'noise\n' > "$LOGS/error.log"

# A fake WordPress root with the quick-check artifacts and packages for the
# integrity/timestamp passes (checksumdir points at an empty dir, so the
# integrity pass never touches the network).
WP="$WORK/wp"
mkdir -p "$WP/wp-includes" "$WP/wp-admin" "$WP/wp-content/plugins/hello-dolly" "$WP/wp-content/themes/twentyx" \
         "$WP/wp-content/uploads/2026" "$WP/wp-content/mu-plugins"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$WP/wp-includes/version.php"
for i in $(seq 1 12); do printf '<?php // core %s\n' "$i" > "$WP/wp-includes/file$i.php"; done
printf '<?php // login\n' > "$WP/wp-login.php"
printf '<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n' > "$WP/wp-content/plugins/hello-dolly/hello.php"
printf '<?php // loose plugin\n' > "$WP/wp-content/plugins/loose.php"
printf '/*\nTheme Name: Twenty X\nVersion: 1.0\n*/\n' > "$WP/wp-content/themes/twentyx/style.css"
printf '<?php echo 1;\n' > "$WP/wp-content/uploads/2026/shell.php"
printf '<?php // silence\n' > "$WP/wp-content/uploads/index.php"
printf '<?php // mu\n' > "$WP/wp-content/mu-plugins/loader.php"
printf '<?php // hidden\n' > "$WP/wp-content/.hidden.php"
printf 'auto_prepend_file = /tmp/evil.php\n' > "$WP/.user.ini"
printf 'if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};\n' > "$WP/wp-content/themes/twentyx/bad.js"
# A timestamp outlier: 12 core files from 2024, one edited "later".
find "$WP/wp-includes" -type f -exec touch -t 202401010000 {} +
touch -t 202406010000 "$WP/wp-includes/file7.php"
touch -t 202401010000 "$WP/wp-login.php"
EMPTY="$WORK/empty"
mkdir -p "$EMPTY"

SP_DBROOT="${ELDERWARD_DBROOT:-/tmp/claude-0/-home-user-repo/17782ee5-9ca9-5ef3-84d1-5311e5ee9ae3/scratchpad/dbroot}"
DB_UP=0
if command -v mysqladmin >/dev/null 2>&1 && mysqladmin --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1 && [ -f "$SP_DBROOT/wp-config.php" ]; then
    DB_UP=1
fi

###############
# Runner
##############
# compare NAME [args...]  - run old and new in text and json, compare.
compare() {
    local name="$1"; shift
    local mode
    for mode in text json; do
        local extra=()
        [ "$mode" = json ] && extra=(format=json)
        local o_out n_out o_rc n_rc
        # ${extra[@]+...}: an empty array is "unbound" to bash 3.2 (macOS) under set -u.
        (cd "$WORK" && php $OLD_INI "$OLD" "$@" ${extra[@]+"${extra[@]}"} > "$WORK/o.out" 2>/dev/null); o_rc=$?
        # noselfcheck=1: the old script had no self-check stage (that
        # stage has its own test, tests/checksums.sh).
        (cd "$WORK" && php "$NEW" "$@" ${extra[@]+"${extra[@]}"} noselfcheck=1 > "$WORK/n.out" 2>/dev/null); n_rc=$?
        o_out="$(sort "$WORK/o.out")"
        n_out="$(sort "$WORK/n.out")"
        if [ "$o_out" == "$n_out" ] && [ "$o_rc" == "$n_rc" ]; then
            PASS=$((PASS+1))
            printf 'PASS  %-34s %-4s exit=%s lines=%s\n' "$name" "$mode" "$n_rc" "$(printf '%s' "$n_out" | grep -c .)"
        else
            FAIL=$((FAIL+1))
            printf 'FAIL  %-34s %-4s old exit=%s new exit=%s\n' "$name" "$mode" "$o_rc" "$n_rc"
            diff <(printf '%s\n' "$o_out") <(printf '%s\n' "$n_out") | head -20
        fi
    done
}

compare "signature dryrun"            dryrun=1 "scandirectory=$SITE"
compare "signature allfiles dryrun"   dryrun=1 allfiles=1 "scandirectory=$SITE"
compare "signature bad dir"           "scandirectory=$WORK/nonexistent"
compare "scan_all rejected"           scan_all=1 "scandirectory=$SITE"
compare "mode exclusivity"            scancron=1 scantimes=1
compare "correlate without scanlog"   correlate=1
compare "plus decodes to space"       "scandirectory=$WORK/a+b"
compare "log single file"             "scanlog=$LOGS/access.log"
compare "log directory"               "scanlog=$LOGS"
compare "log + correlate"             "scanlog=$LOGS" correlate=1 "scandirectory=$SITE"
compare "log missing target"          "scanlog=$WORK/nope"
compare "crontab"                     scancron=1
compare "quickscan"                   quickscan=1 "scandirectory=$WP"
compare "quickscan non-wp root"       quickscan=1 "scandirectory=$SITE"
compare "scantimes"                   scantimes=1 "scandirectory=$WP"
compare "scanintegrity offline"       scanintegrity=1 "checksumdir=$EMPTY" "scandirectory=$WP"
compare "scanall offline (no db)"     scanall=1 "checksumdir=$EMPTY" "scandirectory=$WP"
compare "scanall + scanlog"           scanall=1 "scanlog=$LOGS" "checksumdir=$EMPTY" "scandirectory=$WP"
compare "scanall restore ignored"     scanall=1 restore=1 "checksumdir=$EMPTY" "scandirectory=$WP"

if [ "$DB_UP" = 1 ]; then
    compare "scandb infected"         scandb=1 "scandirectory=$SP_DBROOT"
    compare "scanall with db"         scanall=1 "checksumdir=$EMPTY" "scandirectory=$SP_DBROOT"
    for variant in root_badprefix root_badpass root_tcp; do
        if [ -d "$(dirname "$SP_DBROOT")/$variant" ]; then
            compare "scandb $variant"       scandb=1 "scandirectory=$(dirname "$SP_DBROOT")/$variant"
            compare "scanall $variant"      scanall=1 "checksumdir=$EMPTY" "scandirectory=$(dirname "$SP_DBROOT")/$variant"
        fi
    done
else
    SKIP=$((SKIP+1))
    echo "SKIP  database cases (MariaDB not reachable or $SP_DBROOT missing)"
fi

###############
# Real cleanup: both must leave the same bytes on disk.
##############
cp -r "$SITE" "$WORK/clean-old"; cp -r "$SITE" "$WORK/clean-new"
php $OLD_INI "$OLD" "scandirectory=$WORK/clean-old" >/dev/null 2>&1; o_rc=$?
php "$NEW" "scandirectory=$WORK/clean-new" >/dev/null 2>&1; n_rc=$?
if diff -r "$WORK/clean-old" "$WORK/clean-new" >/dev/null && [ "$o_rc" == "$n_rc" ] && ! grep -q ndsw "$WORK/clean-new/ndsw.js"; then
    PASS=$((PASS+1)); echo "PASS  real cleanup: identical trees, payload removed, exit=$n_rc"
else
    FAIL=$((FAIL+1)); echo "FAIL  real cleanup differs (old exit=$o_rc new exit=$n_rc)"; diff -r "$WORK/clean-old" "$WORK/clean-new" | head
fi

###############
# Custom signatures (signatures=, new in the plugin round: no old-script
# counterpart, so these check the new CLI on its own). A custom signature
# reports SIGNATURE_MATCH and never modifies the file, even without dryrun.
##############
SIGSITE="$WORK/sigsite"
mkdir -p "$SIGSITE"
printf '<?php // acme_loader\n$x = get_option("c"); eval($x);\n' > "$SIGSITE/hit.php"
printf '<?php echo "hello";\n' > "$SIGSITE/clean.php"
cat > "$WORK/sigs.json" <<'JSON'
{"elderward_signatures":1,"signatures":[{"id":"acme-loader","target":"file","severity":"MEDIUM","description":"ACME loader","match":[{"string":"acme_loader"},{"regex":"/eval\\s*\\(\\s*\\$/"}]}]}
JSON
cat > "$WORK/sigs-bad.json" <<'JSON'
{"elderward_signatures":1,"signatures":[{"id":"everything","target":"file","severity":"LOW","description":"matches all","match":[{"regex":"/.*/"}]}]}
JSON
sig_check() {
    local name="$1" want_rc="$2" want="$3" refuse="$4"; shift 4
    local out rc
    # noselfcheck=1: these cases are about the scan under test, not about
    # whether checksums.json matches this checkout (tests/checksums.sh).
    out="$(cd "$WORK" && php "$NEW" "$@" noselfcheck=1 2>/dev/null)"; rc=$?
    if [ "$rc" == "$want_rc" ] && printf '%s' "$out" | grep -q -- "$want" && { [ -z "$refuse" ] || ! printf '%s' "$out" | grep -q -- "$refuse"; }; then
        PASS=$((PASS+1)); printf 'PASS  %-39s exit=%s\n' "$name" "$rc"
    else
        FAIL=$((FAIL+1)); printf 'FAIL  %-39s exit=%s (want %s)\n' "$name" "$rc" "$want_rc"; printf '%s\n' "$out" | head -10
    fi
}
before="$(sha256sum "$SIGSITE/hit.php")"
sig_check "custom signature dryrun text"    2 'SIGNATURE_MATCH.*hit\.php' 'clean\.php' dryrun=1 "signatures=$WORK/sigs.json" "scandirectory=$SIGSITE"
sig_check "custom signature dryrun json"    2 '"type":"SIGNATURE_MATCH"' '' dryrun=1 format=json "signatures=$WORK/sigs.json" "scandirectory=$SIGSITE"
sig_check "custom signature real run"       2 'SIGNATURE_MATCH' '' "signatures=$WORK/sigs.json" "scandirectory=$SIGSITE"
if [ "$before" == "$(sha256sum "$SIGSITE/hit.php")" ]; then
    PASS=$((PASS+1)); echo "PASS  custom signature left the file unchanged"
else
    FAIL=$((FAIL+1)); echo "FAIL  custom signature modified the file"
fi
sig_check "custom signature matches empty"  1 'empty' '' dryrun=1 "signatures=$WORK/sigs-bad.json" "scandirectory=$SIGSITE"
sig_check "custom signature file missing"   1 'sigs-nope' '' dryrun=1 "signatures=$WORK/sigs-nope.json" "scandirectory=$SIGSITE"

###############
# Files the signature scan cannot check are findings, never a silent skip
# (new rule, no old-script counterpart). A JavaScript bundle over the size
# cap is INFO (core ships several); PHP that large, or a file that cannot be
# read, is an ERROR. A dangling symlink holds nothing and stays quiet.
##############
BIGJS="$WORK/big-js"; BIGPHP="$WORK/big-php"; UNREAD="$WORK/unreadable"
mkdir -p "$BIGJS" "$BIGPHP" "$UNREAD"
head -c 2200000 /dev/zero | tr '\0' 'a' > "$BIGJS/bundle.js"
{ printf '<?php\n/*'; head -c 2200000 /dev/zero | tr '\0' 'a'; printf '*/\n'; } > "$BIGPHP/padded.php"
printf '<?php echo 1;\n' > "$UNREAD/locked.php"; chmod 000 "$UNREAD/locked.php"
ln -s "$WORK/nonexistent.php" "$UNREAD/dangling.php"
sig_check "oversized js is INFO"            0 'INFO,FILE_TOO_LARGE,.*bundle\.js,larger than the 2 MB' '' dryrun=1 "scandirectory=$BIGJS"
sig_check "oversized php is ERROR"          2 'ERROR,FILE_TOO_LARGE,.*padded\.php,.*review it by hand' '' dryrun=1 "scandirectory=$BIGPHP"
sig_check "oversized json event"            2 '"type":"FILE_TOO_LARGE"' '' dryrun=1 format=json "scandirectory=$BIGPHP"
if [ -r "$UNREAD/locked.php" ]; then
    SKIP=$((SKIP+1)); echo "SKIP  unreadable file case (running as root: chmod 000 does not stop reads)"
else
    sig_check "unreadable file is ERROR"    2 'ERROR,FILE_UNREADABLE,.*locked\.php' 'dangling' dryrun=1 "scandirectory=$UNREAD"
fi
chmod 644 "$UNREAD/locked.php"

###############
# A regex the engine gives up on is a finding, never a silent "no match"
# (new rule, no old-script counterpart): a custom signature that backtracks
# without end on one file reports SIGNATURE_ERROR (exit 2). A 540 KB
# one-line chr() chain, which ran the PCRE JIT stack out under the first
# version of php_chr_chain, is detected with no engine error.
##############
REGEX="$WORK/regex-limit"; LONGCHR="$WORK/long-chr"
mkdir -p "$REGEX" "$LONGCHR"
{ printf '<?php // backtrack_me\n$s = "'; head -c 30000 /dev/zero | tr '\0' 'a'; printf '";\n'; } > "$REGEX/heavy.php"
cat > "$WORK/sigs-heavy.json" <<'JSON'
{"elderward_signatures":1,"signatures":[{"id":"heavy","target":"file","severity":"LOW","description":"backtracks","match":[{"string":"backtrack_me"},{"regex":"/(?:a+)+$/"}]}]}
JSON
php -r 'echo "<?php\n\$x = " . str_repeat("chr(101).", 60000) . "chr(59);\n";' > "$LONGCHR/one-line.php"
sig_check "regex engine error is ERROR"     2 'ERROR,SIGNATURE_ERROR,.*heavy\.php,.*custom\.heavy' 'SIGNATURE_MATCH' dryrun=1 "signatures=$WORK/sigs-heavy.json" "scandirectory=$REGEX"
sig_check "regex engine error json event"   2 '"type":"SIGNATURE_ERROR"' '' dryrun=1 format=json "signatures=$WORK/sigs-heavy.json" "scandirectory=$REGEX"
sig_check "long one-line chr chain"         2 'MALWARE_FOUND,.*one-line\.php,php_chr_chain' 'SIGNATURE_ERROR' dryrun=1 "scandirectory=$LONGCHR"
# The WordPress-guard check of the looser upload rule reads the whole file:
# a 1.9 MB file with the uploader at the very end must still be caught.
BIGUP="$WORK/big-upload"; mkdir -p "$BIGUP"
php -r '$c = "\$a = \$_POST[\"x\"]; if (\$f) { \$g(\$h); } // note\n"; echo "<?php\n", str_repeat($c, (int) (1900000 / strlen($c))), "move_uploaded_file(\$_FILES[\"f\"][\"tmp_name\"], \$d . basename(\$_FILES[\"f\"][\"name\"]));\n";' > "$BIGUP/big.php"
sig_check "uploader at the end of 1.9 MB"   3 'MALWARE_FOUND,.*big\.php,php_upload_client_name' 'SIGNATURE_ERROR' dryrun=1 "scandirectory=$BIGUP"

###############
# Built-in detection signatures (new set, no old-script counterpart). The
# fixtures in tests/fixtures/detection are stored as .txt so a git checkout
# of the plugin never holds a reachable .php backdoor; they get their real
# extension in the work dir. pos--RULE[--variant].EXT must report exactly
# MALWARE_FOUND for RULE, neg--* (clean code shaped like a rule, mostly
# taken from false positives seen on real plugins) must report nothing, every
# rule must have a positive, and a real (non-dry) run must change nothing.
##############
DET="$WORK/detect"
mkdir -p "$DET"
for f in "$REPO"/tests/fixtures/detection/*.txt; do cp "$f" "$DET/$(basename "$f" .txt)"; done
det_before="$(cd "$DET" && cat -- * | shasum)"
det_out="$(cd "$WORK" && php "$NEW" dryrun=1 noselfcheck=1 "scandirectory=$DET" 2>/dev/null)"
det_fail=""; det_pos=0; det_neg=0
for f in "$DET"/pos--*; do
    b="$(basename "$f")"; rule="${b#pos--}"; rule="${rule%%.*}"; rule="${rule%%--*}"; det_pos=$((det_pos+1))
    printf '%s\n' "$det_out" | grep -qF ",MALWARE_FOUND,$DET/$b,$rule: " || det_fail="$det_fail $b"
done
for f in "$DET"/neg--*; do
    b="$(basename "$f")"; det_neg=$((det_neg+1))
    printf '%s\n' "$det_out" | grep -qF "$DET/$b," && det_fail="$det_fail $b"
done
if [ -z "$det_fail" ]; then
    PASS=$((PASS+1)); echo "PASS  detection fixtures: $det_pos positives reported, $det_neg negatives quiet"
else
    FAIL=$((FAIL+1)); echo "FAIL  detection fixtures:$det_fail"; printf '%s\n' "$det_out" | grep MALWARE_FOUND | head -40
fi
det_missing=""
for rule in $(php -r 'require $argv[1] . "/includes/engine/load.php"; echo implode(" ", array_keys(Elderward\Engine\Signatures::builtin_detection()));' "$REPO"); do
    found=0
    for x in "$DET"/pos--"$rule".* "$DET"/pos--"$rule"--*; do [ -e "$x" ] && found=1; done
    [ "$found" = 1 ] || det_missing="$det_missing $rule"
done
if [ -z "$det_missing" ]; then
    PASS=$((PASS+1)); echo "PASS  every detection signature has a positive fixture"
else
    FAIL=$((FAIL+1)); echo "FAIL  detection signatures without a positive fixture:$det_missing"
fi
if printf '%s\n' "$det_out" | grep -qF "pos--php_variable_function_name--split.php,php_variable_function_name: " \
   && printf '%s\n' "$det_out" | grep -F "pos--php_variable_function_name--split.php," | grep -q 'after joining split strings'; then
    PASS=$((PASS+1)); echo "PASS  split strings are joined for the second look"
else
    FAIL=$((FAIL+1)); echo "FAIL  the split-string fixture was not caught by the second look"
fi
(cd "$WORK" && php "$NEW" noselfcheck=1 "scandirectory=$DET" >/dev/null 2>&1)
if [ "$det_before" == "$(cd "$DET" && cat -- * | shasum)" ]; then
    PASS=$((PASS+1)); echo "PASS  detection signatures never modify files (real run)"
else
    FAIL=$((FAIL+1)); echo "FAIL  a real run modified a detection fixture"
fi

###############
# Restore safety (new rules, no old-script counterpart): a verified package
# whose subfolder is a symlink to somewhere else must not have a file
# restored through it, and a version header that is not a plain version
# string gives the package no reference instead of a file name.
##############
RWP="$WORK/restore-wp"
ROUT="$WORK/restore-outside"
RSUMS="$WORK/restore-sums"
mkdir -p "$RWP/wp-includes" "$RWP/wp-content/plugins/hello-dolly" "$RWP/wp-content/plugins/evil" "$ROUT" "$RSUMS"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$RWP/wp-includes/version.php"
printf '<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n' > "$RWP/wp-content/plugins/hello-dolly/hello.php"
printf '<?php\n/*\nPlugin Name: Evil\nVersion: ../../x\n*/\n' > "$RWP/wp-content/plugins/evil/evil.php"
ln -s "$ROUT" "$RWP/wp-content/plugins/hello-dolly/sub"
php -r '
$wp = $argv[1]; $sums = $argv[2];
$extra = "<?php // pristine extra file";
$hello = md5_file($wp . "/wp-content/plugins/hello-dolly/hello.php");
file_put_contents($sums . "/plugin-hello-dolly-1.7.2.json", json_encode(array("files" => array("hello.php" => array("md5" => $hello), "sub/extra.php" => array("md5" => md5($extra))))));
$zip = new ZipArchive(); $zip->open($sums . "/plugin-hello-dolly-1.7.2.zip", ZipArchive::CREATE); $zip->addFromString("hello-dolly/sub/extra.php", $extra); $zip->close();
' "$RWP" "$RSUMS"
sig_check "restore through symlink refused"  2 'RESTORE_FAILED.*resolves outside the package' 'INTEGRITY_RESTORED' scanintegrity=1 restore=1 "checksumdir=$RSUMS" "scandirectory=$RWP"
if [ -z "$(ls -A "$ROUT")" ]; then
    PASS=$((PASS+1)); echo "PASS  restore wrote nothing outside the package"
else
    FAIL=$((FAIL+1)); echo "FAIL  restore wrote outside the package:"; ls -la "$ROUT"
fi
sig_check "traversal version gets no reference" 2 'plugin evil: could not determine the installed version' 'plugin evil \.\.' scanintegrity=1 "checksumdir=$RSUMS" "scandirectory=$RWP"

# Positive control for the same rules: a modified file and a file missing
# from a folder that does not exist yet are both restored, the original is
# quarantined into a quarantine folder created on the fly, and a plugins
# folder that is itself a symlink (Composer/Bedrock layouts) is accepted.
PWP="$WORK/positive-wp"
PREAL="$WORK/positive-real-plugins"
PSUMS="$WORK/positive-sums"
mkdir -p "$PWP/wp-includes" "$PWP/wp-content" "$PREAL/hello-dolly/inc" "$PSUMS"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$PWP/wp-includes/version.php"
ln -s "$PREAL" "$PWP/wp-content/plugins"
php -r '
$real = $argv[1]; $sums = $argv[2];
$pristine = "<?php /* Plugin Name: Hello Dolly\nVersion: 1.7.2 */ echo 1;";
$inc = "<?php // pristine inc file";
$new = "<?php // pristine file in a new folder";
file_put_contents($real . "/hello-dolly/hello.php", $pristine);
file_put_contents($real . "/hello-dolly/inc/a.php", $inc . "\n// tampered");
file_put_contents($sums . "/plugin-hello-dolly-1.7.2.json", json_encode(array("files" => array("hello.php" => array("md5" => md5($pristine)), "inc/a.php" => array("md5" => md5($inc)), "deep/er/new.php" => array("md5" => md5($new))))));
$zip = new ZipArchive(); $zip->open($sums . "/plugin-hello-dolly-1.7.2.zip", ZipArchive::CREATE);
$zip->addFromString("hello-dolly/hello.php", $pristine); $zip->addFromString("hello-dolly/inc/a.php", $inc); $zip->addFromString("hello-dolly/deep/er/new.php", $new); $zip->close();
' "$PREAL" "$PSUMS"
sig_check "restore modified file (symlinked plugins)" 3 'INTEGRITY_RESTORED.*inc/a\.php' 'RESTORE_FAILED' scanintegrity=1 restore=1 "quarantinedir=$WORK/positive-quarantine" "checksumdir=$PSUMS" "scandirectory=$PWP"
if [ -f "$WORK/positive-quarantine/plugin-hello-dolly-1.7.2/inc/a.php.quarantine" ] && [ -f "$PREAL/hello-dolly/deep/er/new.php" ]; then
    PASS=$((PASS+1)); echo "PASS  restore quarantined the original and created the missing file"
else
    FAIL=$((FAIL+1)); echo "FAIL  restore left no quarantine copy or no new file"
fi
sig_check "rescan after restore is clean"      0 'Integrity scan complete: 0 modified, 0 missing' 'INTEGRITY_M' scanintegrity=1 "checksumdir=$PSUMS" "scandirectory=$PWP"

###############
# Cleanup safety (new rules, no old-script counterpart): a removal starts at
# the campaign's own marker and stops at the end of that injection, so the
# legitimate code around it survives byte for byte, and a symbolic link is
# reported instead of being replaced by a regular file.
##############
CSITE="$WORK/cleanup-site"
CLINK="$WORK/cleanup-linked"
mkdir -p "$CSITE/js" "$CLINK"
C_LEGIT='!function(){var a=1;if(typeof jQuery==="undefined"){throw new Error("needs jQuery")}window.lib={init:function(){return a}};}();'
C_WQPQ=';if(typeof wqpq==="undefined"){(function(q,f){try{var c=-parseInt(Z(0x12, x9))/0x1;}catch(e){}}(a,b));var wqpq=true;(function(){if(1){x();}}());};'
C_NDSW='if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};'
# A one-line minified file with its own typeof guard, injection appended.
printf '%s%s\n' "$C_LEGIT" "$C_WQPQ" > "$CSITE/js/lib.min.js"
# The same file injected twice, legitimate code between the two.
printf 'var first=1;\n%s\nvar between=2;\n%s\nvar last=3;\n' "$C_NDSW" "$C_NDSW" > "$CSITE/js/twice-ndsw.js"
printf '%s%svar between=2;%s\n' "$C_LEGIT" "$C_WQPQ" "$C_WQPQ" > "$CSITE/js/twice-wqpq.js"
printf 'var linked=1;\n%s\n' "$C_NDSW" > "$CLINK/shared.js"
ln -s "$CLINK/shared.js" "$CSITE/js/linked.js"
linked_before="$(sha256sum "$CLINK/shared.js")"
sig_check "cleanup: dry run names the symlink" 3 'MALWARE_FOUND.*linked\.js.*symbolic link.*never modified' 'MALWARE_CLEANED\|linked\.js.*dry run' dryrun=1 "scandirectory=$CSITE"
sig_check "cleanup: dry run lists the others"  3 'MALWARE_FOUND.*lib\.min\.js.*dry run' 'MALWARE_CLEANED' dryrun=1 "scandirectory=$CSITE"
sig_check "cleanup: symlink reported, kept"    3 'MALWARE_FOUND.*linked\.js.*symbolic link.*never modified' 'MALWARE_CLEANED.*linked\.js' "scandirectory=$CSITE"
if [ "$(cat "$CSITE/js/lib.min.js")" == "$C_LEGIT;" ] \
    && [ "$(cat "$CSITE/js/twice-ndsw.js")" == "$(printf 'var first=1;\n\nvar between=2;\n\nvar last=3;')" ] \
    && [ "$(cat "$CSITE/js/twice-wqpq.js")" == "$C_LEGIT;var between=2;;" ]; then
    PASS=$((PASS+1)); echo "PASS  cleanup kept the legitimate code around and between injections"
else
    FAIL=$((FAIL+1)); echo "FAIL  cleanup changed legitimate code:"; head -c 400 "$CSITE/js/lib.min.js" "$CSITE/js/twice-ndsw.js" "$CSITE/js/twice-wqpq.js"
fi
if [ -L "$CSITE/js/linked.js" ] && [ "$linked_before" == "$(sha256sum "$CLINK/shared.js")" ]; then
    PASS=$((PASS+1)); echo "PASS  cleanup left the symbolic link and its target alone"
else
    FAIL=$((FAIL+1)); echo "FAIL  cleanup replaced the symbolic link or wrote through it"
fi
sig_check "cleanup: rescan finds only the link" 3 'MALWARE_FOUND.*linked\.js' 'lib\.min\.js\|twice-' dryrun=1 "scandirectory=$CSITE"
sig_check "cleanup: the link target is cleaned" 3 'MALWARE_CLEANED.*shared\.js' 'CLEANUP_FAILED' "scandirectory=$CLINK"

###############
# "Clean" must mean "looked" (new rules, no old-script counterpart).
#
# The tool uploaded next to the site (bin/ and includes/ in the home folder,
# the site in public_html below it) would skip every file as its own: that
# is refused with the way out, and works once the tool has its own folder.
##############
check() {
    local name="$1" want_rc="$2" want="$3" refuse="$4" rc="$5" out="$6"
    if [ "$rc" == "$want_rc" ] && printf '%s' "$out" | grep -q -- "$want" && { [ -z "$refuse" ] || ! printf '%s' "$out" | grep -q -- "$refuse"; }; then
        PASS=$((PASS+1)); printf 'PASS  %-39s exit=%s\n' "$name" "$rc"
    else
        FAIL=$((FAIL+1)); printf 'FAIL  %-39s exit=%s (want %s)\n' "$name" "$rc" "$want_rc"; printf '%s\n' "$out" | head -10
    fi
}
LOOSE="$WORK/loose-home"
mkdir -p "$LOOSE/public_html" "$LOOSE/bin" "$LOOSE/includes"
cp "$REPO/bin/elderward.php" "$LOOSE/bin/"; cp -r "$REPO/includes/engine" "$LOOSE/includes/engine"
printf '%s\n' "$C_NDSW" > "$LOOSE/public_html/bad.js"
out="$(cd "$WORK" && php "$LOOSE/bin/elderward.php" dryrun=1 "scandirectory=$LOOSE/public_html" 2>/dev/null)"; rc=$?
check "tool beside the site is refused"     1 'inside the folder Elderward runs from' 'MALWARE_' "$rc" "$out"
out="$(cd "$LOOSE" && php "$LOOSE/bin/elderward.php" dryrun=1 2>/dev/null)"; rc=$?
check "tool folder as scan folder refused"  1 'inside the folder Elderward runs from' 'MALWARE_' "$rc" "$out"
mkdir "$LOOSE/elderward"; mv "$LOOSE/bin" "$LOOSE/includes" "$LOOSE/elderward/"
out="$(cd "$WORK" && php "$LOOSE/elderward/bin/elderward.php" dryrun=1 "scandirectory=$LOOSE/public_html" 2>/dev/null)"; rc=$?
check "tool in its own folder scans"        3 'MALWARE_FOUND,.*public_html/bad\.js' '' "$rc" "$out"

###############
# A symbolic link to a folder is followed by report-only runs (a linked
# uploads folder would otherwise hide everything in it), never back up the
# tree, to the filesystem root or twice; a run that can modify files does
# not follow it and says so.
##############
LWP="$WORK/link-wp"; LEXT="$WORK/link-shared-uploads"
mkdir -p "$LWP/wp-includes" "$LWP/wp-content/plugins" "$LEXT/2026"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$LWP/wp-includes/version.php"
printf '<?php echo 1;\n' > "$LEXT/2026/shell.php"
printf '%s\n' "$C_NDSW" > "$LEXT/2026/bad.js"
ln -s "$LEXT" "$LWP/wp-content/uploads"
ln -s "$LWP" "$LEXT/back-to-site"
ln -s / "$LEXT/to-fs-root"
ln -s .. "$LEXT/2026/parent"
sig_check "quickscan follows linked uploads"   3 'HIGH,UPLOADS_PHP,.*wp-content/uploads/2026/shell\.php' 'back-to-site/\|to-fs-root/\|parent/' quickscan=1 "scandirectory=$LWP"
sig_check "signatures follow linked uploads"   3 'MALWARE_FOUND,.*wp-content/uploads/2026/bad\.js' 'back-to-site/\|to-fs-root/\|parent/' dryrun=1 "scandirectory=$LWP"
# A second link to the same folder: whichever is listed first is followed.
ln -s "$LEXT/2026" "$LWP/wp-content/again"
link_hits="$(cd "$WORK" && php "$NEW" dryrun=1 noselfcheck=1 "scandirectory=$LWP" 2>/dev/null | grep -c 'bad\.js')"
if [ "$link_hits" = 1 ]; then
    PASS=$((PASS+1)); echo "PASS  a folder reached through two links is read once"
else
    FAIL=$((FAIL+1)); echo "FAIL  the linked file was reported $link_hits times"
fi
link_before="$(sha256sum "$LEXT/2026/bad.js")"
rm "$LWP/wp-content/again"
sig_check "cleanup does not follow the link"   2 'ERROR,SYMLINK_NOT_FOLLOWED,.*wp-content/uploads,.*NOT checked for malware signatures' 'MALWARE_' "scandirectory=$LWP"
if [ "$link_before" == "$(sha256sum "$LEXT/2026/bad.js")" ]; then
    PASS=$((PASS+1)); echo "PASS  cleanup left the file behind the link alone"
else
    FAIL=$((FAIL+1)); echo "FAIL  cleanup wrote through a linked folder"
fi

###############
# A folder that cannot be listed is an ERROR finding: it used to stop the
# quick scan with an uncaught exception at the top level and to be skipped
# without a word further down.
##############
UWP="$WORK/unlistable-wp"
mkdir -p "$UWP/wp-includes/locked" "$UWP/wp-content/uploads" "$UWP/lost+found" "$UWP/wp-content/cache/deep"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$UWP/wp-includes/version.php"
chmod 000 "$UWP/lost+found" "$UWP/wp-content/cache/deep" "$UWP/wp-includes/locked"
if [ -r "$UWP/lost+found" ]; then
    SKIP=$((SKIP+1)); echo "SKIP  unlistable folder cases (running as root: chmod 000 does not stop reads)"
else
    sig_check "quickscan: unlistable top folder"   2 'ERROR,FILE_UNREADABLE,.*/lost+found,cannot list the folder' 'Uncaught' quickscan=1 "scandirectory=$UWP"
    sig_check "quickscan: unlistable nested one"   2 'ERROR,FILE_UNREADABLE,.*/cache/deep,cannot list the folder' '' quickscan=1 "scandirectory=$UWP"
    sig_check "signatures: unlistable folders"     2 'ERROR,FILE_UNREADABLE,.*/cache/deep,cannot list the folder.*NOT checked for malware signatures' '' dryrun=1 "scandirectory=$UWP"
    sig_check "scantimes: unlistable core folder"  2 'ERROR,FILE_UNREADABLE,.*/wp-includes/locked,cannot list the folder' '' scantimes=1 "scandirectory=$UWP"
fi
chmod 755 "$UWP/lost+found" "$UWP/wp-content/cache/deep" "$UWP/wp-includes/locked"

###############
# A finding with bytes that are not valid UTF-8 is still one JSON event per
# line (it used to print an empty line): a log line here, and a file name
# where the filesystem accepts one.
##############
ULOG="$WORK/utf8-logs"; mkdir -p "$ULOG"
printf '203.0.113.5 - - [20/Sep/2026:10:05:01 +0000] "POST /wp-content/uploads/2026/09/caf\xe9-cache.php HTTP/1.1" 200 312 "-" "python-requests/2.31"\n' > "$ULOG/access.log"
json_events() {
    php -r '$n = 0; foreach (file("php://stdin") as $l) { $e = json_decode($l, true); if (!is_array($e) || !isset($e["event"])) { exit(1); } if ("finding" === $e["event"]) { $n++; } } exit($n > 0 ? 0 : 1);'
}
if (cd "$WORK" && php "$NEW" "scanlog=$ULOG/access.log" format=json noselfcheck=1 2>/dev/null) | json_events; then
    PASS=$((PASS+1)); echo "PASS  invalid UTF-8 in a log line is still a JSON finding"
else
    FAIL=$((FAIL+1)); echo "FAIL  invalid UTF-8 in a log line broke the JSON output"
fi
UNAME="$WORK/utf8-names"; mkdir -p "$UNAME"
if { printf '%s\n' "$C_NDSW" > "$UNAME/$(printf 'bad\xff').js"; } 2>/dev/null; then
    if (cd "$WORK" && php "$NEW" dryrun=1 format=json noselfcheck=1 "scandirectory=$UNAME" 2>/dev/null) | json_events; then
        PASS=$((PASS+1)); echo "PASS  invalid UTF-8 in a file name is still a JSON finding"
    else
        FAIL=$((FAIL+1)); echo "FAIL  invalid UTF-8 in a file name broke the JSON output"
    fi
else
    SKIP=$((SKIP+1)); echo "SKIP  invalid UTF-8 file name (this filesystem refuses the name)"
fi

###############
# A reference that should have been there and could not be used is an
# ERROR (the package was not verified); one that is simply not in
# checksumdir= stays INFO, which the old-vs-new cases above cover.
##############
BADSUMS="$WORK/bad-sums"; mkdir -p "$BADSUMS"
printf 'not json' > "$BADSUMS/core-6.5.2.json"
printf '{"files":false}' > "$BADSUMS/plugin-hello-dolly-1.7.2.json"
sig_check "broken core manifest is ERROR"      2 'ERROR,INTEGRITY_NO_REFERENCE,.*core 6\.5\.2 (en_US): no reference checksums available (error) - core files were NOT verified' '' scanintegrity=1 "checksumdir=$BADSUMS" "scandirectory=$WP"
sig_check "broken plugin manifest is ERROR"    2 'ERROR,INTEGRITY_NO_REFERENCE,.*plugin hello-dolly 1\.7\.2: could not fetch reference checksums - its files were NOT verified' '' scanintegrity=1 "checksumdir=$BADSUMS" "scandirectory=$WP"

###############
# The core locale comes from the install itself: a localized package says
# so in wp-includes/version.php, and its translated core files only match
# that locale's checksums. locale= still wins, and a value that does not
# look like a locale is not used.
##############
LOCWP="$WORK/locale-wp"; LOCSUMS="$WORK/locale-sums"
mkdir -p "$LOCWP/wp-includes" "$LOCWP/wp-content" "$LOCSUMS"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n$wp_local_package = '"'"'pt_BR'"'"';\n' > "$LOCWP/wp-includes/version.php"
php -r 'file_put_contents($argv[2] . "/core-6.5.2.json", json_encode(array("checksums" => array("wp-includes/version.php" => md5_file($argv[1] . "/wp-includes/version.php")))));' "$LOCWP" "$LOCSUMS"
sig_check "core locale read from version.php"  0 'Checking core 6\.5\.2 pt_BR (1 files)' 'INTEGRITY_M' scanintegrity=1 "checksumdir=$LOCSUMS" "scandirectory=$LOCWP"
sig_check "locale= option wins"                0 'Checking core 6\.5\.2 (1 files)' 'pt_BR' scanintegrity=1 locale=en_US "checksumdir=$LOCSUMS" "scandirectory=$LOCWP"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n$wp_local_package = '"'"'../../x'"'"';\n' > "$LOCWP/wp-includes/version.php"
sig_check "odd locale value is not used"       3 'Checking core 6\.5\.2 (1 files)' '\.\./\.\./x' scanintegrity=1 "checksumdir=$LOCSUMS" "scandirectory=$LOCWP"

###############
# A multisite network is recognised from wp-config.php (the database scan
# then reads every site listed in {prefix}blogs; that needs a real
# network, TESTPLAN E5). A commented-out define does not count.
##############
MSITE="$WORK/multisite-config"; mkdir -p "$MSITE/on" "$MSITE/off"
MS_BASE='<?php
define("DB_NAME", "wp"); define("DB_USER", "u"); define("DB_PASSWORD", "p"); define("DB_HOST", "localhost");
$table_prefix = "wp_";
'
printf '%s%s\n' "$MS_BASE" "define( 'MULTISITE', true );" > "$MSITE/on/wp-config.php"
printf '%s%s\n' "$MS_BASE" "// define( 'MULTISITE', true );
define( 'WP_ALLOW_MULTISITE', true );" > "$MSITE/off/wp-config.php"
ms_flag() { php -r 'require $argv[1] . "/includes/engine/load.php"; $c = Elderward\Engine\MysqliDb::parse_wp_config($argv[2]); echo (is_array($c) && $c["multisite"]) ? "yes" : "no";' "$REPO" "$1"; }
if [ "$(ms_flag "$MSITE/on")" = yes ] && [ "$(ms_flag "$MSITE/off")" = no ]; then
    PASS=$((PASS+1)); echo "PASS  multisite is read from wp-config.php"
else
    FAIL=$((FAIL+1)); echo "FAIL  multisite detection: on=$(ms_flag "$MSITE/on") off=$(ms_flag "$MSITE/off")"
fi

echo
echo "passed=$PASS failed=$FAIL skipped=$SKIP  (work dir: $WORK)"
[ "$FAIL" = 0 ]
