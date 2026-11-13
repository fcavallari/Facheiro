# What to review that the tools do not

`CLAUDE.md` is the source of the rules. This page does not repeat them: it
says where to look for each kind of change and which follow-through steps
are easy to forget. Read the `CLAUDE.md` sections named here before judging
the code.

## Contents

- Which rules apply to which files
- Questions to ask of every change
- Follow-through that travels with a change
- Security
- What phpcs already covers
- Commit message

## Which rules apply to which files

| Files | Rules | `CLAUDE.md` section |
|---|---|---|
| `includes/engine/`, `bin/` | PHP 5.6 syntax, no WordPress functions, output only through the Reporter, Scanner/Layout/TreeWalk/adapter contracts | Engine contracts |
| `includes/plugin/`, `facheiro.php`, `uninstall.php` | WordPress.org rules: prefixes, capability and nonce, escaping, `$wpdb->prepare()`, translations, report-only admin | Plugin side rules |
| `recovery.php`, `includes/recovery/` | no WordPress, own escaping and tokens, inert without a key | Invariants (recovery mode), Plugin side rules |
| everything | the invariants | Invariants |
| everything | code style | Style |

## Questions to ask of every change

Read enough of the surrounding file to answer these. A finding needs a file
and line, and a reason taken from the code or from `CLAUDE.md`.

1. **Does it fit the code around it?** Look at how the neighbouring
   functions do the same job (the sibling ajax handlers, the other scanners,
   the other queries). A change that does by hand what a helper already does
   (`Layout`, `TreeWalk`, `is_php_file()`, `resolve_log_path()`,
   `read_site_file()`, `require_access()`, `Facheiro_Seal::update()`) is the
   most common way a rule gets broken here.
2. **Is the new behaviour tested, and does the test test it?** New engine
   behaviour needs a case in `tests/regress.sh` and an entry in
   `TESTPLAN.md`; a scanner needs a positive case and its false-positive
   negatives. Check that the test would fail without the change: a case that
   only asserts the exit code, or matches text the old code also printed,
   proves nothing.
3. **What happens when something is missing or fails?** An unreadable file,
   a failed query, a missing extension, an empty or huge input, a time limit.
   In this repository a blocked check must become an `ERROR` finding, and
   only `preg_match(...) === 1` counts as a match. A silent `return`, an
   empty `catch` or an `@` with no handling on the next line is a finding.
4. **Could it write, delete or send anything?** Every write must be covered
   by `dryrun`; the admin page and the assistant tools are report-only;
   nothing leaves the site on its own.
5. **Does it change something others depend on?** The text and JSON output,
   exit codes, finding types and summary keys, option names, CLI arguments,
   the findings table, saved options, hooks, ability names. `tests/regress.sh`
   protects the output contract: a change there must be deliberate and
   written up in `README.md`.

## Follow-through that travels with a change

Check each from the diff. Most are in the "must fix" group when missing,
because the repository's own checks or its users break without them.

| If the diff | It must also | How to tell |
|---|---|---|
| changes any tracked file, or adds a file git does not ignore | regenerate `checksums.json` in the same commit | `tests/checksums.sh` |
| adds or changes an admin string (written in Portuguese) | update `languages/facheiro.pot`, the en_US `.po` with its English translation, `.mo`, `.l10n.php` | the string appears in the `.pot` and `.po` |
| adds a recovery-page string (written in Portuguese) | add its English line in `includes/recovery/i18n/en.php` with the same placeholders | grep the file |
| adds a finding type, option or command | document it in `README.md` (and `readme.txt` when users see it), add it to `TESTPLAN.md` | grep the docs for the new name |
| adds a finding type for files | consider `Facheiro_False_Positives` (file types that bind to a SHA-256) | read that class |
| adds a detection signature | add a positive fixture in `tests/fixtures/detection/` as `.txt`, plus negatives | list the folder |
| adds a tracked development file or folder | keep `.distignore`, `.gitattributes` and `SelfCheckScanner::$dev_only` in step | `tests/checksums.sh`, read the three |
| bumps the version | change `readme.txt` Stable tag, the `Version:` header and `FACHEIRO_VERSION` together | grep all three |
| changes an engine contract or adds a class | update the matching paragraph of `CLAUDE.md` | read it |
| adds an outbound request, a filesystem write or a shell call | disclose it in `readme.txt` and give the `phpcs:ignore` its reason | read `readme.txt` |

## Security

This tool runs on sites that are already compromised, so everything read
from the site (file names, file contents, log lines, database values, API
responses) is written by the attacker. Look at each new place where such
data, or request data, ends up:

- **In a database query**: every value through `$wpdb->prepare()`; engine
  queries are fixed SQL. `sanitize_text_field()` does not make a value safe
  for SQL.
- **In HTML or JavaScript**: escaped on output in PHP (`esc_html()` and
  friends, `App::h()` on the recovery page); in JavaScript, `textContent` or
  text nodes, never `innerHTML` with data.
- **In a file path**: `realpath()` and containment as the rules require; no
  `wp-config*`; symlinks refused where a write follows.
- **In a shell command, `include`, `unserialize()`, `eval`, a regex pattern,
  a URL or a file name**: the engine avoids all of these with outside data.
- **In an action**: capability check (`Facheiro_Plugin::can_manage()`) and a
  nonce on every ajax and admin-post handler; a nonce is not a permission
  check. Recovery actions need the session token.
- **In a log, an export or an assistant's output**: no secrets, no
  `wp-config` contents, no recovery key; assistant output with scanned data
  carries `untrusted_data_notice`.
- **Secrets in code**: keys, tokens, passwords, private URLs in the diff,
  including tests and fixtures.

Treat every `phpcs:ignore` and `phpcs:disable` the diff adds as a claim to
check, not as a clearance: read the code under it and decide whether the
stated reason is true. A file-wide `phpcs:disable` in a plugin-side file is
against the repository's rules.

## What phpcs already covers

Do not write findings for these unless phpcs could not run, or a
`phpcs:ignore` hides one: unescaped output, unsanitised or unvalidated
request data, missing nonce verification, SQL built without `prepare()`,
unprefixed globals, discouraged and development functions, PHP newer than
5.6 in the engine, CLI and recovery page. Report what phpcs said instead.

Formatting is deliberately not enforced. Do not report spacing, brace or
naming style beyond what `CLAUDE.md` (Style) asks for.

## Commit message

Only when the change is already committed. The repository's messages have an
imperative subject that says what changed for the person using the tool, a
body that explains why, a list of what changed, and what it was checked on.
Compare with `git log -5`. A message that differs is a "nice to have",
never a "must fix".
