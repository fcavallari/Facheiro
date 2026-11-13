# Which checks to run, and how

The commands come from `CLAUDE.md` (Commands), `composer.json` (scripts) and
`README.md` (Development). If one of those files disagrees with this page,
the repository's file wins: say so in the report.

There is no CI and there are no git hooks, so a check that is not run here
has not been run at all.

## Contents

- Run these (read-only)
- Never run these
- Could not check here
- When a command fails to start

## Run these (read-only)

Pick by what the diff touches. Run each as its own command so the user can
see it, and keep the exit code and the last lines of output for the report.

| The diff touches | Run | Passing looks like |
|---|---|---|
| any `.php` file | `php -l <file>` for each changed file | `No syntax errors detected` |
| `elderward.php`, `uninstall.php`, `recovery.php`, `bin/`, `includes/` | `composer phpcs` | exit 0, no output |
| any tracked file, or a new file git does not ignore | `tests/checksums.sh` | `checksums: N passed, 0 failed` |
| `includes/engine/`, `bin/`, `tests/regress.sh`, `tests/fixtures/` | `tests/regress.sh` | `passed=N failed=0` |

Notes:

- `composer phpcs` checks every file `phpcs.xml.dist` lists and takes about a
  second. Run it whole rather than passing changed files: files outside that
  list (`tests/`, `build/`) are deliberately not sniffed, and passing them
  would apply rules the repository does not have. Then sort the output:
  a message in a changed line belongs to this change, anything else was
  already there.
- `php -l` runs on the local PHP (8.x), so it cannot see PHP 5.6 problems in
  the engine. `composer phpcs` is what catches those.
- `tests/regress.sh` takes about ten seconds and prints `SKIP` for the
  database cases when the MariaDB fixture is not running, and for cases the
  filesystem or a root user makes impossible. Report the skips by name: a
  skipped case is a case nobody looked at.
- `tests/regress.sh` and `tests/checksums.sh` run the code in the working
  tree and create scratch folders in the system temp directory. They do not
  change the repository.
- There is no JavaScript linter or test runner for `assets/admin.js` and
  `includes/recovery/app.js`. JavaScript changes are review-only; say so.

## Never run these

They write to the repository, install things, or change a site. When one is
needed, put it in the report as a step for the user.

- `php build/make-checksums.php` (rewrites `checksums.json`, even with
  `--help`)
- `php build/make-zip.php` (writes `dist/`)
- `vendor/bin/phpcbf` (rewrites source files)
- `composer install`, `composer update`, `npm install`
- `wp i18n make-pot`, `update-po`, `make-mo`, `make-php` (rewrite
  `languages/`)
- `git fetch`, `git pull`, `git add`, `git commit`, `git stash`,
  `git checkout`, `git push`, and anything else that changes git state
- `tests/tamper.sh`, the Playwright suites (`tests/*.js`), anything with
  `--restore` or without `dryrun`: these act on a live WordPress site, and
  `tests/recovery.js` breaks and repairs it

## Could not check here

These need a WordPress install, WP-CLI, Playwright or a network, so this
skill does not run them. When the diff touches the area in the left column,
list the check under "Could not check" with the command, so the user can run
it on their test site. Never count them as passed.

| The diff touches | Not checked | Command for the user |
|---|---|---|
| a scanner's `plan()`/`run()` units or state | resumability | `php tests/chunking.php /path/to/wp-root` (must print `IDENTICAL`) |
| `Elderward_Seal`, settings, false positives, signature store | sealed settings | `WP_PATH=... WP_CLI="wp" tests/tamper.sh`, `tests/tamper-ui.js` |
| `Elderward_Admin*`, `assets/admin.js`, `assets/admin.css` | admin pages | the matching Playwright file: `tests/admin-ui.js`, `background-ui.js`, `findings-ui.js`, `signatures-ui.js`, `hardening-ui.js` |
| `recovery.php`, `includes/recovery/` | recovery page | `tests/recovery.js` |
| `Elderward_Abilities` | assistant tools | `tests/mcp-stdio.js` |
| database scan (`includes/engine/database.php`, `db.php`, `Elderward_WP_Db`) | DB cases | `tests/regress.sh` with the MariaDB fixture, `TESTPLAN.md` section E |
| integrity, restore, `Http` | live wordpress.org tests | `TESTPLAN.md` sections B and D |
| any admin-facing string | translation files | the `wp i18n` commands in `README.md`, Translations |
| anything headed for a release | Plugin Check | `php build/make-zip.php`, then Plugin Check on `dist/elderward.zip` (`TESTPLAN.md` F13) |

`TESTPLAN.md` is the full list. Look there when the diff touches something
this table does not name.

## When a command fails to start

A check that did not start has not passed. Work out which of these it is,
and report it.

- **`composer phpcs` says a PHP extension is missing** (`tokenizer`,
  `xmlwriter`, `SimpleXML`, `iconv` or `mbstring`): on some machines an
  extension in the local `php.ini` interferes with how PHP reports the
  others. The error message alone is the trigger; no further diagnosis is
  needed. Run the same check with the ini skipped:

  ```
  php -n vendor/bin/phpcs --standard=phpcs.xml.dist
  ```

  In "Checks run", give one row for phpcs with this command and the note
  "`composer phpcs` did not start here (PHP extension error), ran the same
  check with `php -n`". It is the command behind `composer phpcs`, not a
  different rule set. If this one fails to start too, phpcs could not be
  checked.
- **`vendor/bin/phpcs` does not exist**: phpcs could not be checked. The user
  needs `composer install`.
- **`tests/regress.sh` cannot extract the old script** (`cannot extract ...`):
  the checkout is shallow or the reference commit is missing. Could not check.
- **A permission prompt was declined**: could not check; name the command.
