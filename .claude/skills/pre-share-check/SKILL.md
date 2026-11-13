---
name: pre-share-check
description: Checks the changes on the current branch of the Facheiro repository before they are shared - runs the repository's own checks (php -l, composer phpcs, tests/checksums.sh, tests/regress.sh) on what the diff touches, then reviews the diff against CLAUDE.md for convention, quality and security problems the tools miss, and reports must-fix and nice-to-have findings without changing anything. Use it whenever the user asks to check, review, verify or sanity-check their changes, branch, diff or work in progress before a commit, push, pull request or hand-off ("check my changes", "is this ready to share?", "anything wrong before I open the PR?"), even if they don't name the skill. Not for reviewing someone else's pull request or auditing the whole codebase.
argument-hint: "[base ref, default origin/main]"
context: fork
agent: general-purpose
background: false
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash(git status *)
  - Bash(git diff *)
  - Bash(git log *)
  - Bash(git show *)
  - Bash(git merge-base *)
  - Bash(git rev-parse *)
  - Bash(git ls-files *)
  - Bash(php -l *)
  - Bash(composer phpcs)
  - Bash(php -n vendor/bin/phpcs --standard=phpcs.xml.dist)
---

# Pre-share check

Check the changes in this working tree before the user shares them, and
report what you found. You are running on your own: you cannot see the
conversation that started this, and you cannot ask questions. The report is
the only thing the user gets, so it has to stand by itself.

What the user typed after the skill name, if anything: $ARGUMENTS

Treat that as a base ref or a narrower scope ("only the engine files") when
it reads like one. Ignore it otherwise.

## Ground rules

- **Change nothing.** No edits, no commits, no staging, no stash, no fetch,
  no push, no generated files. The user decides what gets fixed after reading
  the report. Scripts that rewrite files are listed in
  `${CLAUDE_SKILL_DIR}/references/checks.md` under "Never run these";
  a command you are unsure about is one you do not run.
- **Say nothing outside this session.** Findings go in your final message and
  nowhere else: no pull request or issue comments, no `gh`, no chat or
  tracker tools, no published pages, no files in the repository. A security
  finding written anywhere public tells attackers where to look before it is
  fixed. If a finding involves a secret, name the file and line, not the
  value.
- **Run every command as its own visible step, typed exactly as written
  here.** One check per command, with nothing added: no `; echo "exit=$?"`,
  no pipe into `tail` or `grep`, no `cd` in front, no two checks joined. The
  tool already returns the exit code and the output. The read-only commands
  are approved in advance by their exact text, so a changed command is
  refused or stops to ask the user, and a piped one hides what ran.
- **Search and read with the Grep, Glob and Read tools**, not with
  `git grep`, `cat`, `find` or `sed`.
- **Stay inside the diff.** The rest of the repository is context for
  understanding the change, not something to review.

## 1. Find what changed

Run these and read the output:

```
git status --porcelain
git rev-parse --abbrev-ref HEAD
git merge-base HEAD origin/main
git diff --stat <merge-base>
git diff <merge-base>
git log --format='%h %s%n%b' <merge-base>..HEAD
```

- Use the base ref from the arguments instead of `origin/main` when one was
  given.
- `git diff <merge-base>` covers committed and uncommitted changes to tracked
  files. It does not show untracked files: take those from
  `git status --porcelain` and read them. They are part of the change.
- Do not `git fetch`. If `origin/main` looks old (the branch has dozens of
  commits the user clearly did not write), say so in the report rather than
  updating it.
- If nothing differs from the base and nothing is untracked, stop and report
  "Nothing to check: this branch has no changes against <base>". Do not
  review the repository instead.
- If the diff is very large (several thousand lines), run the checks on all
  of it, review the files with logic first, and say which files you only
  skimmed.

## 2. Run the repository's checks

Read `${CLAUDE_SKILL_DIR}/references/checks.md`. It maps what the diff
touches to the checks to run, gives the exact commands, lists what must
never be run, and lists the checks that need a WordPress site and so cannot
run here.

For each check, record the command, the exit code and the summary line.
Then sort each failure:

- **From this change**: the message names a changed file and line, or the
  check passes on the base. Must fix.
- **Already there**: it would fail without this change. Mention it once
  under "nice to have"; it is not the user's to fix before sharing.

A check that could not start, was declined, or was skipped is not a pass.
It goes under "Could not check".

## 3. Review what the tools miss

Read `CLAUDE.md` at the repository root first. It is the source of this
repository's rules, and it is detailed. Then read
`${CLAUDE_SKILL_DIR}/references/review-guide.md`, which says which
rules apply to which files, the questions to ask of every change, the
follow-through steps that travel with a change (checksums, translations,
docs, tests), and the security checklist.

Read the changed code with its surroundings: the whole function, the sibling
functions that do the same kind of job, the callers. Most problems here are
a change doing by hand what the code next to it does through a helper.

Do not write findings for things phpcs enforces; report its output instead.
Do not report formatting: this repository does not enforce it.

Prove a finding by reading where you can: the helper that should have been
used, the caller, the `.pot` file a string should be in. Running the CLI with
`dryrun=1` against a scratch folder outside the repository is allowed when
reading cannot settle it, but it is optional: if the command is declined,
mark the finding "Likely", say what you would have run, and move on. Do not
leave scratch files behind. Never prove a security finding against a real
site.

## 4. Decide what each finding is

- **Must fix**: a repository check fails because of this change; a rule in
  `CLAUDE.md` is broken; a bug; a security problem; a missing follow-through
  step that breaks a check or a user (stale `checksums.json`, an untranslated
  admin string, an undocumented change to the output contract); new behaviour
  with no test where the repository has a place for one.
- **Nice to have**: improvements, weaker tests that still test something,
  commit message style, problems that were already there near the change.

Only something this change introduced can be a must fix. A problem that was
already in the code goes under "nice to have" and says so.

For each finding give your confidence:

- **Confirmed**: a check failed, or you ran or traced it and saw it happen.
- **Likely**: the code reads that way and you found nothing that prevents it.
- **Unsure**: it depends on something you could not see or run. Say what.

Give each separate problem its own numbered finding, so the count in the
verdict is honest. When one fix resolves several of them (for example,
"use the existing unit walk instead of a second walker"), say that once at
the top of "Must fix" and keep the findings short.

If the change is clean, say so plainly. Do not pad the report with doubts to
look thorough: an empty "must fix" list is a valid result.

## 5. Report

Write for someone who will act on this without reading anything else. Plain
language, most important first. Use this shape:

```
# Pre-share check: <branch> against <base>

**Verdict:** ready to share / not ready: N things to fix / nothing to check

What was checked: <N files, +A/-D lines, committed and/or uncommitted>.

## Must fix

1. **<What is wrong, in a few words>** - `path/to/file.php:123`
   - What: <what the code does>
   - Why it matters: <what goes wrong, for whom>
   - Confidence: Confirmed / Likely / Unsure - <how you know>
   - Suggested fix: <the change, naming the helper or pattern to use>

## Nice to have

<same shape, shorter>

## Checks run

| Check | Command | Result |
|---|---|---|
| ... | `...` | passed / failed (from this change) / failed (already there) |

## Could not check

- <check>: <why> - run `<command>` <where>.

## Before you share

<the follow-through steps still to do, as commands: regenerate checksums,
refresh translations, ...>

Nothing was changed, committed or posted. Tell me which findings you want
fixed and I will ask before touching anything.
```

Leave out a section that would be empty, except "Must fix" (write "None")
and "Checks run". Keep the last paragraph: whoever relays this report must
not start fixing on their own.

Under "Could not check", list only checks for areas this diff touches and
that did not run here. Leave out environments nobody asked about and
diagnostics you would have liked to run.

If a finding is a possible security vulnerability (it lets someone read,
change or run something they should not, or exposes a secret), put this line
under the verdict. A broken convention or a missing test is not one: "This report contains security findings. Keep it in this session:
do not paste it into a pull request, issue or chat until they are fixed."
