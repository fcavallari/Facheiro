<?php
////////////////
// Facheiro recovery mode.
//
// A page that scans the site WITHOUT loading WordPress, for when WordPress
// itself no longer works (white screen, fatal error, hijacked admin). It is
// inert unless an administrator created a recovery key (Facheiro >
// Recovery, `wp facheiro recovery-key create`, or a key file uploaded by
// hand): without one it answers 404 and does nothing else.
//
// Report-only: it reads files and the database and never changes anything.
//
// This file is meant to be requested directly: that is the whole point of
// a page that works when WordPress does not. What protects it is the key,
// not WordPress. Loaded from inside WordPress it does nothing.
//////////////

if (!defined('ABSPATH')) {
    define('FACHEIRO_RECOVERY_ENTRY', true);
    require __DIR__ . '/includes/recovery/app.php';

    \Facheiro\Recovery\App::run(__DIR__);
}
