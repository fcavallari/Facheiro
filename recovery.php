<?php
////////////////
// Elderward recovery mode.
//
// A page that scans the site WITHOUT loading WordPress, for when WordPress
// itself no longer works (white screen, fatal error, hijacked admin). It is
// inert unless an administrator created a recovery key (Elderward >
// Recovery, `wp elderward recovery-key create`, or a key file uploaded by
// hand): without one it answers 404 and does nothing else.
//
// Report-only: it reads files and the database and never changes anything.
//////////////

define('ELDERWARD_RECOVERY_ENTRY', true);
require __DIR__ . '/includes/recovery/app.php';

\Elderward\Recovery\App::run(__DIR__);
