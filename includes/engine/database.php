<?php
namespace Facheiro\Engine;

////////////////
// Database scanning (report-only, SELECT-only)
//
// A large share of WordPress compromises live partly or entirely in the
// database: rogue administrators, script injections in options and posts,
// hijacked siteurl/home. Everything read from the DB is hostile data -
// values are pattern-matched only, NEVER unserialize()d (PHP object
// injection) and never executed.
//
// Units: administrators, options, posts; each carries the primary key it
// resumes after, so a paused unit continues where it stopped.
//
// A multisite network keeps the options and posts of every site in tables
// of their own ({base}{id}_options ...) and one shared users table. There
// the plan is: the network's own settings ({base}sitemeta: super admins,
// network-activated plugins), the main site, and a 'sites' unit that reads
// {base}blogs a batch of ids at a time and queues the same three units for
// each site (they carry 'site' => id), then itself for the next batch. The
// queue therefore never holds more than one batch, however many sites the
// network has.
//////////////

// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- an exception message is data, not output: the entry layer that catches it (CLI, WP-CLI, admin page, recovery page) escapes it for the place it shows it.

class DatabaseScanner extends Scanner
{
    // An administrator registered this recently on a compromised site is the
    // classic takeover artifact.
    const RECENT_ADMIN_DAYS = 30;
    // Only the first 256KB of a value is scanned, so a giant transient or post
    // cannot balloon memory.
    const VALUE_SCAN_CAP = 262144;
    // Capabilities that amount to site takeover. A role other than
    // administrator holding one of them is how an attacker keeps a
    // low-profile account powerful. unfiltered_html is left out: editors hold
    // it by default on single-site installs.
    const ADMIN_CAPS = 'manage_options|edit_users|create_users|promote_users|delete_users|edit_files|edit_plugins|edit_themes|install_plugins|install_themes|update_core|activate_plugins|switch_themes';
    // Per site on a network: one spam-filled site must not use up the
    // listing for the others.
    const MAX_REPORTED_POSTS = 100;
    // Sites queued per 'sites' unit.
    const SITE_BATCH = 25;
    // Logins of the super admin list that are followed one by one.
    const MAX_SUPER_ADMINS = 200;

    private $fatal_on_error;
    private $connected = false;
    // Set by iterate(): the last query failed (and was reported).
    private $failed = false;

    public function __construct(Context $ctx, $fatal_on_error)
    {
        parent::__construct($ctx);
        $this->fatal_on_error = $fatal_on_error;
    }

    public function name()
    {
        return ('database');
    }

    public function init_state()
    {
        return array(
            'counts'      => array('ADMINS' => 0, 'OPTIONS' => 0, 'FLAGGED_OPTIONS' => 0, 'FLAGGED_POSTS' => 0),
            'suppressed'  => 0,
            'unavailable' => false,
            // The site the per-site listing cap is counting for.
            'posts_site'    => 0,
            'posts_flagged' => 0,
            // Network only: md5(login) => array(login, hash of the list it
            // was read from, seen as a user) and whether a list was found.
            'super_admins'  => array(),
            'super_list'    => false,
        );
    }

    private function connect()
    {
        if ($this->connected) {
            return (null);
        }
        if (null === $this->ctx->db) {
            return ('no database adapter configured, cannot scan the database');
        }
        $error = $this->ctx->db->connect($this->ctx);
        if (null === $error) {
            $this->connected = true;
        }
        return ($error);
    }

    public function plan(array &$state)
    {
        $root = $this->ctx->root();
        $failure = $this->connect();
        if (null !== $failure) {
            if ($this->fatal_on_error) {
                throw new Fatal($failure);
            }
            ///////////////
            // Inside scanall a skipped database is an ERROR finding: it has to
            // show in the JSON stream and the exit code, or "nothing found"
            // silently means "never looked".
            //////////////
            $config_path = (null === $this->ctx->db) ? null : $this->ctx->db->config_path();
            $where = (null !== $config_path) ? $config_path : $root . '/wp-config.php';
            $this->report('ERROR', 'DB_UNAVAILABLE', $where, $failure . ' - the database was NOT scanned');
            $state['unavailable'] = true;
            return array();
        }

        // The active_plugins check needs the plugin folder: say when it is
        // unknown (inside scanall the quick scan already did).
        Layout::report_notes($this->ctx, false);
        if (!$this->ctx->db->multisite()) {
            $this->progress('Scanning database ' . $this->ctx->db->name() . ' (prefix ' . $this->ctx->db->prefix() . ") - read-only\n");
            return array(
                array('table' => 'admins', 'after' => 0),
                array('table' => 'options', 'after' => 0),
                array('table' => 'posts', 'after' => 0),
            );
        }
        ///////////////
        // A network. The main site (id 1, the base prefix) is planned here
        // and not left to the list of sites: it is scanned even when
        // {base}blogs cannot be read.
        //////////////
        $this->progress('Scanning database ' . $this->ctx->db->name() . ' (prefix ' . $this->ctx->db->prefix()
            . ') - read-only, multisite network: every site listed in ' . $this->ctx->db->table('blogs') . "\n");
        $state['counts']['SITES'] = 1;
        $state['counts']['SUPER_ADMINS'] = 0;
        return array_merge(
            array(
                array('table' => 'network', 'after' => 0),
                array('table' => 'superadmins', 'after' => 0),
            ),
            self::site_units(1),
            array(array('table' => 'sites', 'after' => 1))
        );
    }

    private static function site_units($site)
    {
        return array(
            array('table' => 'admins', 'after' => 0, 'site' => (int) $site),
            array('table' => 'options', 'after' => 0, 'site' => (int) $site),
            array('table' => 'posts', 'after' => 0, 'site' => (int) $site),
        );
    }

    // " of site 3" on a network, nothing on a single site (site 0).
    private static function of_site($site)
    {
        return ($site > 0) ? ' of site ' . (int) $site : '';
    }

    public function run(array $unit, array &$state)
    {
        $failure = $this->connect();
        if (null !== $failure) {
            throw new Fatal($failure);
        }
        // 0 on a single site; on a network the id from {base}blogs, only
        // ever used as an integer.
        $site = isset($unit['site']) ? (int) $unit['site'] : 0;
        $per_site = in_array($unit['table'], array('admins', 'options', 'posts'), true);
        if ((int) $unit['after'] > 0 && $per_site) {
            ///////////////
            // A continuation (only the paused web job produces one): say how
            // far the table has been read so a long stage visibly moves.
            //////////////
            $seen = ('posts' === $unit['table']) ? $state['counts']['FLAGGED_POSTS'] . ' flagged post(s) so far'
                : (('options' === $unit['table']) ? $state['counts']['OPTIONS'] . ' options checked' : $state['counts']['ADMINS'] . ' administrator(s) listed');
            $this->progress('Scanning database: ' . $unit['table'] . self::of_site($site) . ' past id ' . (int) $unit['after'] . ', ' . $seen . "\n");
        }
        switch ($unit['table']) {
            case 'admins':
                return ($this->scan_admins((int) $unit['after'], $state, $site));
            case 'options':
                return ($this->scan_options((int) $unit['after'], $state, $site));
            case 'posts':
                return ($this->scan_posts((int) $unit['after'], $state, $site));
            case 'network':
                return ($this->scan_network((int) $unit['after'], $state));
            case 'superadmins':
                return ($this->scan_super_admins((int) $unit['after'], $state));
            case 'sites':
                return ($this->scan_sites((int) $unit['after'], $state));
        }
        return (null);
    }

    public function finish(array &$state)
    {
        if ($state['unavailable']) {
            return;
        }
        if ($this->connected) {
            $this->ctx->db->close();
            $this->connected = false;
        }
        $counts = $state['counts'];
        $network = isset($counts['SITES']) ? $counts['SITES'] . ' site(s), ' . $counts['SUPER_ADMINS'] . ' super admin(s), ' : '';
        $this->summary('database', $counts,
            'Database scan complete: ' . $network . $counts['ADMINS'] . ' administrator(s), ' . $counts['OPTIONS'] . ' options scanned, '
            . $counts['FLAGGED_OPTIONS'] . ' flagged options, ' . $counts['FLAGGED_POSTS'] . " flagged posts\n");
    }

    ///////////////
    // A query that fails or a result stream that dies mid-way means that
    // part of the database was NOT checked. That is an ERROR finding (exit
    // 2, visible in JSON) - never a progress line and a clean-looking
    // summary. Returns the continuation unit when the iteration paused.
    // $unit_name is the unit to continue with, $short_table the table the
    // finding names ($site picks the site's own on a network).
    //////////////
    private function iterate($unit_name, $short_table, $what, array $query, $callback, $after, $site = 0)
    {
        $db = $this->ctx->db;
        $this->failed = false;
        $result = $db->each($query, $callback, $after);
        if (null !== $result['error']) {
            $this->failed = true;
            $label = $result['early'] ? $what . ' (result stream ended early)' : $what;
            $this->report('ERROR', 'DB_QUERY_FAILED', 'db:' . $db->table($short_table, $site), $label . ' NOT verified: ' . $result['error']);
            return (null);
        }
        if (!$result['done']) {
            $next = array('table' => $unit_name, 'after' => $result['last']);
            if ($site > 0) {
                $next['site'] = (int) $site;
            }
            return ($next);
        }
        return (null);
    }

    private function scan_admins($after, array &$state, $site = 0)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        // Each site of a network has its own {site prefix}capabilities row
        // for a user, in the one usermeta table.
        $prefix = $db->site_prefix($site);
        $of_site = self::of_site($site);
        $users_table = $db->table('users');
        $recent_cutoff = time() - (self::RECENT_ADMIN_DAYS * 86400);

        // Serialized capabilities look like a:1:{s:13:"administrator";b:1;}.
        // Matching the b:1 excludes a revoked role (b:0) and look-alike custom
        // role names.
        $query = array(
            'columns' => 'u.ID, u.user_login, u.user_email, u.user_registered',
            'from'    => $users_table . ' u JOIN ' . $db->table('usermeta') . ' m ON m.user_id = u.ID',
            'where'   => "m.meta_key = '" . $prefix . "capabilities' AND m.meta_value LIKE '%\"administrator\";b:1;%'",
            'pk'      => 'u.ID',
        );
        $scanner = $this;
        // The same user can administer several sites: the site in the detail
        // keeps those findings (and a false-positive mark on one) apart.
        return $this->iterate('admins', 'users', 'administrators' . $of_site, $query, function ($row) use (&$counts, $ctx, $users_table, $recent_cutoff, $of_site, $scanner) {
            $counts['ADMINS']++;
            $registered = strtotime($row[3]);
            $where = 'db:' . $users_table . ':ID=' . $row[0];
            $who = '"' . $row[1] . '" <' . $row[2] . '> registered ' . $row[3];

            if (false !== $registered && $registered >= $recent_cutoff) {
                $scanner->report_public('MEDIUM', 'DB_NEW_ADMIN', $where, 'administrator' . $of_site . ' ' . $who . ' - created within the last ' . DatabaseScanner::RECENT_ADMIN_DAYS . ' days, the classic takeover artifact; verify who created it');
            } else {
                $scanner->report_public('INFO', 'DB_ADMIN_USER', $where, 'administrator' . $of_site . ' ' . $who . ' - confirm this account is known');
            }
            return (!$ctx->out_of_time());
        }, $after, $site);
    }

    private function scan_options($after, array &$state, $site = 0)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        // The roles option carries the site's own prefix: wp_3_user_roles.
        $prefix = $db->site_prefix($site);
        $options_table = $db->table('options', $site);
        // active_plugins entries are relative to the folder WordPress loads
        // plugins from; with no plugin folder found that check is skipped
        // (the layout ERROR already says so).
        $plugin_dir = Layout::of($this->ctx)->plugin_dir();
        $signatures = Signatures::db_options();
        $scanner = $this;

        // SUBSTRING caps each value read.
        $query = array(
            'columns' => 'option_id, option_name, SUBSTRING(option_value, 1, ' . self::VALUE_SCAN_CAP . ')',
            'from'    => $options_table,
            'where'   => '',
            'pk'      => 'option_id',
        );
        return $this->iterate('options', 'options', 'options', $query, function ($row) use (&$counts, $ctx, $prefix, $options_table, $plugin_dir, $signatures, $scanner) {
            $counts['OPTIONS']++;
            $option_name = $row[1];
            $value = (string) $row[2];
            $where = 'db:' . $options_table . ':' . $option_name;
            // Binds a false-positive mark to the value that was reviewed.
            $meta = array('value_sha256' => hash('sha256', $value));

            ///////////////
            // siteurl/home hijacks redirect every visitor; report the values
            // as inventory even when they look sane.
            //////////////
            if ('siteurl' === $option_name || 'home' === $option_name) {
                if (preg_match('@^https?://[^\s<>\'"]+$@', $value) === 1) {
                    $scanner->report_public('INFO', 'DB_SITE_URL', $where, $option_name . ' = ' . $value . ' - confirm this is the real site address', array(), $meta);
                } else {
                    $scanner->report_public('HIGH', 'DB_SITE_URL', $where, $option_name . ' does not look like a plain URL (hijack or injection): ' . substr($value, 0, 200), array(), $meta);
                    $counts['FLAGGED_OPTIONS']++;
                }
                return (!$ctx->out_of_time());
            }

            ///////////////
            // active_plugins is serialized PHP; extract the .php entries with a
            // regex (NEVER unserialize hostile data) and sanity-check each.
            //////////////
            if ('active_plugins' === $option_name) {
                $scanner->check_active_plugins($value, $where, $plugin_dir, $counts);
                return (!$ctx->out_of_time());
            }

            // Role definitions: a non-admin role quietly granted admin powers.
            if ($prefix . 'user_roles' === $option_name) {
                $scanner->check_user_roles($value, $where, $counts, $meta);
                return (!$ctx->out_of_time());
            }

            $scanner->check_option_signatures($signatures, $value, $where, $counts, $meta);
            return (!$ctx->out_of_time());
        }, $after, $site);
    }

    private function scan_posts($after, array &$state, $site = 0)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        // The listing cap counts per site: a new site starts from zero (a
        // continuation of the same site keeps its count).
        if ($state['posts_site'] !== $site) {
            $state['posts_site'] = $site;
            $state['posts_flagged'] = 0;
            $state['suppressed'] = 0;
        }
        $flagged = &$state['posts_flagged'];
        $suppressed = &$state['suppressed'];
        $posts_table = $db->table('posts', $site);
        $signatures = Signatures::db_posts();
        $scanner = $this;

        ///////////////
        // The posts table can be huge: a LIKE prefilter runs server-side and
        // only candidates come back (value capped) for the real pattern check.
        // The prefilter lists what the built-in post signatures look for; a
        // custom post signature can look for anything (spam links, a script
        // URL), so when there is one every live post is read, still paged.
        // Revisions and autosaves (post_type revision) would repeat every
        // injected post once per saved version: one finding per live post.
        //////////////
        $custom = Signatures::custom();
        $where = "post_type <> 'revision'";
        if (empty($custom['db_posts'])) {
            $where .= " AND (post_content LIKE '%<?php%' OR post_content LIKE '%eval(%'"
                . " OR post_content LIKE '%fromCharCode%' OR post_content LIKE '%atob(%'"
                . " OR post_content LIKE '%unescape(%' OR post_content LIKE '%<iframe%')";
        }
        $query = array(
            'columns' => 'ID, post_title, post_type, SUBSTRING(post_content, 1, ' . self::VALUE_SCAN_CAP . ')',
            'from'    => $posts_table,
            'where'   => $where,
            'pk'      => 'ID',
        );
        $next = $this->iterate('posts', 'posts', 'posts', $query, function ($row) use (&$counts, &$flagged, &$suppressed, $ctx, $posts_table, $signatures, $scanner) {
            $content = (string) $row[3];
            foreach ($signatures as $signature) {
                if (preg_match($signature['pattern'], $content) !== 1) {
                    continue;
                }
                $counts['FLAGGED_POSTS']++;
                $flagged++;
                if ($flagged > DatabaseScanner::MAX_REPORTED_POSTS) {
                    $suppressed++;
                } else {
                    $scanner->report_public($signature['severity'], 'DB_POST_IOC', 'db:' . $posts_table . ':ID=' . $row[0],
                        $signature['name'] . ' in ' . $row[2] . ' "' . $row[1] . '": ' . $signature['description'],
                        array(), array('value_sha256' => hash('sha256', $content)));
                }
                break;
            }
            return (!$ctx->out_of_time());
        }, $after, $site);

        if (null === $next && $suppressed > 0) {
            $this->progress('...and ' . $suppressed . ' more flagged posts' . self::of_site($site) . " not listed\n");
        }
        return ($next);
    }

    ///////////////
    // The network's own settings ({base}sitemeta): who is a super admin,
    // which plugins run on every site, and the same injection patterns the
    // options of a site are checked for.
    //////////////
    private function scan_network($after, array &$state)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        $sitemeta_table = $db->table('sitemeta');
        $plugin_dir = Layout::of($this->ctx)->plugin_dir();
        $signatures = Signatures::db_options();
        $scanner = $this;

        $query = array(
            'columns' => 'meta_id, meta_key, SUBSTRING(meta_value, 1, ' . self::VALUE_SCAN_CAP . ')',
            'from'    => $sitemeta_table,
            'where'   => '',
            'pk'      => 'meta_id',
        );
        $next = $this->iterate('network', 'sitemeta', 'network settings and the super admin list', $query, function ($row) use (&$counts, &$state, $ctx, $sitemeta_table, $plugin_dir, $signatures, $scanner) {
            $counts['OPTIONS']++;
            $meta_key = $row[1];
            $value = (string) $row[2];
            $where = 'db:' . $sitemeta_table . ':' . $meta_key;
            $meta = array('value_sha256' => hash('sha256', $value));

            if ('site_admins' === $meta_key) {
                $scanner->check_super_admin_list($value, $where, $state, $meta);
                return (!$ctx->out_of_time());
            }
            // Plugins activated for the whole network: serialized
            // path => time, checked like a site's active_plugins.
            if ('active_sitewide_plugins' === $meta_key) {
                $scanner->check_active_plugins($value, $where, $plugin_dir, $counts);
                return (!$ctx->out_of_time());
            }
            $scanner->check_option_signatures($signatures, $value, $where, $counts, $meta);
            return (!$ctx->out_of_time());
        }, $after);

        if (null === $next && !$this->failed && !$state['super_list']) {
            // get_super_admins() falls back to array('admin').
            $this->report('LOW', 'DB_SUPER_ADMIN', 'db:' . $sitemeta_table . ':site_admins',
                'the network has no site_admins entry: WordPress then treats the login "admin" as its super admin - verify that account');
        }
        return ($next);
    }

    ///////////////
    // The users the super admin list names. The match is done by the
    // server (the login, serialized, appears in the list) so the users
    // table is never pulled; both sides are compared as bytes, which is
    // exact like WordPress's own check and independent of the tables'
    // collations.
    //////////////
    private function scan_super_admins($after, array &$state)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        $listed = &$state['super_admins'];
        $where = 'db:' . $db->table('sitemeta') . ':site_admins';
        $recent_cutoff = time() - (self::RECENT_ADMIN_DAYS * 86400);
        $scanner = $this;

        $query = array(
            'columns' => 'u.ID, u.user_login, u.user_email, u.user_registered',
            'from'    => $db->table('users') . ' u',
            'where'   => 'EXISTS (SELECT 1 FROM ' . $db->table('sitemeta') . " m WHERE m.meta_key = 'site_admins'"
                . " AND LOCATE(CONCAT('s:', LENGTH(u.user_login), ':\"', CAST(u.user_login AS BINARY), '\";'), CAST(m.meta_value AS BINARY)) > 0)",
            'pk'      => 'u.ID',
        );
        $next = $this->iterate('superadmins', 'users', 'super admins', $query, function ($row) use (&$counts, &$listed, $ctx, $where, $recent_cutoff, $scanner) {
            $counts['SUPER_ADMINS']++;
            $key = md5($row[1]);
            $meta = array();
            if (isset($listed[$key])) {
                $listed[$key]['seen'] = 1;
                // Binds a false-positive mark to the list that was reviewed.
                $meta = array('value_sha256' => $listed[$key]['hash']);
            }
            $registered = strtotime($row[3]);
            $who = '"' . $row[1] . '" <' . $row[2] . '> (user ID ' . $row[0] . ') registered ' . $row[3];
            if (false !== $registered && $registered >= $recent_cutoff) {
                $scanner->report_public('MEDIUM', 'DB_NEW_ADMIN', $where, 'super admin ' . $who . ' - created within the last ' . DatabaseScanner::RECENT_ADMIN_DAYS . ' days, the classic takeover artifact; verify who created it', array(), $meta);
            } else {
                $scanner->report_public('INFO', 'DB_SUPER_ADMIN', $where, 'super admin ' . $who . ' - controls every site of the network; confirm this account is known', array(), $meta);
            }
            return (!$ctx->out_of_time());
        }, $after);
        if (null !== $next) {
            return ($next);
        }

        ///////////////
        // Logins the list names that matched no user. When the users could
        // not be read they are still listed, as what they are: names.
        //////////////
        foreach ($listed as $entry) {
            if (!empty($entry['seen'])) {
                continue;
            }
            $meta = array('value_sha256' => $entry['hash']);
            if ($this->failed) {
                $this->report('INFO', 'DB_SUPER_ADMIN', $where, 'super admin login "' . $entry['login'] . '" - the account behind it could not be read; confirm it is known', array(), $meta);
            } else {
                $this->report('LOW', 'DB_SUPER_ADMIN', $where, 'super admin login "' . $entry['login'] . '" has no user account: an account created with that name would be a super admin - remove it from the list', array(), $meta);
            }
        }
        $listed = array();
        return (null);
    }

    ///////////////
    // The sites of the network, a batch of ids per unit: the three units of
    // each site are queued ahead of the unit that reads the next batch, so
    // a network of any size is walked with a short queue. The main site
    // (id 1) is in the plan already.
    //////////////
    private function scan_sites($after, array &$state)
    {
        $db = $this->ctx->db;
        $blogs_table = $db->table('blogs');
        $ids = array();
        $query = array(
            'columns' => 'blog_id',
            'from'    => $blogs_table,
            'where'   => '',
            'pk'      => 'blog_id',
        );
        $result = $db->each($query, function ($row) use (&$ids) {
            $ids[] = (int) $row[0];
            return (count($ids) < DatabaseScanner::SITE_BATCH);
        }, $after);

        $units = array();
        foreach ($ids as $id) {
            if ($id < 2) {
                continue;
            }
            $state['counts']['SITES']++;
            $units = array_merge($units, self::site_units($id));
        }
        if (count($ids) > 0) {
            $this->progress('Scanning database: sites ' . $ids[0] . ' to ' . $ids[count($ids) - 1] . ' (' . $state['counts']['SITES'] . " so far)\n");
        }
        if (null !== $result['error']) {
            // The sites past this point are not known, so not scanned.
            $this->report('ERROR', 'DB_QUERY_FAILED', 'db:' . $blogs_table,
                'the list of sites could not be read past id ' . (int) $result['last'] . ', the sites after it were NOT scanned: ' . $result['error']);
        } elseif (!$result['done']) {
            $units[] = array('table' => 'sites', 'after' => (int) $result['last']);
        }
        return ($units);
    }

    ///////////////
    // active_plugins and active_sitewide_plugins: sanity-check each .php
    // entry of the serialized list.
    //////////////
    public function check_active_plugins($value, $where, $plugin_dir, array &$counts)
    {
        if (!preg_match_all('@"((?:[^"\\\\]|\\\\.)*?\.php)"@', $value, $matches)) {
            return;
        }
        foreach ($matches[1] as $plugin_entry) {
            if (false !== strpos($plugin_entry, '..')) {
                $this->report('HIGH', 'DB_ACTIVE_PLUGIN', $where, 'active plugin path escapes the plugins directory: ' . $plugin_entry);
                $counts['FLAGGED_OPTIONS']++;
            } elseif (null !== $plugin_dir && !is_file($plugin_dir . '/' . $plugin_entry)) {
                $this->report('LOW', 'DB_ACTIVE_PLUGIN', $where, 'active plugin file missing on disk: ' . $plugin_entry);
            }
        }
    }

    // The injection patterns, on one option (or network setting) value.
    public function check_option_signatures(array $signatures, $value, $where, array &$counts, array $meta)
    {
        foreach ($signatures as $signature) {
            if (preg_match($signature['pattern'], $value, $hit, PREG_OFFSET_CAPTURE) !== 1) {
                continue;
            }
            // Excerpt around the match itself, not the start of the value.
            $excerpt_start = max(0, $hit[0][1] - 40);
            $this->report($signature['severity'], 'DB_OPTION_IOC', $where,
                $signature['name'] . ': ' . $signature['description'],
                array('e.g. ' . substr($value, $excerpt_start, 200)), $meta);
            $counts['FLAGGED_OPTIONS']++;
            break;
        }
    }

    ///////////////
    // site_admins is a serialized list of logins, a:2:{i:0;s:5:"admin";...}.
    // The logins are kept in the state (cleaned for storage, keyed by the
    // hash of the raw bytes) for the unit that looks the users up. A list
    // that cannot be read is reported: it must not pass for "no super
    // admins".
    //////////////
    public function check_super_admin_list($value, $where, array &$state, array $meta)
    {
        $state['super_list'] = true;
        if (preg_match('/^a:(\d+):\{/', $value, $shape) !== 1) {
            $this->report('LOW', 'DB_SUPER_ADMIN', $where, 'site_admins is not a serialized list of logins (damaged or tampered with): ' . substr($value, 0, 200), array(), $meta);
            return;
        }
        $logins = self::serialized_strings($value, self::MAX_SUPER_ADMINS + 1);
        if (count($logins) > self::MAX_SUPER_ADMINS) {
            array_pop($logins);
            $this->report('MEDIUM', 'DB_SUPER_ADMIN', $where, 'site_admins lists ' . (int) $shape[1] . ' super admins, far more than a network needs: the accounts are all reported, but only the first '
                . self::MAX_SUPER_ADMINS . ' logins are checked for a missing user', array(), $meta);
        } elseif ((int) $shape[1] !== count($logins)) {
            $this->report('LOW', 'DB_SUPER_ADMIN', $where, 'site_admins declares ' . (int) $shape[1] . ' entries but ' . count($logins)
                . ' login name(s) could be read from it (damaged or tampered with)', array(), $meta);
        }
        foreach ($logins as $login) {
            $state['super_admins'][md5($login)] = array(
                'login' => BaseReporter::clean_utf8(substr($login, 0, 255)),
                'hash'  => $meta['value_sha256'],
                'seen'  => 0,
            );
        }
    }

    ///////////////
    // The strings of a serialized value, each read by its declared length
    // (s:5:"admin";) and never by unserialize(): a quote inside a string
    // cannot end it early, and nothing is ever instantiated.
    //////////////
    public static function serialized_strings($value, $max)
    {
        $found = array();
        $offset = 0;
        while (count($found) < $max && preg_match('/s:(\d{1,7}):"/', $value, $header, PREG_OFFSET_CAPTURE, $offset) === 1) {
            $start = $header[0][1] + strlen($header[0][0]);
            $length = (int) $header[1][0];
            if ('";' !== substr($value, $start + $length, 2)) {
                // Not a string header after all, or a value cut short.
                $offset = $start;
                continue;
            }
            $found[] = substr($value, $start, $length);
            $offset = $start + $length + 2;
        }
        return ($found);
    }

    public function check_user_roles($value, $where, array &$counts, array $meta = array())
    {
        ///////////////
        // {prefix}user_roles is serialized role => array(name, capabilities =>
        // array(cap => bool)). Parsed with a regex, never unserialize()d: each
        // capabilities array holds no nested arrays, so the lazy match stops at
        // the first "}}" (capabilities close + role close).
        //////////////
        if (!preg_match_all('/s:\d+:"([^"]*)";a:\d+:\{s:4:"name";s:\d+:"[^"]*";s:12:"capabilities";a:\d+:\{(.*?)\}\}/s', $value, $roles, PREG_SET_ORDER)) {
            return;
        }
        foreach ($roles as $role) {
            if ('administrator' === $role[1]) {
                continue;
            }
            if (preg_match_all('/"(' . self::ADMIN_CAPS . ')";b:1;/', $role[2], $caps)) {
                $this->report('MEDIUM', 'DB_ROLE_CAPS', $where,
                    'role "' . $role[1] . '" holds administrator-level capabilities: ' . implode(', ', array_unique($caps[1]))
                    . ' - role-editor plugins and shop-manager roles do this legitimately; verify it was intentional and check who holds the role', array(), $meta);
                $counts['FLAGGED_OPTIONS']++;
            }
        }
    }

    // Closures in PHP 5.x cannot call a protected method of the enclosing
    // object; this is the same as report() for use from the row callbacks.
    public function report_public($severity, $type, $path, $detail, $context = array(), $meta = array())
    {
        $this->report($severity, $type, $path, $detail, $context, $meta);
    }
}
