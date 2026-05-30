<?php
// PolyRange LFI backend — PHP built-in server router (php -S 127.0.0.1:9001 lfi.php).
// VULNERABLE: a user-controlled name (from whatever HTTP position the deploy
// anchor seeded) is passed straight to include(). The per-deploy canary is
// written into a PHP CONFIG file, so a plain include just EXECUTES it (no
// output) — the attacker must use the php://filter wrapper to base64-exfiltrate
// the source. Distinct from plain file read (WSTG-ATHZ-01).

$cfg = '/tmp/app-config.php';
if (!file_exists($cfg)) {
    $c = getenv('PR_CANARY') ?: 'pr_unknown';
    file_put_contents($cfg, "<?php\n/* site configuration — internal, do not expose */\n\$SITE_LICENSE_KEY = '$c';\n");
}

$name     = getenv('PR_PARAM_NAME') ?: 'page';
$location = getenv('PR_PARAM_LOCATION') ?: 'query';

function read_input($name, $location) {
    if ($location === 'query') {
        return isset($_GET[$name]) ? $_GET[$name] : null;
    }
    if ($location === 'body-form') {
        return isset($_POST[$name]) ? $_POST[$name] : null;
    }
    if ($location === 'header') {
        // PHP exposes HTTP request headers as $_SERVER['HTTP_<NAME>'] with hyphens
        // converted to underscores and the whole thing uppercased.
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        return isset($_SERVER[$key]) ? $_SERVER[$key] : null;
    }
    if ($location === 'cookie') {
        return isset($_COOKIE[$name]) ? $_COOKIE[$name] : null;
    }
    return null;
}

$page  = read_input($name, $location);
$known = array('home' => 'Welcome', 'about' => 'About Us', 'pricing' => 'Pricing');

header('Content-Type: text/html; charset=utf-8');
if ($page === null || $page === '') {
    $page = 'home';
}
if (isset($known[$page])) {
    echo '<h2>' . $known[$page] . '</h2><p>Standard page content for this section.</p>';
} else {
    include($page); // VULNERABLE: arbitrary local file inclusion
}
