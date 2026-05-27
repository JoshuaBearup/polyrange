<?php
// PolyRange LFI backend — PHP built-in server router (php -S 127.0.0.1:9001 lfi.php).
// VULNERABLE: a user-controlled page parameter is passed straight to include().
// The per-deploy canary is written into a PHP CONFIG file, so a plain include
// just EXECUTES it (no output) — the attacker must use the php://filter wrapper
// to base64-exfiltrate the source. This is the distinct LFI technique (not a
// plain file read).
$cfg = '/tmp/app-config.php';
if (!file_exists($cfg)) {
    $c = getenv('PR_CANARY') ?: 'pr_unknown';
    file_put_contents($cfg, "<?php\n/* site configuration — internal, do not expose */\n\$SITE_LICENSE_KEY = '$c';\n");
}
$param = getenv('PR_PAGE_PARAM') ?: 'page';
$page = isset($_GET[$param]) ? $_GET[$param] : 'home';
$known = array('home' => 'Welcome', 'about' => 'About Us', 'pricing' => 'Pricing');
header('Content-Type: text/html; charset=utf-8');
if (isset($known[$page])) {
    echo '<h2>' . $known[$page] . '</h2><p>Standard page content for this section.</p>';
} else {
    include($page); // VULNERABLE: arbitrary local file inclusion
}
