<?php
// PolyRange BUSL-09 backend — PHP built-in server router.
// VULNERABLE: the upload endpoint stores files into the webroot with NO type or
// content validation, and php -S executes any .php under the docroot. Uploading
// a web shell and requesting it runs arbitrary PHP (RCE). The per-deploy canary
// is in this process's environment.
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$docroot = $_SERVER['DOCUMENT_ROOT'] ?: __DIR__;
$dir = $docroot . '/uploads';
if (!is_dir($dir)) @mkdir($dir, 0777, true);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $uri === '/upload') {
    if (!empty($_FILES['file']['tmp_name'])) {            // multipart upload
        $name = basename($_FILES['file']['name']);
        move_uploaded_file($_FILES['file']['tmp_name'], "$dir/$name");
    } else {                                              // raw-body upload (?name=)
        $name = basename($_GET['name'] ?? '');
        if ($name === '') { http_response_code(400); echo 'name required'; return true; }
        file_put_contents("$dir/$name", file_get_contents('php://input'));
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo "Uploaded to /uploads/$name";
    return true;
}
return false; // let php -S serve/execute docroot files (incl uploaded /uploads/*.php)
