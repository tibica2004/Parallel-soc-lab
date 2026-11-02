<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_read_bad() {
    $f = $_GET['file'];
    // ruleid: wp-file-read-user-input
    readfile(WP_CONTENT_DIR . '/exports/' . $f);
}

function soc_test_read_ok() {
    $f = basename($_GET['file']);
    // ok: wp-file-read-user-input
    readfile(WP_CONTENT_DIR . '/exports/' . $f);
}

function soc_test_read_ok_raw_body() {
    // ok: wp-file-read-user-input
    return file_get_contents('php://input');
}
