<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_unser_bad() {
    // ruleid: wp-unserialize-user-input
    $data = unserialize($_POST['state']);
    return $data;
}

function soc_test_unser_bad_raw() {
    $raw = file_get_contents('php://input');
    // ruleid: wp-unserialize-user-input
    return unserialize($raw);
}

function soc_test_unser_ok_json() {
    // ok: wp-unserialize-user-input
    return json_decode(wp_unslash($_POST['state']), true);
}

function soc_test_unser_ok_noclasses() {
    // ok: wp-unserialize-user-input
    return unserialize($_POST['state'], ['allowed_classes' => false]);
}

function soc_test_unser_ok_local() {
    $opt = get_option('soc_test');
    // ok: wp-unserialize-user-input
    return unserialize($opt);
}
