<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_include_bad() {
    $tpl = $_GET['tpl'];
    // ruleid: wp-dynamic-include
    include plugin_dir_path(__FILE__) . 'templates/' . $tpl . '.php';
}

function soc_test_include_ok() {
    $allowed = ['lista' => 'templates/lista.php', 'detalii' => 'templates/detalii.php'];
    $key = sanitize_key($_GET['tpl']);
    $file = isset($allowed[$key]) ? $allowed[$key] : 'templates/lista.php';
    // ok: wp-dynamic-include
    include plugin_dir_path(__FILE__) . 'templates/lista.php';
}
