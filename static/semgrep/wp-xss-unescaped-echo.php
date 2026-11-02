<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_xss_bad() {
    $q = $_GET['q'];
    // ruleid: wp-xss-unescaped-echo
    echo '<p>Rezultate pentru ' . $q . '</p>';
}

function soc_test_xss_bad_uri() {
    // ruleid: wp-xss-unescaped-echo
    echo '<a href="' . $_SERVER['REQUEST_URI'] . '">reincarca</a>';
}

function soc_test_xss_ok() {
    $q = $_GET['q'];
    // ok: wp-xss-unescaped-echo
    echo '<p>Rezultate pentru ' . esc_html($q) . '</p>';
}

function soc_test_xss_ok_static() {
    // ok: wp-xss-unescaped-echo
    echo '<p>' . esc_html__('Salut', 'soc') . '</p>';
}
