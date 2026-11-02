<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_extract_bad() {
    // ruleid: wp-extract-user-input
    extract($_POST);
}

function soc_test_extract_ok() {
    $title = isset($_POST['title']) ? sanitize_text_field(wp_unslash($_POST['title'])) : '';
    // ok: wp-extract-user-input
    extract(['title' => $title]);
}
