<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_upload_bad() {
    $dest = wp_upload_dir()['path'] . '/' . basename($_FILES['f']['name']);
    // ruleid: wp-upload-no-validation
    move_uploaded_file($_FILES['f']['tmp_name'], $dest);
}

function soc_test_upload_ok_checked() {
    $check = wp_check_filetype_and_ext($_FILES['f']['tmp_name'], $_FILES['f']['name']);
    if (!$check['ext'] || $check['ext'] !== 'png') {
        return;
    }
    $dest = wp_upload_dir()['path'] . '/' . sanitize_file_name($_FILES['f']['name']);
    // ok: wp-upload-no-validation
    move_uploaded_file($_FILES['f']['tmp_name'], $dest);
}

function soc_test_upload_ok_handler() {
    $r = wp_handle_upload($_FILES['f'], ['test_form' => true, 'mimes' => ['png' => 'image/png']]);
    // ok: wp-upload-no-validation
    return $r;
}
