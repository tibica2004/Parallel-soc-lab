<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_sqldirect_bad() {
    global $wpdb;
    // ruleid: wp-sql-direct-input
    return $wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE meta_id = " . $_POST['meta_id']);
}

function soc_test_sqldirect_ok() {
    global $wpdb;
    // ok: wp-sql-direct-input
    return $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->postmeta} WHERE meta_id = %d", $_POST['meta_id']));
}
