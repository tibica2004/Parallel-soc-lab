<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_wpdb_bad() {
    global $wpdb;
    $id = $_GET['id'];
    // ruleid: wp-wpdb-no-prepare
    return $wpdb->get_row("SELECT * FROM {$wpdb->posts} WHERE ID = $id");
}

function soc_test_wpdb_bad_concat() {
    global $wpdb;
    // ruleid: wp-wpdb-no-prepare
    return $wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE post_name = '" . $_POST['slug'] . "'");
}

function soc_test_wpdb_ok_prepare() {
    global $wpdb;
    // ok: wp-wpdb-no-prepare
    return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $_GET['id']));
}

function soc_test_wpdb_ok_absint() {
    global $wpdb;
    $id = absint($_GET['id']);
    // ok: wp-wpdb-no-prepare
    return $wpdb->get_row("SELECT * FROM {$wpdb->posts} WHERE ID = $id");
}

function soc_test_wpdb_ok_static() {
    global $wpdb;
    // ok: wp-wpdb-no-prepare
    return $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts}");
}
