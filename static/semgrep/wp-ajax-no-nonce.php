<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

add_action('wp_ajax_soc_test_save', 'soc_test_save');
// ruleid: wp-ajax-no-nonce
function soc_test_save() {
    if (!current_user_can('manage_options')) {
        wp_die();
    }
    update_option('soc_test', sanitize_text_field(wp_unslash($_POST['v'])));
    wp_send_json_success();
}

add_action('wp_ajax_soc_test_save_ok', 'soc_test_save_ok');
// ok: wp-ajax-no-nonce
function soc_test_save_ok() {
    check_ajax_referer('soc_test_save_ok');
    if (!current_user_can('manage_options')) {
        wp_die();
    }
    update_option('soc_test', sanitize_text_field(wp_unslash($_POST['v'])));
    wp_send_json_success();
}

add_action('wp_ajax_soc_test_save_ok2', 'soc_test_save_ok2');
// ok: wp-ajax-no-nonce
function soc_test_save_ok2() {
    if (!wp_verify_nonce($_POST['_n'], 'soc_test_save_ok2')) {
        wp_die();
    }
    update_option('soc_test', 1);
}

add_action('init', 'soc_test_not_ajax');
// ok: wp-ajax-no-nonce
function soc_test_not_ajax() {
    register_post_type('soc_test');
}
