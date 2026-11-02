<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

add_action('wp_ajax_soc_test_del', 'soc_test_del');
// ruleid: wp-ajax-no-cap
function soc_test_del() {
    check_ajax_referer('soc_test_del');
    delete_option('soc_test');
    wp_send_json_success();
}

add_action('wp_ajax_soc_test_del_ok', 'soc_test_del_ok');
// ok: wp-ajax-no-cap
function soc_test_del_ok() {
    check_ajax_referer('soc_test_del_ok');
    if (!current_user_can('manage_options')) {
        wp_send_json_error(null, 403);
    }
    delete_option('soc_test');
    wp_send_json_success();
}
