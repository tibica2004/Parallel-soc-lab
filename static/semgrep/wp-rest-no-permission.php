<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_rest_routes() {
    // ruleid: wp-rest-no-permission
    register_rest_route('soc/v1', '/settings', [
        'methods'             => 'POST',
        'callback'            => 'soc_test_rest_save',
        'permission_callback' => '__return_true',
    ]);

    // ruleid: wp-rest-no-permission
    register_rest_route('soc/v1', '/items', array(
        'methods'  => 'GET',
        'callback' => 'soc_test_rest_items',
    ));

    // ok: wp-rest-no-permission
    register_rest_route('soc/v1', '/admin', [
        'methods'             => 'POST',
        'callback'            => 'soc_test_rest_save',
        'permission_callback' => function () {
            return current_user_can('manage_options');
        },
    ]);
}
