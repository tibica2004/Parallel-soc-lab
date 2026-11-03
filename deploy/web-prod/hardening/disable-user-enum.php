<?php
/*
Plugin Name: SOC - dezactiveaza enumerarea de utilizatori
Description: Blocheaza enumerarea de utilizatori (REST /wp/v2/users si ?author=N) pentru cereri
 neautentificate. Expunere gasita la auto-atacul de masurare (nuclei/wpscan au scurs admin,
 soc-benign-admin). Nu afecteaza benign-gen, care se logheaza. mu-plugin: se incarca intotdeauna.
*/
if (!defined('ABSPATH')) exit;

// REST: ascunde endpoint-ul de utilizatori pentru cei nelogati.
add_filter('rest_endpoints', function ($endpoints) {
    if (!is_user_logged_in()) {
        foreach (array('/wp/v2/users', '/wp/v2/users/(?P<id>[\\d]+)') as $route) {
            if (isset($endpoints[$route])) unset($endpoints[$route]);
        }
    }
    return $endpoints;
});

// ?author=N dezvaluie slug-ul prin redirect: il oprim pentru cei nelogati.
add_action('template_redirect', function () {
    if (!is_admin() && isset($_GET['author']) && !is_user_logged_in()) {
        wp_redirect(home_url('/'), 301);
        exit;
    }
});
