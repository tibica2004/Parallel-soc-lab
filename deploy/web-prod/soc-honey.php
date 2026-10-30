<?php
/**
 * Plugin Name: SOC honeytoken login
 * Description: Logheaza orice incercare de autentificare cu contul momeala backup_admin.
 *              Nu schimba autentificarea si nu atinge alte conturi.
 *
 * Pasul 3.C (deploy/web-prod/honeytokens-wp.sh il instaleaza in wp-content/mu-plugins).
 * Contul backup_admin NU exista in WordPress: apare doar in momeala backup.sql. Cine il
 * incearca a descarcat backup-ul. Linia ajunge in jurnalul de erori Apache (error_log),
 * de unde regula Kibana soc-honey-wp-login o prinde dupa textul SOC_HONEY.
 *
 * Numele de utilizator primit e date ale atacatorului: nu se logheaza niciodata, se
 * compara doar cu constanta. IP-ul se logheaza doar daca e o adresa valida.
 */

defined( 'ABSPATH' ) || exit;

function soc_honey_is_decoy( $login ) {
	if ( ! is_string( $login ) ) {
		return false;
	}
	$login = strtolower( trim( $login ) );
	return 'backup_admin' === $login || 'backup_admin@localhost' === $login;
}

function soc_honey_log( $event ) {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP ) : false;
	error_log( 'SOC_HONEY event=' . $event . ' user=backup_admin ip=' . ( $ip ? $ip : 'unknown' ) );
}

// wp_login_failed acopera si utilizatorii inexistenti; wp_login doar succesul. Fara
// filtrul authenticate: ar dubla fiecare incercare esuata.
add_action(
	'wp_login_failed',
	function ( $username ) {
		if ( soc_honey_is_decoy( $username ) ) {
			soc_honey_log( 'login_failed' );
		}
	},
	10,
	1
);

add_action(
	'wp_login',
	function ( $user_login ) {
		if ( soc_honey_is_decoy( $user_login ) ) {
			soc_honey_log( 'login_success' );
		}
	},
	10,
	1
);
