<?php
/**
 * PHPUnit bootstrap for the WordPress integration test suite.
 *
 * Runs against a real WordPress install and its PHPUnit test library. Install
 * both (and print the environment variables to export) with:
 *
 *   bin/install-wp-tests.sh [wp-version] [db-name] [db-user] [db-pass] [db-host]
 *
 * then run `composer test`.
 *
 * @package Bernskiold\WP\Experience
 */

// Locate the WordPress test library: WP_TESTS_DIR (wp-env), WP_PHPUNIT__DIR
// (wp-phpunit/wp-phpunit, used by bin/install-wp-tests.sh) or the temp dir.
$_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( ! $_tests_dir ) {
	$_tests_dir = getenv( 'WP_PHPUNIT__DIR' );
}

if ( ! $_tests_dir ) {
	$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
}

// Point the WP test suite at the Yoast PHPUnit polyfills bundled via Composer.
if ( ! defined( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH' ) ) {
	$_polyfills = dirname( __DIR__, 2 ) . '/vendor/yoast/phpunit-polyfills';

	if ( is_dir( $_polyfills ) ) {
		define( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH', $_polyfills );
	}
}

$_functions = "{$_tests_dir}/includes/functions.php";

if ( ! file_exists( $_functions ) ) {
	echo "Could not find the WordPress test library at {$_tests_dir}." . PHP_EOL;
	echo 'Install it with bin/install-wp-tests.sh and export the variables it prints.' . PHP_EOL;
	exit( 1 );
}

// Give access to tests_add_filter() before WordPress loads.
require_once $_functions;

/**
 * Manually load the plugin under test.
 */
function _manually_load_bm_wp_experience(): void {
	// The update checker talks to GitHub; keep the test run offline.
	if ( ! defined( 'BM_WP_EXPERIENCE_DISABLE_UPDATER' ) ) {
		define( 'BM_WP_EXPERIENCE_DISABLE_UPDATER', true );
	}

	// Constants are fixed per process, so the suite runs with two-factor
	// authentication required (the stricter configuration).
	if ( ! defined( 'BM_WP_REQUIRE_TWO_FACTOR' ) ) {
		define( 'BM_WP_REQUIRE_TWO_FACTOR', true );
	}

	require dirname( __DIR__, 2 ) . '/bm-wp-experience.php';
}

tests_add_filter( 'muplugins_loaded', '_manually_load_bm_wp_experience' );

// Start up the WP testing environment.
require "{$_tests_dir}/includes/bootstrap.php";

require_once __DIR__ . '/TestCase.php';
require_once __DIR__ . '/Redirect_Exception.php';
require_once __DIR__ . '/Template_Exception.php';
