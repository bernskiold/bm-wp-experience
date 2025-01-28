<?php
/**
 * Plugin Name: BM WP Experience
 * Plugin URI:  https://www.bernskiold.com
 * Description: Provides an opinionated WordPress experience with clean-up and tweaks that we at Bernskiold Media have found runs WordPress best.
 * Version:     3.11.6
 * Author:      Bernskiold Media
 * Author URI:  https://www.bernskiold.com
 * Text Domain: bm-wp-experience
 * Domain Path: /languages/
 *
 * **************************************************************************
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * **************************************************************************
 *
 * @package BernskioldMedia\WP\Experience
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Autoloader
 */
if ( file_exists( __DIR__ . '/vendor/autoload.php' ) ) {
	require __DIR__ . '/vendor/autoload.php';
} else {
	throw new Exception( 'Autoload does not exist. Please run composer install --no-dev -o.' );
}

/**
 * Basic Constants
 */
define( 'BM_WP_EXPERIENCE_FILE_PATH', __FILE__ );

/**
 * Main Plugin Class Function
 *
 * @return object
 */
function bm_wp_experience() {
	return \BernskioldMedia\WP\Experience\Plugin::instance();
}

// Initialize the class instance only once.
bm_wp_experience();

/**
 * Run update checker if not disabled.
 */
if ( ! defined( 'BM_WP_EXPERIENCE_DISABLE_UPDATER' ) || ( defined( 'BM_WP_EXPERIENCE_DISABLE_UPDATER' ) && false === BM_WP_EXPERIENCE_DISABLE_UPDATER ) ) {
	$bm_wp_experience_updater = Puc_v4_Factory::buildUpdateChecker( 'https://github.com/bernskioldmedia/bm-wp-experience', __FILE__, 'bm-wp-experience' );
	$bm_wp_experience_updater->getVcsApi()->enableReleaseAssets();

	// Add our own plugin icon.
	$bm_wp_experience_updater->addResultFilter( function( $plugin_info ) {
		$plugin_info->icons = [
			'svg' => \BernskioldMedia\WP\Experience\Plugin::get_assets_url( 'icons/bm.svg' ),
		];

		return $plugin_info;
	} );
}
