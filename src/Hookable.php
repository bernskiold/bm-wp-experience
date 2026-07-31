<?php
/**
 * Hookable
 *
 * @package BernskioldMedia\WP\Experience
 */

namespace BernskioldMedia\WP\Experience;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface Hookable {

	/**
	 * Hookable classes must implement a standardized hooks function
	 * that can be called when booted.
	 */
	public static function hooks(): void;
}
