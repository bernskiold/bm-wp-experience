<?php

namespace BernskioldMedia\WP\Experience\Core;

/**
 * Hookable
 *
 * Hookable classes implement a standardized hooks() method that is called
 * when the class is booted by the plugin.
 */
interface Hookable {

	public static function hooks(): void;

}
