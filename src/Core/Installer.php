<?php

namespace BernskioldMedia\WP\Experience\Core;

defined( 'ABSPATH' ) || exit;

/**
 * Installer
 *
 * Base class for the plugin activation routine.
 */
abstract class Installer {

	public static function install(): void {
		if ( method_exists( static::class, 'scheduled_tasks' ) ) {
			static::scheduled_tasks();
		}

		flush_rewrite_rules();
	}

}
