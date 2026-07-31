<?php
/**
 * Installer
 */

namespace BernskioldMedia\WP\Experience;

use BernskioldMedia\WP\Experience\Modules\Htaccess\ResponseHeaders;
use BernskioldMedia\WP\Experience\Modules\Htaccess\XMLRPC_Protection;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Install {

	public static function install(): void {
		if ( method_exists( static::class, 'scheduled_tasks' ) ) {
			static::scheduled_tasks();
		}

		flush_rewrite_rules();

		if ( true === apply_filters( 'bm_wpexp_modify_htaccess_on_install', true ) ) {
			ResponseHeaders::activate();
			XMLRPC_Protection::activate();
		}
	}
}
