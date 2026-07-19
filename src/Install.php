<?php
/**
 * Installer
 */

namespace BernskioldMedia\WP\Experience;

use BernskioldMedia\WP\Experience\Modules\Htaccess\ResponseHeaders;
use BernskioldMedia\WP\Experience\Modules\Htaccess\XMLRPC_Protection;
use BernskioldMedia\WP\Experience\Core\Installer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Install extends Installer {

	public static function install(): void {
		parent::install();

		if ( true === apply_filters( 'bm_wpexp_modify_htaccess_on_install', true ) ) {
			ResponseHeaders::activate();
			XMLRPC_Protection::activate();
		}
	}
}
