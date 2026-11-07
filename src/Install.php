<?php
/**
 * Installer
 */

namespace Bernskiold\WP\Experience;

use Bernskiold\WP\Experience\Modules\Htaccess\ResponseHeaders;
use Bernskiold\WP\Experience\Modules\Htaccess\XMLRPC_Protection;
use Bernskiold\WP\Experience\Core\Installer;
use Bernskiold\WP\Experience\Modules\XML_RPC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Install extends Installer {

	public static function install(): void {
		parent::install();

		if ( true === apply_filters( 'bm_wpexp_modify_htaccess_on_install', true ) ) {
			ResponseHeaders::activate();

			// Keep the .htaccess rule in line with the PHP-level setting.
			if ( XML_RPC::is_disabled() ) {
				XMLRPC_Protection::activate();
			} else {
				XMLRPC_Protection::deactivate();
			}
		}
	}
}
