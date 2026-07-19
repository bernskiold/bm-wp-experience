<?php
/**
 * Admin Columns
 *
 **/

namespace Bernskiold\WP\Experience\Admin;

use Bernskiold\WP\Experience\Helpers;
use Bernskiold\WP\Experience\Plugin;
use Bernskiold\WP\Experience\Core\Hookable;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Admin_Columns implements Hookable {
    public static function hooks(): void {
        $acp_file_path = 'admin-columns-pro/admin-columns-pro.php';

        if ( Helpers::is_plugin_active( $acp_file_path ) || Helpers::is_plugin_active_for_network( $acp_file_path ) ) {
            self::create_repository();
        }
    }

    public static function create_repository(): void {
        add_filter( 'acp/storage/repositories', function ($repositories, $factory) {
            /*
             * Developers!
             *
             * When you want to save new ACP columns to this repository,
             * set the second arg "false" to "true".
             *
             * Remember to set this back to "false" before shipping.
             * We need the repository to be read-only.
             */
            $repositories['bm_wp_experience'] = $factory->create( Plugin::get_path() . '/acp-columns', false );

            return $repositories;
        }, 20, 2 );
    }
}
