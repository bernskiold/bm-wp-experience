<?php

namespace Bernskiold\WP\Experience\Integrations;

class DownloadManager extends Integration {
    public static string $plugin_file = 'download-manager/download-manager.php';

    public static function hooks(): void {
        // Hide notice to install WC Admin.
        add_action( 'init', [ self::class, 'update_options' ] );

        add_action( 'admin_menu', [ self::class, 'remove_sub_menus' ], 9999999 );
    }

    public static function update_options(){
        update_option( '__wpdm_gutenberg_editor', 0 );

        $wpdm_scripts = [
            'wpdm-bootstrap-js',
            'wpdm-bootstrap-css',
            'wpdm-font-awesome',
            'wpdm-front'
        ];
        $wpdm_scripts = serialize( $wpdm_scripts );
        update_option( '__wpdm_disable_scripts', $wpdm_scripts );
        update_option( '__wpdm_sanitize_filename', 1 );
        update_option( '__wpdm_google_font', '' );

        update_option( '__wpdm_noip', 1 );
        update_option( '__wpdm_delstats_on_udel', 1 );

    }

    public static function remove_sub_menus(){

        $pages = [
            'wpdm-asset-manager',
            'templates',
            'wpdm-addons',
            'settings'
        ];

        foreach( $pages as $page ){
            remove_submenu_page( 'edit.php?post_type=wpdmpro', $page );
        }
    }
}