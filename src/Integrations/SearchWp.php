<?php

namespace Bernskiold\WP\Experience\Integrations;

class SearchWp extends Integration {
    public static string $plugin_file = 'searchwp/index.php';

    public static function hooks(): void {
        // Add support for adding the license dynamically.
        add_filter( 'searchwp\license\key', static function () {
            return defined( 'SEARCH_WP_LICENSE_KEY' ) ? SEARCH_WP_LICENSE_KEY : null;
        } );

        // Disable SearchWP Admin Bar entry.
        add_filter( 'searchwp\admin_bar', '__return_false' );
    }
}
