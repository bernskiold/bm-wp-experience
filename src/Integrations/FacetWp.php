<?php

namespace Bernskiold\WP\Experience\Integrations;

class FacetWp extends Integration {
    public static string $plugin_file = 'facetwp/index.php';

    public static function hooks(): void {
        /**
         * set is_main_query to false to stop facetwp to alter tribe_events queries causing events to
         * display in the wrong order if used in our BM Block Library
         */
        add_filter( 'facetwp_is_main_query', function( $is_main_query, $query ) {
            if ( 'tribe_events' == $query->get( 'post_type' ) ) {
                $is_main_query = false;
            }
            return $is_main_query;
        }, 10, 2 );
    }
}