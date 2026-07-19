<?php
/**
 * Cleanup WordPress Output
 *
 * Some things added to WordPress are not things we need.
 * These are cleanup and tweaks functions.
 */

namespace Bernskiold\WP\Experience\Modules;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Cleanup extends Module {
    public static function hooks(): void {
        // Clean up wp_head().
        self::wp_head_cleanup();

        // Remove WordPress Version from RSS Feeds.
        add_filter( 'the_generator', '__return_false' );

        // Rewrites the search URL.
        add_action( 'template_redirect', [ self::class, 'nice_search_url' ] );
        add_action('parse_query', [ self::class, 'query_vars_search_filter' ]);

        // Blank Search Query Fix.
        add_filter( 'request', [ self::class, 'blank_search_fix' ] );

        // Disable Jetpack promotions.
        add_filter( 'jetpack_just_in_time_msgs', '__return_false', 20 );
        add_filter( 'jetpack_show_promotions', '__return_false', 20 );
    }

    /**
     * Clean up wp_head() from unnecessary bloat.
     *
     * Remove unnecessary <link>'s
     */
    public static function wp_head_cleanup(): void {
        if ( self::should_disable_feed_urls() ) {
            remove_action( 'wp_head', 'feed_links', 2 );
            remove_action( 'wp_head', 'feed_links_extra', 3 );
        }

        remove_action( 'wp_head', 'rsd_link' );
        remove_action( 'wp_head', 'wlwmanifest_link' );
        remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10 );
        remove_action( 'wp_head', 'wp_generator' );
        remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );

        // all actions related to emojis.
        remove_action( 'admin_print_styles', 'print_emoji_styles' );
        remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
        remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
        remove_action( 'wp_print_styles', 'print_emoji_styles' );
        remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );
        remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
        remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );

        // filter to remove TinyMCE emojis.
        add_filter( 'tiny_mce_plugins', [ self::class, 'disable_emojicons_tinymce' ] );

        if ( true === apply_filters( 'bm_wpexp_disable_public_rest_api', true ) ) {
            remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
            remove_action( 'template_redirect', 'rest_output_link_header', 11 );
        }

        if ( true === apply_filters( 'bm_wpexp_disable_oembed_discovery', true ) ) {
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );
        }
    }

    /**
     * Disable Emojis in TincyMCE
     *
     * @param array $plugins active Plugins Array
     */
    public static function disable_emojicons_tinymce($plugins): array {
        return array_diff( $plugins, [ 'wpemoji' ] );
    }

    /**
     * Redirects search results from /?s=query to /search/query/
     * and converts %20 to + in the URL.
     *
     * @see http://txfx.net/wordpress-plugins/nice-search/
     * @see https://github.com/roots/roots/blob/master/lib/cleanup.php
     */
    public static function nice_search_url(): void {
        global $wp_rewrite;

        if ( defined('BM_WP_PRETTIFY_SEARCH_URL') && BM_WP_PRETTIFY_SEARCH_URL === false ) {
            return;
        }

        if ( ! isset( $wp_rewrite ) || ! is_object( $wp_rewrite ) || ! $wp_rewrite->using_permalinks() ) {
            return;
        }

        $search_base = $wp_rewrite->search_base;

        if ( is_search() && ! is_admin() && ! str_contains( $_SERVER['REQUEST_URI'] ?? '', "/{$search_base}/" ) ) {
            wp_safe_redirect( home_url( "/{$search_base}/" . rawurlencode( get_query_var( 's' ) ) ) );
            exit();
        }
    }

    /**
     * URL decode our search result to be able to search and display the search query properly
     * Special characters will otherwise look weird
     *
     * @param  \WP_Query  $query
     */
    public static function query_vars_search_filter( $query ): void {
        if ($query->is_search && !is_admin()) {
            $query->query_vars['s'] = urldecode( $query->query_vars['s'] );
        }
    }

    /**
     * Fix for empty search queries redirecting to home page
     *
     * @see http://wordpress.org/support/topic/blank-search-sends-you-to-the-homepage#post-1772565
     * @see http://core.trac.wordpress.org/ticket/11330
     * @see https://github.com/roots/roots/blob/master/lib/cleanup.php
     *
     * @param array $query_vars query Vars
     */
    public static function blank_search_fix(array $query_vars): array {
        if ( isset( $_GET['s'] ) && empty( $_GET['s'] ) && ! is_admin() ) {
            $query_vars['s'] = ' ';
        }

        return $query_vars;
    }

    /**
     * Lets you select in the application config whether to
     * disable feed URLs in the <head> or not.
     *
     * If undefined, defaults to true = disable.
     */
    protected static function should_disable_feed_urls(): bool {
        if ( ! defined( 'BM_WP_DISABLE_FEED_URLS' ) ) {
            return true;
        }

        return BM_WP_DISABLE_FEED_URLS;
    }
}
