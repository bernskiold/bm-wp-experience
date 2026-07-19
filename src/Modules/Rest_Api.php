<?php
/**
 * REST API Tweaks
 *
 * These are additional security tweaks for the REST API
 * that makes it inaccessible unless you are authorized.
 **/

namespace Bernskiold\WP\Experience\Modules;

use WP_Error;
use WP_Query;

class Rest_Api extends Module {
    public static function hooks(): void {
        add_filter('rest_authentication_errors', [ self::class, 'restrict' ], 99);
        add_filter('rest_endpoints', [ self::class, 'restrict_user_endpoints' ]);
        add_filter('determine_current_user', [ self::class, 'handle_basic_auth' ], 20);
        add_filter('posts_orderby', [ self::class, 'posts_orderby' ], 10, 2);
    }

    /**
     * If we have chosen to restrict the REST API, we send a 403
     * status back if we are not authenticated.
     *
     * @param WP_Error|bool|null $result error from another authentication handler,
     *                                   null if we should handle it, or another value
     *                                   if not
     *
     * @return WP_Error|bool|null
     */
    public static function restrict($result) {
        // Respect other handlers
        if (null !== $result) {
            return $result;
        }

        $is_restricted = self::get_restricted_status();

        if ('all' === $is_restricted && ! is_user_logged_in()) {
            return new WP_Error('rest_api_restricted', __('Authentication is required.', 'bm-wp-experience'), [
                'status' => rest_authorization_required_code(),
            ]);
        }

        return $result;
    }

    /**
     * Restrict requests to user endpoints unless authenticated.
     * This will prevent
     *
     * @param array $endpoints Array of endpoints
     */
    public static function restrict_user_endpoints(array $endpoints): array {
        $restrict = self::get_restricted_status();

        if ('none' === $restrict) {
            return $endpoints;
        }

        if (! is_user_logged_in()) {
            $keys = preg_grep('/\/wp\/v2\/users\b/', array_keys($endpoints));

            if ($keys) {
                foreach ($keys as $key) {
                    unset($endpoints[ $key ]);
                }
            }

            return $endpoints;
        }

        return $endpoints;
    }

    /**
     * Get Restriction Status
     *
     * If nothing is set, we default to restricting everything.
     */
    public static function get_restricted_status(): string {
        $level = 'all';

        if (defined('BM_WP_RESTRICT_REST_API')) {
            if (in_array(BM_WP_RESTRICT_REST_API, [ 'all', 'users', 'none' ], true)) {
                $level = BM_WP_RESTRICT_REST_API;
            }
        }

        return apply_filters('bm_wpexp_rest_api_restriction_level', $level);
    }

    /**
     * Handle Basic Authentication
     */
    public static function handle_basic_auth($user) {
        // Don't authenticate twice
        if (! empty($user)) {
            return $user;
        }

        // Check that we're trying to authenticate
        if (! isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
            return $user;
        }

        $username = wp_strip_all_tags($_SERVER['PHP_AUTH_USER']);
        $password = wp_strip_all_tags($_SERVER['PHP_AUTH_PW']);

        /*
         * In multi-site, wp_authenticate_spam_check filter is run on authentication. This filter calls
         * get_currentuserinfo which in turn calls the determine_current_user filter. This leads to infinite
         * recursion and a stack overflow unless the current function is removed from the determine_current_user
         * filter during authentication.
         */
        remove_filter('determine_current_user', [ self::class, 'handle_basic_auth' ], 20);

        $user = wp_authenticate($username, $password);

        add_filter('determine_current_user', [ self::class, 'handle_basic_auth' ], 20);

        if (is_wp_error($user)) {
            return null;
        }

        return $user->ID;
    }

    /**
     * Filters a REST query ordered by menu_order to ensure a repeatable sequence over multiple pages.
     *
     * This can be removed when WordPress core supports pagination of requests ordering on menu_order.
     *
     * @see https://core.trac.wordpress.org/ticket/46294
     *
     * @param string   $orderby current orderby value
     * @param WP_Query $query   query object
     */
    public static function posts_orderby(string $orderby, WP_Query $query): string {
        global $wpdb;

        if (defined('REST_REQUEST') && REST_REQUEST) {
            if (isset($query->query['orderby']) && 'menu_order' === $query->query['orderby']) {
                $orderby = "$wpdb->posts.menu_order,$wpdb->posts.post_title,$wpdb->posts.id " . $query->query['order'];
            }
        }

        return $orderby;
    }
}
