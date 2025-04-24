<?php
/**
 * Adjustments to Comments
 */

namespace BernskioldMedia\WP\Experience\Modules;

use BernskioldMedia\WP\Experience\Helpers;
use WP_Admin_Bar;

if (! defined('ABSPATH')) {
    exit;
}

class Comments extends Module {
    public static function hooks(): void {
        // We disable comments by default. Set BM_WP_ENABLE_COMMENTS to true to enable, which skips this function.
        if (defined('BM_WP_ENABLE_COMMENTS') && BM_WP_ENABLE_COMMENTS === true) {
            return;
        }

        add_action('widgets_init', [ self::class, 'remove_recent_comments_widget' ]);
        add_filter('wp_headers', [ self::class, 'remove_pingback_header' ]);
        add_action('template_redirect', [ self::class, 'protect_comment_feeds' ], 9);
        add_action('template_redirect', [ self::class, 'remove_comments_from_admin_bar' ]);
        add_action('admin_init', [ self::class, 'remove_comments_from_admin_bar' ]);
        add_action('admin_init', [ self::class, 'remove_post_type_support' ]);
        add_filter('rest_endpoints', [ self::class, 'remove_comments_from_rest_api' ]);
        add_filter('rest_pre_insert_comment', [ self::class, 'disable_adding_comments_from_rest_api' ]);
        add_filter('xmlrpc_methods', [ self::class, 'disable_comments_via_xmlrpc' ]);

        add_action('admin_menu', [ self::class, 'remove_comments_from_admin_menu' ], 9999);
        add_action('admin_print_styles-index.php', [ self::class, 'hide_comment_counts' ]);
        add_action('admin_print_styles-profile.php', [ self::class, 'hide_comment_counts' ]);
        add_filter('pre_option_default_pingback_flag', '__return_zero');
        add_filter('feed_links_show_comments_feed', '__return_false');

        add_filter('comments_open', '__return_false', 20, 2);
        add_filter('pings_open', '__return_false', 20, 2);
        add_filter('comments_array', '__return_empty_array', 10, 2);

        remove_action('wp_head', 'feed_links_extra', 3);

        add_action('wp_enqueue_scripts', static function () {
            wp_deregister_script('comment-reply');
        });
    }

    public static function remove_post_type_support(): void {
        foreach (get_post_types() as $post_type) {
            if (post_type_supports($post_type, 'comments')) {
                remove_post_type_support($post_type, 'comments');
                remove_post_type_support($post_type, 'trackbacks');
            }
        }
    }

    /**
     * Remove the recent comments widget.
     */
    public static function remove_recent_comments_widget(): void {
        unregister_widget('WP_Widget_Recent_Comments');
        add_filter('show_recent_comments_widget_style', '__return_false');
    }

    /**
     * Remove the X-Pingback HTTP header
     */
    public static function remove_pingback_header(array $headers): array {
        unset($headers['X-Pingback']);

        return $headers;
    }

    /**
     * 403 Protect all Comment Feeds
     */
    public static function protect_comment_feeds(): void {
        if (! is_comment_feed()) {
            return;
        }

        wp_die(__('This site does not support comments.', 'bm-wp-experience'), '', [ 'response' => 403 ]);
    }

    /**
     * Remove comments from admin bar.
     */
    public static function remove_comments_from_admin_bar(): void {
        if (! is_admin_bar_showing()) {
            return;
        }

        remove_action('admin_bar_menu', 'wp_admin_bar_comments_menu', 60);

        if (is_multisite()) {
            add_action('admin_bar_menu', [ self::class, 'remove_comments_from_network_admin_bar' ], 500);
        }
    }

    /**
     * Remove comment links from the admin bar in a multisite network.
     */
    public static function remove_comments_from_network_admin_bar(WP_Admin_Bar $wp_admin_bar): void {
        // If network activated, remove for all sites.
        if (Helpers::is_network_active() && is_user_logged_in()) {
            foreach ((array) $wp_admin_bar->user->blogs as $blog) {
                $wp_admin_bar->remove_menu('blog-' . $blog->userblog_id . '-c');
            }
        } else {
            $wp_admin_bar->remove_menu('blog-' . get_current_blog_id() . '-c');
        }
    }

    /**
     * Remove the comments endpoint from the REST API
     */
    public static function remove_comments_from_rest_api(array $endpoints): array {
        unset($endpoints['comments']);

        return $endpoints;
    }

    /**
     * Disable comments via XMLRPC.
     */
    public static function disable_comments_via_xmlrpc(array $methods): array {
        unset($methods['wp.newComment']);

        return $methods;
    }

    /**
     * Disables adding comments from the REST API.
     *
     * @param array|\WP_Error $prepared_comment
     * @param \WP_REST_Request $request
     */
    public static function disable_adding_comments_from_rest_api($prepared_comment, $request): void {
        return;
    }

    /**
     * Remove comments and discussion settings from the admin menu.
     */
    public static function remove_comments_from_admin_menu(): void {
        global $pagenow;

        remove_menu_page('edit-comments.php');
        remove_submenu_page('options-general.php', 'options-discussion.php');

        if ($pagenow === 'comment.php' || $pagenow === 'edit-comments.php' || $pagenow === 'options-discussion.php') {
            wp_die(__('This site does not support comments.', 'bm-wp-experience'), '', [ 'response' => 403 ]);
        }
    }

    /**
     * Hides comment counts and statements that we cannot
     * remove programatically in any other way.
     */
    public static function hide_comment_counts(): void {
        echo '<style>
			#dashboard_right_now .comment-count,
			#dashboard_right_now .comment-mod-count,
			#latest-comments,
			#welcome-panel .welcome-comments,
			.user-comment-shortcuts-wrap {
				display: none !important;
			}
		</style>';
    }
}
