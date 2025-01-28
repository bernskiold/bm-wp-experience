<?php
/**
 * Dashboard Extensions
 *
 * Remove unnecessary dashboard widgets, and add
 * some custom ones too.
 */

namespace BernskioldMedia\WP\Experience\Modules;

use BernskioldMedia\WP\Experience\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Dashboard extends Module {
    public static function hooks(): void {
        add_action('wp_dashboard_setup', [ self::class, 'remove_dashboard_widgets' ]);
        add_action('wp_network_dashboard_setup', [ self::class, 'remove_dashboard_widgets' ]);
        add_action('wp_user_dashboard_setup', [ self::class, 'remove_dashboard_widgets' ]);

        add_action('wp_dashboard_setup', [ self::class, 'add_bm_academy_dashboard_widget' ]);
    }

    /**
     * Remove Dashboard Widgets
     */
    public static function remove_dashboard_widgets(): void {
        remove_meta_box('dashboard_primary', get_current_screen(), 'side');
        remove_meta_box('dashboard_secondary', get_current_screen(), 'side');
        remove_meta_box('dashboard_plugins', get_current_screen(), 'normal');
        remove_meta_box('dashboard_incoming_links', get_current_screen(), 'normal');
        remove_meta_box('dashboard_quick_press', get_current_screen(), 'side');
        remove_meta_box('dashboard_recent_drafts', get_current_screen(), 'side');
        remove_meta_box('simple_history_dashboard_widget', get_current_screen(), 'normal');

        remove_meta_box('wpseo-dashboard-overview', get_current_screen(), 'side');

        if (Updates::is_on_maintenance_plan()) {
            remove_meta_box('dashboard_site_health', 'dashboard', 'normal');
        }
    }

    public static function add_bm_academy_dashboard_widget(): void {
        wp_add_dashboard_widget('bm_academy', __('Bernskiold Media Academy', 'bm-wp-experience'), static function () {
            $feed = fetch_feed(_x('https://bernskiold.com/en/feed/', 'academy feed', 'bm-wp-experience'));

            if (is_wp_error($feed)) {
                echo __('Unfortunately the academy content is not currently available.', 'bm-wp-experience');
            } else {
                $feed->init();
                $feed->set_output_encoding('UTF-8');
                $feed->handle_content_type();
                $feed->set_cache_duration(21600);
                $limit = $feed->get_item_quantity(5);
                $items = $feed->get_items(0, $limit);

                include Plugin::get_view_path('dashboard-widgets/academy-feed');
            }
        }, null, null, 'side');
    }
}
