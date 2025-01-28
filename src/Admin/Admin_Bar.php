<?php
/**
 * Add options to the admin bar.
 *
 **/

namespace BernskioldMedia\WP\Experience\Admin;

use BernskioldMedia\WP\Experience\Modules\Updates;
use BernskioldMedia\WP\Experience\Plugin;
use BMWPEXP_Vendor\BernskioldMedia\WP\PluginBase\Interfaces\Hookable;
use WP_Admin_Bar;

if (! defined('ABSPATH')) {
    exit;
}

class Admin_Bar implements Hookable {
    public static function hooks(): void {
        add_action('admin_bar_menu', [ self::class, 'about_bm' ]);
        add_action('admin_bar_menu', [ self::class, 'support' ], 60);
        add_action('admin_bar_menu', [ self::class, 'customizer' ], 60);
        add_action('admin_bar_menu', [ self::class, 'remove' ], 999999);

        add_action('wp_enqueue_scripts', [ self::class, 'assets' ]);
        add_action('admin_enqueue_scripts', [ self::class, 'assets' ]);

        // Remove "howdy" from admin bar.
        add_action( 'admin_bar_menu', [ self::class, 'remove_howdy' ], 11 );
    }

    /**
     * Load admin bar assets.
     */
    public static function assets(): void {
        wp_register_style('bm-admin-bar', Plugin::get_assets_url('styles/dist/admin-bar.css'), [], Plugin::get_version(), 'all');

        if (is_admin_bar_showing()) {
            wp_enqueue_style('bm-admin-bar');
        }
    }

    /**
     * Remove certain items from the admin bar,
     * that are most often irrelevant for our users.
     *
     * Nodes can be designated as "always", "admin" or "frontend"
     * to choose where we will remove them from.
     *
     * @param WP_Admin_Bar $wp_admin_bar
     */
    public static function remove($wp_admin_bar): void {
        $nodes_to_remove = apply_filters('bm_wpexp_remove_admin_bar_items', [
            'wp-logo'    => 'always',
            'comments'   => 'always',
            'wpseo-menu' => 'always',
            'new_draft'  => 'always',
            'customize'  => 'always',
            'updates'    => Updates::is_on_maintenance_plan() ? 'always' : 'frontend',
        ]);

        foreach ($nodes_to_remove as $id => $place) {
            if (is_admin() && 'admin' === $place) {
                $wp_admin_bar->remove_node($id);
            }

            if (! is_admin() && 'frontend' === $place) {
                $wp_admin_bar->remove_node($id);
            }

            if ('always' === $place) {
                $wp_admin_bar->remove_node($id);
            }
        }
    }

    /**
     * Add a "Support" menu item to the admin bar.
     *
     * @param WP_Admin_Bar $wp_admin_bar
     */
    public static function support($wp_admin_bar): void {
        /*
         * Allow the option of hiding the admin bar
         * links via a filter.
         */
        if (false === apply_filters('bm_wpexp_show_admin_bar_support', true)) {
            return;
        }

        /*
         * Hide the admin bar link in admin.
         */
        if (is_admin()) {
            return;
        }

        $wp_admin_bar->add_node([
            'id'    => 'bm-support',
            'title' => '<span class="bm-support-icon"></span> ' . esc_html__('Help & Support', 'bm-wp-experience'),
            'href'  => esc_url(apply_filters('bm_wpexp_admin_bar_support_url', admin_url('admin.php?page=bm-support'))),
            'meta'  => [
                'title' => esc_html__('Help & Support', 'bm-wp-experience'),
                'class' => 'ab-help-support',
            ],
        ]);
    }

    /**
     * Re-hooking the customizer to place it under the home
     * menu item on frontend.
     *
     * @param WP_Admin_Bar $wp_admin_bar
     */
    public static function customizer($wp_admin_bar): void {
        /*
         * Hide the admin bar link in admin.
         */
        if (is_admin()) {
            return;
        }

        $wp_admin_bar->add_node([
            'id'     => 'bm-customizer',
            'parent' => 'site-name',
            'title'  => esc_html__('Customize', 'bm-wp-experience'),
            'href'   => esc_url(admin_url('customize.php')),
            'meta'   => [
                'title' => esc_html__('Customize the site appearance.', 'bm-wp-experience'),
                'class' => 'ab-customizer',
            ],
        ]);
    }

    /**
     * Add an "About BM" menu item to the admin bar.
     *
     * @param WP_Admin_Bar $wp_admin_bar
     */
    public static function about_bm($wp_admin_bar): void {
        /*
         * Allow the option of hiding the admin bar
         * links via a filter.
         */
        if (false === apply_filters('bm_wpexp_show_admin_bar_bm', true)) {
            return;
        }

        if (is_user_logged_in() && current_user_can('edit_posts')) {
            $wp_admin_bar->add_node([
                'id'    => 'bm',
                'title' => '<div class="bm-icon ab-item"><span class="screen-reader-text">' . esc_html__('Bernskiold', 'bm-wp-experience') . '</span></div>',
                'href'  => admin_url('admin.php?page=bm-about'),
                'meta'  => [
                    'title' => 'Bernskiold',
                ],
            ]);

            $wp_admin_bar->add_node([
                'id'     => 'bm-about',
                'parent' => 'bm',
                'title'  => esc_html__('About Bernskiold', 'bm-wp-experience'),
                'href'   => esc_url(admin_url('admin.php?page=bm-about')),
                'meta'   => [
                    'title' => esc_html__('About Bernskiold', 'bm-wp-experience'),
                ],
            ]);

            $wp_admin_bar->add_group([
                'parent' => 'bm',
                'id'     => 'bm-list',
                'meta'   => [
                    'class' => 'ab-sub-secondary',
                ],
            ]);

            $wp_admin_bar->add_node([
                'id'     => 'bm-academy',
                'parent' => 'bm-list',
                'title'  => esc_html__('Academy', 'bm-wp-experience'),
                'href'   => esc_url(_x('https://www.bernskiold.com/en/academy/', 'BM Academy URL', 'bm-wp-experience')),
                'meta'   => [
                    'title' => esc_html__('Academy', 'bm-wp-experience'),
                ],
            ]);

            $wp_admin_bar->add_node([
                'id'     => 'bm-support',
                'parent' => 'bm-list',
                'title'  => esc_html__('Support', 'bm-wp-experience'),
                'href'   => esc_url(_x('https://support.bernskiold.com/', 'BM Support URL', 'bm-wp-experience')),
                'meta'   => [
                    'title' => esc_html__('Support', 'bm-wp-experience'),
                ],
            ]);

            $wp_admin_bar->add_node([
                'id'     => 'bm-services',
                'parent' => 'bm-list',
                'title'  => esc_html__('Services', 'bm-wp-experience'),
                'href'   => esc_url(_x('https://www.bernskiold.com/en/services/', 'BM Services URL', 'bm-wp-experience')),
                'meta'   => [
                    'title' => esc_html__('Services', 'bm-wp-experience'),
                ],
            ]);
        }
    }

    public static function remove_howdy(WP_Admin_Bar $wp_admin_bar): void {
        $current_user = wp_get_current_user();
        $avatar       = get_avatar( $current_user->ID, 28 );

        $wp_admin_bar->add_node( [
            'id'    => 'my-account',
            'title' => $current_user->display_name . $avatar,
        ] );
    }
}
