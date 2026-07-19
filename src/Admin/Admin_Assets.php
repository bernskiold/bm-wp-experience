<?php
/**
 * Handles the loading of scripts and styles for the
 * theme through the proper enqueuing methods.
 *
 **/

namespace Bernskiold\WP\Experience\Admin;

use Bernskiold\WP\Experience\Plugin;
use Bernskiold\WP\Experience\Core\Hookable;

if (! defined('ABSPATH')) {
    exit;
}

class Admin_Assets implements Hookable {
    public static function hooks(): void {
        add_action('admin_enqueue_scripts', [ self::class, 'admin_styles' ]);
        add_action('admin_enqueue_scripts', [ self::class, 'admin_scripts' ]);

    }

    /**
     * Registers and enqueues plugin admin stylesheets.
     **/
    public static function admin_styles(): void {
        $screen = get_current_screen();

        wp_register_style('bm-wp-experience-admin', Plugin::get_assets_url() . '/styles/dist/admin.css', [], Plugin::get_version());

        wp_enqueue_style('bm-wp-experience-admin');

        if (true === apply_filters('bm_wpexp_custom_admin_theme', true)) {
            wp_register_style('bm-wp-experience-admin-theme', Plugin::get_assets_url() . '/styles/dist/admin-theme.css', [], Plugin::get_version());

            wp_enqueue_style('bm-wp-experience-admin-theme');
        }

        if ( $screen && ( $screen->base === 'post' && $screen->post_type === 'wpdmpro'
            || $screen->base === 'edit-tags' && $screen->post_type === 'wpdmpro' ) ) {
            wp_register_style('bm-wp-experience-admin-download-manager', Plugin::get_assets_url() . '/styles/dist/admin-download-manager.css', [], Plugin::get_version());
            wp_enqueue_style('bm-wp-experience-admin-download-manager');
        }
    }

    public static function admin_scripts():void{
        wp_register_script('bm-wp-experience-customize-support', Plugin::get_assets_url() . '/scripts/admin-customize-support.js', [], Plugin::get_version());

        wp_enqueue_script('bm-wp-experience-customize-support');
        wp_localize_script( 'bm-wp-experience-customize-support', 'bmexp_supports',
            array(
                'allow_autocomplete' => defined('BM_WP_ALLOW_USER_AUTOCOMPLETE') ? BM_WP_ALLOW_USER_AUTOCOMPLETE : false,
            )
        );


    }
}
