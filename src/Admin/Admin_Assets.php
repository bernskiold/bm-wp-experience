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

    public static function admin_scripts(): void {
        $handle     = 'bm-wp-experience-customize-support';
        $asset_file = Plugin::get_path('assets/scripts/dist/admin-customize-support.asset.php');
        $asset      = file_exists($asset_file) ? require $asset_file : [];

        // Printed in the head, as before, so it runs ahead of the editor scripts.
        wp_enqueue_script(
            $handle,
            Plugin::get_assets_url('scripts/dist/admin-customize-support.js'),
            $asset['dependencies'] ?? [],
            $asset['version'] ?? Plugin::get_version()
        );

        wp_add_inline_script(
            $handle,
            'window.bmexp_supports = ' . wp_json_encode([
                'allow_autocomplete' => defined('BM_WP_ALLOW_USER_AUTOCOMPLETE') ? BM_WP_ALLOW_USER_AUTOCOMPLETE : false,
            ]) . ';',
            'before'
        );
    }
}
