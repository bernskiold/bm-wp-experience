<?php

namespace BernskioldMedia\WP\Experience\Integrations;

class WooCommerce extends Integration {
    public static string $plugin_file = 'woocommerce/woocommerce.php';

    public static function hooks(): void {
        // Disable startup wizard.
        add_filter( 'woocommerce_enable_setup_wizard', '__return_false', 20 );

        // Disable marketing.
        add_filter( 'woocommerce_marketing_menu_items', '__return_empty_array' );
        add_filter( 'woocommerce_admin_features', [ self::class, 'disable_marketing_features' ] );

        /*
         * Suppress notices about connecting your store to woocommerce to receive updates and extensions.
         * Also suppress general message for woocommerce.com plugin
         */
        add_filter( 'woocommerce_helper_suppress_admin_notices', '__return_true' );

        // No suggestions from WooCommerce marketplace.
        add_filter( 'woocommerce_allow_marketplace_suggestions', '__return_false', 999 );

        /* Jetpack promotions*/
        add_filter( 'jetpack_just_in_time_msgs', '__return_false', 20 );
        add_filter( 'jetpack_show_promotions', '__return_false', 20 );

        // Remove extension library from menus.
        add_action( 'admin_menu', static function () {
            remove_submenu_page( 'woocommerce', 'wc-addons' );
            remove_submenu_page( 'woocommerce', 'wc-addons&section=helper' );
        }, 99 );

        // Remove SkyVerge support dashboard.
        add_action( 'admin_menu', static function () {
            remove_menu_page( 'skyverge' );
        }, 99 );
        add_action( 'admin_enqueue_scripts', static function () {
            wp_dequeue_style( 'sv-wordpress-plugin-admin-menus' );
        }, 20 );

        // Hide WooCommerce dashboard widgets.
        add_action( 'wp_dashboard_setup', [ self::class, 'hide_woocommerce_dashboard_widgets' ] );

        // Remove WooCommerce widgets.
        add_action( 'widgets_init', [ self::class, 'unregister_woocommerce_widgets' ], 99 );

        // Hide notice to install WC Admin.
        add_filter( 'woocommerce_show_admin_notice', [ self::class, 'hide_wc_admin_install_notice' ], 10, 2 );

        // Remove Processing Order Count in wp-admin.
        add_filter( 'woocommerce_menu_order_count', '__return_false' );

        // Delete the WooCommerce usage tracker cron event
        wp_clear_scheduled_hook( 'woocommerce_tracker_send_event' );

        // Disable password strength meter.
        add_action( 'wp_print_scripts', [ self::class, 'disable_password_strength_meter' ], 100 );

        // Disable assets on non-woocommerce pages.
        add_action( 'wp_enqueue_scripts', [ self::class, 'disable_assets' ], 99 );

        // Disable fragments on non-woocommerce pages.
        add_action( 'wp_enqueue_scripts', [ self::class, 'disable_fragments' ], 99 );
    }

    public static function disable_marketing_features(array $features): array {
        $marketing = array_search( 'marketing', $features, true );

        if ( false !== $marketing ) {
            unset( $features[ $marketing ] );
        }

        return $features;
    }

    public static function hide_woocommerce_dashboard_widgets(): void {
        // Status
        remove_meta_box( 'woocommerce_dashboard_status', 'dashboard', 'normal' );

        // Setup help
        remove_meta_box( 'wc_admin_dashboard_setup', 'dashboard', 'normal' );

        // Elementor
        remove_meta_box( 'e-dashboard-overview', 'dashboard', 'normal' );
    }

    public static function unregister_woocommerce_widgets(): void {
        $widgets = apply_filters( 'bm_wpexp_woocommerce_widgets', [
            'WC_Widget_Products',
            'WC_Widget_Product_Categories',
            'WC_Widget_Product_Tag_Cloud',
            'WC_Widget_Cart',
            'WC_Widget_Layered_Nav',
            'WC_Widget_Layered_Nav_Filters',
            'WC_Widget_Price_Filter',
            'WC_Widget_Product_Search',
            'WC_Widget_Recently_Viewed',
            'WC_Widget_Recent_Reviews',
            'WC_Widget_Top_Rated_Products',
            'WC_Widget_Rating_Filter',
        ] );

        foreach ( $widgets as $widget ) {
            unregister_widget( $widget );
        }
    }

    public static function hide_wc_admin_install_notice(bool $notice_enabled, string $notice): bool {
        if ( 'wc_admin' === $notice ) {
            return false;
        }

        return $notice_enabled;
    }

    public static function disable_password_strength_meter(): void {
        if ( false === apply_filters( 'bm_wpexp_woocommerce_disable_password_strength_meter', true ) ) {
            return;
        }

        global $wp;

        $is_wp = isset( $wp->query_vars['lost-password'] ) || ( isset( $_GET['action'] ) && $_GET['action'] === 'lostpassword' ) || is_page( 'lost_password' );
        $is_wc = false;
        if( function_exists( 'is_account_page')){
            $is_wc = is_account_page() || is_checkout();
        }

        if ( ! $is_wp && ! $is_wc ) {
            if ( wp_script_is( 'zxcvbn-async', 'enqueued' ) ) {
                wp_dequeue_script( 'zxcvbn-async' );
            }

            if ( wp_script_is( 'password-strength-meter', 'enqueued' ) ) {
                wp_dequeue_script( 'password-strength-meter' );
            }

            if ( wp_script_is( 'wc-password-strength-meter', 'enqueued' ) ) {
                wp_dequeue_script( 'wc-password-strength-meter' );
            }
        }
    }

    public static function disable_assets(): void {
        if ( false === apply_filters( 'bm_wpexp_woocommerce_disable_assets_on_non_woo_pages', true ) ) {
            return;
        }

        if( !function_exists( 'is_woocommerce')){
            return;
        }

        if ( ! is_woocommerce() && ! is_cart() && ! is_checkout() && ! is_account_page() && ! is_product() && ! is_product_category() && ! is_shop() ) {
            //Dequeue WooCommerce Styles
            wp_dequeue_style( 'woocommerce-general' );
            wp_dequeue_style( 'woocommerce-layout' );
            wp_dequeue_style( 'woocommerce-smallscreen' );
            wp_dequeue_style( 'woocommerce_frontend_styles' );
            wp_dequeue_style( 'woocommerce_fancybox_styles' );
            wp_dequeue_style( 'woocommerce_chosen_styles' );
            wp_dequeue_style( 'woocommerce_prettyPhoto_css' );

            //Dequeue WooCommerce Scripts
            wp_dequeue_script( 'wc_price_slider' );
            wp_dequeue_script( 'wc-single-product' );
            wp_dequeue_script( 'wc-add-to-cart' );
            wp_dequeue_script( 'wc-checkout' );
            wp_dequeue_script( 'wc-add-to-cart-variation' );
            wp_dequeue_script( 'wc-single-product' );
            wp_dequeue_script( 'wc-cart' );
            wp_dequeue_script( 'wc-chosen' );
            wp_dequeue_script( 'woocommerce' );
            wp_dequeue_script( 'prettyPhoto' );
            wp_dequeue_script( 'prettyPhoto-init' );
            wp_dequeue_script( 'jquery-blockui' );
            wp_dequeue_script( 'jquery-placeholder' );
            wp_dequeue_script( 'fancybox' );
            wp_dequeue_script( 'jqueryui' );
        }
    }

    public static function disable_fragments(): void {
        if ( false === apply_filters( 'bm_wpexp_woocommerce_disable_fragments_on_non_woo_pages', true ) ) {
            return;
        }

        if( !function_exists( 'is_woocommerce')){
            return;
        }

        if ( ! is_woocommerce() && ! is_cart() && ! is_checkout() && ! is_account_page() && ! is_product() && ! is_product_category() && ! is_shop() ) {
            wp_dequeue_script( 'wc-cart-fragments' );
        }
    }
}
