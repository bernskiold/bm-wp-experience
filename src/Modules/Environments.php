<?php
/**
 * Environments
 *
 * We add some staging-related smartness to reduce workload on
 * environments. Such as automatically hiding non-production from Google,
 * as well as having a clear staging message printed.
 *
 * @since   1.4.0
 **/

namespace BernskioldMedia\WP\Experience\Modules;

use BernskioldMedia\WP\Experience\Helpers;
use BernskioldMedia\WP\Experience\Plugin;
use WP_Admin_Bar;

class Environments extends Module {
    public static function hooks(): void {
        add_action( 'admin_bar_menu', [ self::class, 'show_in_admin_bar' ], 40 );
        add_action( 'wp_footer', [ self::class, 'show_public_staging_notice' ] );
        add_filter( 'wp_robots', [ self::class, 'disable_indexing_outside_production' ], 99999 );

        /*
         * Disable admin emails if not on production
         */
        if ( 'production' !== wp_get_environment_type() ) {
            add_filter( 'wp_new_user_notification_email_admin', '__return_false' );
            add_filter( 'wp_password_change_notification_email', '__return_false' );
            add_filter( 'send_site_admin_email_change_email', '__return_false' );
        }
    }

    /**
     * When we are not on production environments, we automatically
     * disable indexing to prevent human mistakes.
     *
     * @since 1.4.0
     */
    public static function disable_indexing_outside_production(array $robots): array {
        if ( 'production' === wp_get_environment_type() ) {
            return $robots;
        }

        if ( false === apply_filters( 'bm_wpexp_environment_disable_indexing_for_non_production', true ) ) {
            return $robots;
        }

        $robots['noindex']  = true;
        $robots['nofollow'] = true;

        return $robots;
    }

    /**
     * Output the public staging notice to the footer,
     * clearly showing when we have a staging environment.
     *
     * @since 1.4.0
     */
    public static function show_public_staging_notice(): void {
        if ( 'staging' !== wp_get_environment_type() ) {
            return;
        }

        if ( false === apply_filters( 'bm_wpexp_environment_show_staging_public', true ) ) {
            return;
        }

        if ( ! self::should_user_see() ) {
            return;
        }

        include Plugin::get_view_path( 'public/staging-message' );
    }

    /**
     * Add a menu bar item showing the current environment.
     *
     * @since 1.4.0
     */
    public static function show_in_admin_bar(WP_Admin_Bar $wp_admin_bar): void {
        if ( false === apply_filters( 'bm_wpexp_environment_show_admin_bar', true ) ) {
            return;
        }

        if ( ! self::should_user_see() ) {
            return;
        }

        $wp_admin_bar->add_node( [
            'id'    => 'bm-environment',
            'title' => self::get_environment_label(),
            'href'  => '#',
            'meta'  => [
                'class' => 'ab-environment-label environment--' . wp_get_environment_type(),
            ],
        ] );
    }

    /**
     * Decide if the user should see the environment notices.
     *
     * For multisites we default to super admins. For standard sites
     * all users that can manage options.
     *
     * @since 1.4.0
     */
    protected static function should_user_see(): bool {
        if ( is_multisite() && Helpers::is_network_active() ) {
            return is_super_admin();
        }

        $required_role = apply_filters( 'bm_wpexp_environment_role', 'manage_options' );

        return current_user_can( $required_role );
    }

    /**
     * Get a human readable label of the current environment.
     *
     * @since 1.4.0
     */
    protected static function get_environment_label(): string {
        $environment = wp_get_environment_type();

        $label = match ( $environment ) {
            'local', 'development' => __( 'Local', 'bm-wp-experience' ),
            'staging'              => __( 'Staging', 'bm-wp-experience' ),
            default                => __( 'Production', 'bm-wp-experience' ),
        };

        return apply_filters( 'bm_wpexp_staging_environment_label', $label, $environment );
    }
}
