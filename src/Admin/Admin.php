<?php
/**
 * Admin
 *
 * General admin adjustments.
 *
 **/

namespace BernskioldMedia\WP\Experience\Admin;

use BernskioldMedia\WP\Experience\Modules\Users;
use BMWPEXP_Vendor\BernskioldMedia\WP\PluginBase\Interfaces\Hookable;

class Admin implements Hookable {
    public static function hooks(): void {
        // Remove version from footer.
        add_action( 'admin_menu', [ self::class, 'admin_no_footer_version' ] );
        add_action( 'network_admin_menu', [ self::class, 'admin_no_footer_version' ] );

        // Change admin footer text.
        add_filter( 'admin_footer_text', [ self::class, 'change_admin_footer_text' ] );

        // Remove the help tab.
        add_filter( 'admin_head', [ self::class, 'remove_help_tab' ] );

        // Add our help and support widget.
        add_action( 'admin_footer', [ self::class, 'add_help_widget' ] );

        // Maybe remove ACF from admin.
        add_filter( 'acf/settings/show_admin', [ self::class, 'maybe_show_acf' ] );

        add_action( 'admin_menu', [ self::class, 'maybe_hide_litespeed' ], 999 );
        add_filter( 'current_screen', [ self::class, 'maybe_redirect_litespeed' ], 10 );
    }

    /**
     * Change Admin Footer Text
     */
    public static function change_admin_footer_text(): string {
        /* translators: 1. Site Name */
        $new_text = sprintf( __(
            'Thank you for creating with <a href="https://wordpress.org">WordPress</a> and <a href="https://www.bernskiold.com/en/?utm_source=clientsite&utm_medium=dashboard_link&utm_campaign=%1$s">Bernskiold</a>.',
            'bm-wp-experience'
        ), get_bloginfo( 'name' ) );

        return $new_text;
    }

    /**
     * Admin No Footer Version
     */
    public static function admin_no_footer_version(): void {
        remove_filter( 'update_footer', 'core_update_footer' );
    }

    /**
     * Remove the help tabs.
     */
    public static function remove_help_tab(): void {
        $screen = get_current_screen();

        if ( $screen ) {
            $screen->remove_help_tabs();
        }
    }

    public static function add_help_widget(): void {
        if ( false === apply_filters( 'bm_wpexp_show_help_widget', true ) ) {
            return;
        }

        $user = get_user_by( 'ID', get_current_user_id() ); ?>
		<script type="text/javascript" defer>
			! function( e, t, n ) {
				function a() {
					var e = t.getElementsByTagName( 'script' )[ 0 ], n = t.createElement( 'script' );
					n.type = 'text/javascript', n.async = ! 0, n.src = 'https://beacon-v2.helpscout.net', e.parentNode.insertBefore( n, e );
				}

				if ( e.Beacon = n = function( t, n, a ) {
					e.Beacon.readyQueue.push( { method: t, options: n, data: a } );
				}, n.readyQueue = [], 'complete' === t.readyState ) {
					return a();
				}
				e.attachEvent ? e.attachEvent( 'onload', a ) : e.addEventListener( 'load', a, ! 1 );
			}( window, document, window.Beacon || function() {
			} );</script>
		<script type="text/javascript" defer>
			window.Beacon( 'init', '400d429a-e257-4a5d-bd60-97953b3a81c4' );
			window.Beacon( 'identify', {
				name: '<?php echo $user ? esc_js( $user->first_name . ' ' . $user->last_name ) : ''; ?>',
				email: '<?php echo $user ? esc_js( $user->user_email ) : ''; ?>',
			} );
		</script>
		<?php
    }

    public static function maybe_show_acf(): bool {

        // only hide if is production environment
        if( 'production' !== wp_get_environment_type() ){
            return true;
        }

        // if this is a production environment we want to check that it's not the agency using the site
        return Users::is_agency( wp_get_current_user() );
    }

    public static function maybe_hide_litespeed() {
        if( is_multisite() ){
            if( ! current_user_can('setup_network')){ // is not superadmin
                remove_menu_page( 'litespeed' );
            }
        }
    }

    public static function maybe_redirect_litespeed(){
        if( is_multisite() ){
            if( ! current_user_can('setup_network')){ // is not superadmin
                $current_screen = get_current_screen();
                if(strpos($current_screen->id, 'litespeed') !== false){
                    wp_redirect( admin_url( '' ) );
                    exit;
                }
            }
        }
    }
}
