<?php
/**
 * Plugin Tweaks & Customizations
 *
 * @package BernskioldMedia\WP\Experience
 **/

namespace BernskioldMedia\WP\Experience;

/**
 * Class Plugins
 *
 * @package BernskioldMedia\WP\Experience
 */
class Plugins {

	/**
	 * Hooks & Actions
	 */
	public static function init() {
		add_filter( 'install_plugins_tabs', [ self::class, 'add_suggested_plugin_install_link' ] );
		add_filter( 'install_plugins_table_api_args_bmedia', [ self::class, 'plugins_api_args' ] );

		add_action( 'install_plugins_pre_featured', [ self::class, 'add_admin_notice' ] );
		add_action( 'install_plugins_pre_popular', [ self::class, 'add_admin_notice' ] );
		add_action( 'install_plugins_pre_favorites', [ self::class, 'add_admin_notice' ] );
		add_action( 'install_plugins_pre_beta', [ self::class, 'add_admin_notice' ] );
		add_action( 'install_plugins_pre_search', [ self::class, 'add_admin_notice' ] );
		add_action( 'install_plugins_pre_dashboard', [ self::class, 'add_admin_notice' ] );

		add_action( 'install_plugins_bmedia', 'display_plugins_table' );

		add_filter( 'plugin_row_meta', [ self::class, 'show_plugin_meta' ], 100, 4 );

		add_action( 'admin_head-plugins.php', [ 'show_deactivation_warning' ] );

	}

	/**
	 * Add 10up suggested tab to plugins install screen
	 *
	 * @param array $tabs
	 *
	 * @return array
	 */
	public static function add_suggested_plugin_install_link( $tabs ) {

		$new_tabs = [
			'bmedia' => esc_html__( 'Bernskiold Media Suggested', 'bm-wp-experience' ),
		];

		foreach ( $tabs as $key => $value ) {
			$new_tabs[ $key ] = $value;
		}

		return $new_tabs;
	}

	/**
	 * We call the plugins_api() to show plugins that we suggest.
	 * Essentially, this is a list of plugins that we have
	 * favourited on our WP.org account.
	 *
	 * This function sets up the args.
	 *
	 * @return array
	 */
	public static function plugins_api_args() {

		$args = [
			'page'     => 1,
			'per_page' => 60,
			'fields'   => [
				'last_updated'    => true,
				'active_installs' => true,
				'icons'           => true,
			],
			'locale'   => get_user_locale(),
			'user'     => 'bernskioldmedia',
		];

		return $args;
	}

	/**
	 * Show admin notice.
	 */
	public static function add_admin_notice() {
		add_action( 'admin_notices', [ self::class, 'display_install_warning' ] );
		add_action( 'network_admin_notices', [ self::class, 'display_install_warning' ] );
	}

	/**
	 * Display a warning when the user is about to install a new plugin.
	 *
	 * @return void
	 */
	public static function display_install_warning() {

		?>
		<div class="notice notice-warning">
			<p>
				<?php
				// translators: 1. Link to Suggested Plugins
				echo wp_kses_post( sprintf( __( "Some plugins may affect the display, performance, and reliability of your website negatively. Please consider <a href='%s'>Bernskiold Media suggestions</a> and if in doubt consult with Bernskiold Media support.", 'tenup' ), esc_url( network_admin_url( 'plugin-install.php?tab=bmedia' ) ) ) );
				?>
			</p>
		</div>
		<?php

	}

	/**
	 * Add a "learn more" link to the plugin row for this plugin that points to the admin page.
	 *
	 * @param array  $plugin_meta An array of the plugin's metadata,
	 *                            including the version, author,
	 *                            author URI, and plugin URI.
	 * @param string $plugin_file Path to the plugin file, relative to the plugins directory.
	 * @param array  $plugin_data An array of plugin data.
	 * @param string $status      Status of the plugin. Defaults are 'All', 'Active',
	 *                            'Inactive', 'Recently Activated', 'Upgrade', 'Must-Use',
	 *                            'Drop-ins', 'Search'.
	 *
	 * @return array
	 */
	public static function show_plugin_meta( $plugin_meta, $plugin_file, $plugin_data, $status ) {

		if ( 'bm-wp-experience/bm-wp-experience.php' !== $plugin_file ) {
			return $plugin_meta;
		}

		$plugin_meta[] = '<a href="' . esc_url( admin_url( 'admin.php?page=bmedia-about' ) ) . '">' . esc_html__( 'Learn More', 'bm-wp-experience' ) . '</a>';

		return $plugin_meta;
	}

	/**
	 * Show a small but friendly warning if the user tries to
	 * disable this plugin.
	 *
	 * @return void
	 */
	public static function show_deactivation_warning() {

		$message = esc_html__( "Warning: This plugin provides additional enterprise-grade protective measures, alongside WordPress core tweaks for an optimal experience. If you deactive, you should consider adding similar protective measuress.\n\nAre you sure you want to deactivate?", 'bm-wp-experience' );

		?>
		<script type="text/javascript">
			jQuery( document ).ready( function( $ ) {
				$( ".wp-list-table.plugins tr[data-slug=\"bm-wp-experience\"] .deactivate" ).on( "click", function( e ) {
					if ( ! window.confirm( '<?php echo esc_js( $message ); ?>' ) ) {
						e.preventDefault();
					}
				} );
			} );
		</script>
		<?php
	}

}

Plugins::init();
