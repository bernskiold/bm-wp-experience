<?php

namespace BernskioldMedia\WP\Experience;

use BernskioldMedia\WP\Experience\Modules\Security\TwoFactorAuthentication;

class Plugin {

	protected static string $slug = 'bm-wp-experience';
	protected static string $version = '3.11.6';
	protected static string $database_version = '1000';
	protected static string $textdomain = 'bm-wp-experience';
	protected static string $plugin_file_path = BM_WP_EXPERIENCE_FILE_PATH;

	protected static ?self $instance = null;

	protected static array $boot = [
		Admin\Admin_Bar::class, // Boots publicly because it is loaded in public views too.
		TwoFactorAuthentication::class,
	];

	protected static array $admin_boot = [
		Admin\Admin::class,
		Admin\Admin_Assets::class,
		Admin\Admin_Columns::class,
		Admin\Admin_Pages::class,
        Admin\Admin_Analytics_Tab::class,
        Admin\Admin_Mail_Tab::class,
	];

	protected static array $modules = [
		Modules\Admin_Ad_Blocker::class,
		Modules\Block_Editor::class,
		Modules\Cleanup::class,
		Modules\Comments::class,
		Modules\Customizer::class,
		Modules\Dashboard::class,
		Modules\Environments::class,
		Modules\Mail::class,
		Modules\Matomo::class,
        Modules\Matomo_Sync::class,
		Modules\Media::class,
		Modules\Multisite::class,
		Modules\Plugins::class,
		Modules\Rest_Api::class,
		Modules\Security::class,
		Modules\Site_Health::class,
		Modules\Updates::class,
		Modules\Users::class,
	];

	protected static array $integrations = [
        Integrations\DownloadManager::class,
        Integrations\FacetWp::class,
		Integrations\SearchWp::class,
		Integrations\WooCommerce::class,
		Integrations\SSPodcast::class,
	];

	public static function instance(): self {
		return self::$instance ??= new self();
	}

	public function __construct() {
		$this->init_hooks();

		do_action( self::$slug . '_loaded' );

		self::boot_modules();
		self::boot_integrations();

		if ( is_admin() && ! empty( self::$admin_boot ) ) {
			self::boot_admin();
		}

		register_activation_hook( self::$plugin_file_path, [ Install::class, 'install' ] );
	}

	protected function init_hooks(): void {
		do_action( self::$slug . '_init_hooks' );

		add_action( 'init', [ self::class, 'load_languages' ] );

		foreach ( self::$boot as $bootable_class ) {
			$bootable_class::hooks();
		}
	}

	/**
	 * Load plugin translations.
	 */
	public static function load_languages(): void {
		$textdomain = self::get_textdomain();
		$locale     = is_admin() ? get_user_locale() : get_locale();
		$locale     = apply_filters( 'plugin_locale', $locale, $textdomain );

		unload_textdomain( $textdomain );

		// Start checking in the main language dir.
		load_textdomain( $textdomain, WP_LANG_DIR . '/' . $textdomain . '/' . $textdomain . '-' . $locale . '.mo' );

		// Otherwise, load from the plugin.
		load_plugin_textdomain( $textdomain, false, dirname( plugin_basename( self::$plugin_file_path ) ) . '/languages' );
	}

	/**
	 * Get the path to the plugin folder, or the specified
	 * file relative to the plugin folder home.
	 */
	public static function get_path( string $file = '' ): string {
		return untrailingslashit( plugin_dir_path( self::$plugin_file_path ) ) . '/' . $file;
	}

	/**
	 * Get the URL to the plugin folder, or the specified
	 * file relative to the plugin folder home.
	 */
	public static function get_url( string $file = '' ): string {
		return untrailingslashit( plugin_dir_url( self::$plugin_file_path ) ) . '/' . $file;
	}

	/**
	 * Get the URL to the assets folder, or the specified
	 * file relative to the assets folder home.
	 */
	public static function get_assets_url( string $file = '' ): string {
		return self::get_url( 'assets/' . $file );
	}

	public static function get_ajax_url(): string {
		return admin_url( 'admin-ajax.php', 'relative' );
	}

	public static function get_version(): string {
		return self::$version;
	}

	public static function get_database_version(): string {
		return self::$database_version;
	}

	public static function get_textdomain(): string {
		return self::$textdomain;
	}

	public static function boot_modules(): void {
		foreach ( self::$modules as $bootableClass ) {
			$bootableClass::hooks();
		}
	}

	public static function boot_admin(): void {
		foreach ( self::$admin_boot as $bootableClass ) {
			$bootableClass::hooks();
		}
	}

	public static function boot_integrations(): void {
		foreach ( self::$integrations as $bootableClass ) {
			if ( is_string( $bootableClass::$plugin_file ) && Helpers::is_plugin_active( $bootableClass::$plugin_file ) ) {
				$bootableClass::hooks();
			}
		}
	}

	/**
	 * Get View Template Path
	 */
	public static function get_view_path( string $view_name ): string {
		return self::get_path( 'views/' . $view_name . '.php' );
	}
}
