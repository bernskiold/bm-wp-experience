<?php

namespace BernskioldMedia\WP\Experience;

use BernskioldMedia\WP\Experience\Modules\Security\TwoFactorAuthentication;
use BMWPEXP_Vendor\BernskioldMedia\WP\PluginBase\BasePlugin;

class Plugin extends BasePlugin {

	protected static string $slug = 'bm-wp-experience';
	protected static string $version = '3.11.6';
	protected static string $textdomain = 'bm-wp-experience';
	protected static string $plugin_file_path = BM_WP_EXPERIENCE_FILE_PATH;

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
        Modules\Sso\Okta::class,
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

	public function __construct() {
		parent::__construct();

		self::boot_modules();
		self::boot_integrations();

		if ( is_admin() && ! empty( self::$admin_boot ) ) {
			self::boot_admin();
		}

		register_activation_hook( self::$plugin_file_path, [ Install::class, 'install' ] );
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
