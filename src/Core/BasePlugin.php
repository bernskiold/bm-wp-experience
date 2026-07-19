<?php

namespace Bernskiold\WP\Experience\Core;

defined( 'ABSPATH' ) || exit;

/**
 * BasePlugin
 *
 * A small plugin foundation providing a singleton instance, a boot loop for
 * Hookable classes, translation loading and path/URL helpers. Inlined from the
 * former bernskioldmedia/wp-plugin-base dependency and trimmed to what this
 * plugin actually uses.
 *
 * @phpstan-consistent-constructor
 */
class BasePlugin {

	/**
	 * A machine readable plugin slug, used to prefix certain actions.
	 */
	protected static string $slug = 'wp_plugin_base';

	/**
	 * Plugin version.
	 */
	protected static string $version = '1.0.0';

	/**
	 * Plugin textdomain.
	 */
	protected static string $textdomain = 'wp-plugin-base';

	/**
	 * Main plugin file path.
	 */
	protected static string $plugin_file_path = '';

	/**
	 * Classes (implementing Hookable) to boot when the plugin runs.
	 */
	protected static array $boot = [];

	/**
	 * Singleton instance.
	 *
	 * @var static|null
	 */
	protected static $_instance = null;

	/**
	 * Get the singleton plugin instance.
	 *
	 * @return static
	 */
	public static function instance() {
		if ( null === static::$_instance ) {
			static::$_instance = new static();
		}

		return static::$_instance;
	}

	public function __construct() {
		$this->init_hooks();

		do_action( static::$slug . '_loaded' );
	}

	/**
	 * Hooks that are run at the time of init.
	 */
	protected function init_hooks(): void {
		do_action( static::$slug . '_init_hooks' );

		add_action( 'init', [ static::class, 'load_languages' ] );

		foreach ( static::$boot as $bootable_class ) {
			$bootable_class::hooks();
		}
	}

	/**
	 * Load plugin translations.
	 */
	public static function load_languages(): void {
		$locale = is_admin() && function_exists( 'get_user_locale' ) ? get_user_locale() : get_locale();
		$locale = apply_filters( 'plugin_locale', $locale, static::get_textdomain() );

		unload_textdomain( static::get_textdomain() );

		// Start checking in the main language dir.
		load_textdomain( static::get_textdomain(), WP_LANG_DIR . '/' . static::get_textdomain() . '/' . static::get_textdomain() . '-' . $locale . '.mo' );

		// Otherwise, load from the plugin.
		load_plugin_textdomain( static::get_textdomain(), false, dirname( plugin_basename( static::$plugin_file_path ) ) . '/languages' );
	}

	/**
	 * Get the path to the plugin folder, or the specified file relative to it.
	 */
	public static function get_path( string $file = '' ): string {
		return untrailingslashit( plugin_dir_path( static::$plugin_file_path ) ) . '/' . $file;
	}

	/**
	 * Get the URL to the plugin folder, or the specified file relative to it.
	 */
	public static function get_url( string $file = '' ): string {
		return untrailingslashit( plugin_dir_url( static::$plugin_file_path ) ) . '/' . $file;
	}

	/**
	 * Get the URL to the assets folder, or the specified file relative to it.
	 */
	public static function get_assets_url( string $file = '' ): string {
		return static::get_url( 'assets/' . $file );
	}

	/**
	 * Get the AJAX URL.
	 */
	public static function get_ajax_url(): string {
		return admin_url( 'admin-ajax.php', 'relative' );
	}

	/**
	 * Get the plugin version.
	 */
	public static function get_version(): string {
		return static::$version;
	}

	/**
	 * Get the plugin textdomain.
	 */
	public static function get_textdomain(): string {
		return static::$textdomain;
	}

}
