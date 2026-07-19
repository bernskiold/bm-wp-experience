<?php
/**
 * Helpers
 *
 * This class contains small helpers that can be used in this plugin,
 * and referenced on all sites running this as a platform base.
 */

namespace BernskioldMedia\WP\Experience;

class Helpers {

	/**
	 * WordPress has a function to check if a plugin is active.
	 * Unfortunately it is only loaded in the admin. We want a function
	 * we can rely on throughout the system.
	 *
	 * @param  string  $plugin_file  The name of the main plugin file, relative to the main plugin dir. Example: my-plugin/my-plugin.php.
	 */
	public static function is_plugin_active( string $plugin_file ): bool {
		return in_array( $plugin_file, (array) get_option( 'active_plugins', [] ), true ) || self::is_plugin_active_for_network( $plugin_file );
	}

	/**
	 * WordPress has its own function to check if a plugin is network activated.
	 * Unfortunately it is only loaded in the admin. We want a function we can
	 * rely on throughout the system.
	 *
	 * @param  string  $plugin_file  The name of the main plugin file, relative to the main plugin dir. Example: my-plugin/my-plugin.php.
	 */
	public static function is_plugin_active_for_network( string $plugin_file ): bool {
		if ( ! is_multisite() ) {
			return false;
		}

		$plugins = get_site_option( 'active_sitewide_plugins' );

		if ( isset( $plugins[ $plugin_file ] ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if this plugin is activated for the entire network.
	 */
	public static function is_network_active(): bool {
		return is_multisite() && array_key_exists( plugin_basename( BM_WP_EXPERIENCE_FILE_PATH ), (array) get_site_option( 'active_sitewide_plugins' ) );
	}

	/**
	 * Get the file's permission bits (owner/group/other) as an integer.
	 *
	 * The return value is the raw octal permission value (e.g. 0640), not a
	 * decimalised string, so it can be compared against octal literals directly.
	 */
	public static function get_file_permissions( string $file ): int {
		return fileperms( $file ) & 0777;
	}

	/**
	 * Determine whether a (secret) file is exposed to group or other users.
	 *
	 * Returns true when "other" has any permission, or when "group" is
	 * writable. Owner permissions and group-read (e.g. 0600, 0640, 0440) are
	 * considered safe for configuration files.
	 */
	public static function is_file_publicly_accessible( string $file ): bool {
		return ( fileperms( $file ) & 0027 ) !== 0;
	}

	public static function setup_wp_filesystem() {
		global $wp_filesystem;

		if ( empty( $wp_filesystem ) ) {
			require_once( ABSPATH . '/wp-admin/includes/file.php' );
			WP_Filesystem();
		}

		return $wp_filesystem;
	}
}
