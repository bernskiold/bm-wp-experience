<?php
/**
 * XML-RPC
 *
 * XML-RPC is disabled by default. Sites that need it (e.g. for a legacy
 * integration) can re-enable it from a plugin or mu-plugin:
 *
 *     add_filter( 'bm_wpexp_disable_xmlrpc', '__return_false' );
 *
 * The same filter decides whether the .htaccess rule blocking xmlrpc.php is
 * written on activation.
 */

namespace Bernskiold\WP\Experience\Modules;

class XML_RPC extends Module {

	public static function hooks(): void {
		// Runs once all plugins (and mu-plugins) have registered their filters,
		// which is before XML-RPC handles any request.
		add_action( 'plugins_loaded', [ self::class, 'maybe_disable' ], 0 );
	}

	public static function is_disabled(): bool {
		return true === apply_filters( 'bm_wpexp_disable_xmlrpc', true );
	}

	public static function maybe_disable(): void {
		if ( ! self::is_disabled() ) {
			return;
		}

		add_filter( 'xmlrpc_enabled', '__return_false', PHP_INT_MAX );
		add_filter( 'xmlrpc_methods', [ self::class, 'remove_methods' ], PHP_INT_MAX );
		add_filter( 'wp_headers', [ self::class, 'remove_pingback_header' ], PHP_INT_MAX );
		add_filter( 'pings_open', '__return_false', PHP_INT_MAX );
		add_filter( 'pre_option_default_pingback_flag', '__return_zero' );
		add_filter( 'pre_option_default_ping_status', [ self::class, 'closed' ] );
		add_action( 'pre_ping', [ self::class, 'remove_pings' ] );
		remove_action( 'wp_head', 'rsd_link' );

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			self::deny_request();
		}
	}

	/**
	 * End an XML-RPC request before it is processed.
	 */
	public static function deny_request(): void {
		if ( ! headers_sent() ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
		}

		echo esc_html__( 'XML-RPC services are disabled on this site.', 'bm-wp-experience' );

		self::terminate();
	}

	/**
	 * Split out so tests can intercept the exit.
	 */
	protected static function terminate(): void {
		/**
		 * Fires just before an XML-RPC request is ended.
		 */
		do_action( 'bm_wpexp_xmlrpc_request_denied' );

		exit;
	}

	public static function remove_methods( array $methods ): array {
		return [];
	}

	public static function remove_pingback_header( array $headers ): array {
		unset( $headers['X-Pingback'] );

		return $headers;
	}

	public static function closed(): string {
		return 'closed';
	}

	/**
	 * Don't send outgoing pingbacks to linked sites.
	 *
	 * @param array $links Links found in the post content (by reference).
	 */
	public static function remove_pings( array &$links ): void {
		$links = [];
	}
}
