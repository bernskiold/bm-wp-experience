<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\XML_RPC;

/**
 * XML-RPC is disabled by default (set up on plugins_loaded during bootstrap).
 */
class XmlRpcTest extends TestCase {

	/**
	 * Remove what maybe_disable() registered, to start from a clean slate.
	 */
	private function reset_hooks(): void {
		remove_filter( 'xmlrpc_enabled', '__return_false', PHP_INT_MAX );
		remove_filter( 'xmlrpc_methods', [ XML_RPC::class, 'remove_methods' ], PHP_INT_MAX );
		remove_filter( 'wp_headers', [ XML_RPC::class, 'remove_pingback_header' ], PHP_INT_MAX );
		remove_filter( 'pings_open', '__return_false', PHP_INT_MAX );
		remove_filter( 'pre_option_default_pingback_flag', '__return_zero' );
		remove_filter( 'pre_option_default_ping_status', [ XML_RPC::class, 'closed' ] );
		remove_action( 'pre_ping', [ XML_RPC::class, 'remove_pings' ] );
	}

	public function test_runs_before_requests_are_handled(): void {
		$this->assertSame( 0, has_action( 'plugins_loaded', [ XML_RPC::class, 'maybe_disable' ] ) );
	}

	public function test_xmlrpc_is_disabled(): void {
		$this->assertTrue( XML_RPC::is_disabled() );
		$this->assertFalse( apply_filters( 'xmlrpc_enabled', true ) );
	}

	public function test_no_methods_are_exposed(): void {
		$this->assertSame( [], apply_filters( 'xmlrpc_methods', [ 'wp.getPosts' => 'x', 'pingback.ping' => 'y' ] ) );
	}

	public function test_pingbacks_are_off(): void {
		$post_id = self::factory()->post->create( [ 'ping_status' => 'open' ] );

		$this->assertFalse( pings_open( $post_id ) );
		$this->assertSame( 0, (int) get_option( 'default_pingback_flag' ) );
		$this->assertSame( 'closed', get_option( 'default_ping_status' ) );

		$links = [ 'https://example.com/a', 'https://example.com/b' ];
		$pung  = [];
		do_action_ref_array( 'pre_ping', [ &$links, &$pung, $post_id ] );
		$this->assertSame( [], $links, 'No outgoing pingbacks.' );
	}

	public function test_discovery_link_and_header_are_removed(): void {
		$this->assertFalse( has_action( 'wp_head', 'rsd_link' ) );
		$this->assertArrayNotHasKey( 'X-Pingback', apply_filters( 'wp_headers', [ 'X-Pingback' => 'https://example.org/xmlrpc.php' ] ) );
	}

	public function test_xmlrpc_requests_are_ended_with_a_message(): void {
		add_action( 'bm_wpexp_xmlrpc_request_denied', static function () {
			throw new \RuntimeException( 'denied' );
		} );

		ob_start();

		try {
			XML_RPC::deny_request();
			$this->fail( 'Expected the request to end.' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'denied', $e->getMessage() );
		} finally {
			$output = ob_get_clean();
		}

		$this->assertSame( 'XML-RPC services are disabled on this site.', $output );
	}

	public function test_filter_keeps_xmlrpc_enabled(): void {
		$this->reset_hooks();
		add_filter( 'bm_wpexp_disable_xmlrpc', '__return_false' );

		XML_RPC::maybe_disable();

		$this->assertFalse( XML_RPC::is_disabled() );
		$this->assertTrue( apply_filters( 'xmlrpc_enabled', true ) );
		$this->assertSame( [ 'wp.getPosts' => 'x' ], apply_filters( 'xmlrpc_methods', [ 'wp.getPosts' => 'x' ] ) );
		$this->assertFalse( has_action( 'pre_ping', [ XML_RPC::class, 'remove_pings' ] ) );

		// Restore the default for the remaining tests.
		remove_filter( 'bm_wpexp_disable_xmlrpc', '__return_false' );
		XML_RPC::maybe_disable();
	}
}
