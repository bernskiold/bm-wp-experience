<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Rest_Api;
use WP_Error;
use WP_REST_Request;

class RestApiTest extends TestCase {

	public function set_up(): void {
		parent::set_up();

		global $wp_rest_server;
		$wp_rest_server = null;
		rest_get_server();
	}

	public function tear_down(): void {
		global $wp_rest_server;
		$wp_rest_server = null;
		unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );

		parent::tear_down();
	}

	private function dispatch( string $route ) {
		return rest_get_server()->dispatch( new WP_REST_Request( 'GET', $route ) );
	}

	public function test_restriction_defaults_to_all(): void {
		$this->assertSame( 'all', Rest_Api::get_restricted_status() );
	}

	public function test_anonymous_requests_are_rejected_when_restricted(): void {
		wp_set_current_user( 0 );

		$result = rest_get_server()->check_authentication();

		$this->assertWPError( $result );
		$this->assertSame( 'rest_api_restricted', $result->get_error_code() );
		$this->assertSame( 401, $result->get_error_data()['status'] );
	}

	public function test_logged_in_requests_are_allowed(): void {
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'editor' ] ) );

		$this->assertNotWPError( rest_get_server()->check_authentication() );
		$this->assertSame( 200, $this->dispatch( '/wp/v2/posts' )->get_status() );
	}

	public function test_other_authentication_results_are_respected(): void {
		$error = new WP_Error( 'other', 'Other handler' );

		$this->assertSame( $error, Rest_Api::restrict( $error ) );
		$this->assertTrue( Rest_Api::restrict( true ) );
	}

	public function test_users_level_only_hides_user_endpoints_from_anonymous_requests(): void {
		add_filter( 'bm_wpexp_rest_api_restriction_level', static fn() => 'users' );
		wp_set_current_user( 0 );

		$this->assertNull( Rest_Api::restrict( null ) );
		$this->assertNotWPError( rest_get_server()->check_authentication() );

		$endpoints = Rest_Api::restrict_user_endpoints( [
			'/wp/v2/posts'             => [],
			'/wp/v2/users'             => [],
			'/wp/v2/users/(?P<id>\d+)' => [],
			'/wp/v2/users/me'          => [],
		] );

		$this->assertSame( [ '/wp/v2/posts' ], array_keys( $endpoints ) );

		$this->assertSame( 200, $this->dispatch( '/wp/v2/posts' )->get_status() );
		$this->assertSame( 404, $this->dispatch( '/wp/v2/users' )->get_status() );
	}

	public function test_user_endpoints_stay_available_to_logged_in_users(): void {
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );

		$this->assertSame( 200, $this->dispatch( '/wp/v2/users' )->get_status() );
	}

	public function test_none_level_leaves_the_api_open(): void {
		add_filter( 'bm_wpexp_rest_api_restriction_level', static fn() => 'none' );
		wp_set_current_user( 0 );

		$this->assertNull( Rest_Api::restrict( null ) );
		$this->assertSame( [ '/wp/v2/users' => [] ], Rest_Api::restrict_user_endpoints( [ '/wp/v2/users' => [] ] ) );
	}

	public function test_basic_auth_resolves_valid_credentials(): void {
		$user_id = self::factory()->user->create( [ 'user_login' => 'basic', 'user_pass' => 'c0rrect-h0rse-battery' ] );

		$_SERVER['PHP_AUTH_USER'] = 'basic';
		$_SERVER['PHP_AUTH_PW']   = 'c0rrect-h0rse-battery';

		$this->assertSame( $user_id, Rest_Api::handle_basic_auth( false ) );
		$this->assertNotFalse( has_filter( 'determine_current_user', [ Rest_Api::class, 'handle_basic_auth' ] ), 'Filter is restored.' );
	}

	public function test_basic_auth_rejects_invalid_credentials(): void {
		self::factory()->user->create( [ 'user_login' => 'basic', 'user_pass' => 'c0rrect-h0rse-battery' ] );

		$_SERVER['PHP_AUTH_USER'] = 'basic';
		$_SERVER['PHP_AUTH_PW']   = 'wrong';

		$this->assertNull( Rest_Api::handle_basic_auth( false ) );
	}

	public function test_basic_auth_does_not_override_an_existing_user(): void {
		$_SERVER['PHP_AUTH_USER'] = 'basic';
		$_SERVER['PHP_AUTH_PW']   = 'whatever';

		$this->assertSame( 42, Rest_Api::handle_basic_auth( 42 ) );
	}

	public function test_basic_auth_is_skipped_without_credentials(): void {
		$this->assertFalse( Rest_Api::handle_basic_auth( false ) );
	}
}
