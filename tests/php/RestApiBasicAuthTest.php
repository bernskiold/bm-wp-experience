<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Rest_Api;
use Bernskiold\WP\Experience\Modules\Security\TwoFactorAuthentication;
use WP_Application_Passwords;

/**
 * Basic authentication for the REST API.
 */
class RestApiBasicAuthTest extends TestCase {

	private int $user_id;

	public function set_up(): void {
		parent::set_up();

		$this->user_id = self::factory()->user->create( [
			'user_login' => 'api-user',
			'user_email' => 'api@example.org',
			'user_pass'  => 'c0rrect-h0rse-battery',
			'role'       => 'editor',
		] );

		// Application Passwords need HTTPS or a local site; the suite runs
		// over plain HTTP in "production".
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
	}

	public function tear_down(): void {
		unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
		$GLOBALS['wp_rest_application_password_status'] = null;

		parent::tear_down();
	}

	private function authenticate( string $username, string $password ) {
		$_SERVER['PHP_AUTH_USER'] = $username;
		$_SERVER['PHP_AUTH_PW']   = $password;

		return apply_filters( 'determine_current_user', false );
	}

	private function enable_two_factor(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->user_id );
		TwoFactorAuthentication::set_user_two_factor_enabled( true, $this->user_id );
	}

	public function test_account_password_works_without_two_factor(): void {
		$this->assertSame( $this->user_id, $this->authenticate( 'api-user', 'c0rrect-h0rse-battery' ) );
	}

	public function test_wrong_password_is_rejected(): void {
		$this->assertEmpty( $this->authenticate( 'api-user', 'wrong' ) );
	}

	public function test_two_factor_accounts_need_an_application_password(): void {
		$this->enable_two_factor();

		$this->assertEmpty( $this->authenticate( 'api-user', 'c0rrect-h0rse-battery' ), 'Account password (login).' );
		$this->assertEmpty( $this->authenticate( 'api@example.org', 'c0rrect-h0rse-battery' ), 'Account password (email).' );
		$this->assertEmpty( Rest_Api::handle_basic_auth( false ) );
	}

	public function test_two_factor_accounts_can_use_an_application_password(): void {
		$this->enable_two_factor();

		[ $password ] = WP_Application_Passwords::create_new_application_password( $this->user_id, [ 'name' => 'Integration' ] );

		$this->assertSame( $this->user_id, $this->authenticate( 'api-user', $password ) );
	}

	public function test_an_already_resolved_user_is_kept(): void {
		$_SERVER['PHP_AUTH_USER'] = 'api-user';
		$_SERVER['PHP_AUTH_PW']   = 'whatever';

		$this->assertSame( 42, Rest_Api::handle_basic_auth( 42 ) );
	}
}
