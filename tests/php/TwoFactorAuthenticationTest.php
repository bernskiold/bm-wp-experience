<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Security\TwoFactorAuthentication;
use PragmaRX\Google2FA\Google2FA;
use WP_Ajax_UnitTestCase;
use WPAjaxDieContinueException;
use WPAjaxDieStopException;

/**
 * Two-factor authentication: secrets, codes, recovery codes, verification
 * sessions, attempt limiting, the setup endpoints, the login step and the
 * profile screen.
 */
class TwoFactorAuthenticationTest extends WP_Ajax_UnitTestCase {

	private const RECOVERY_KEY = 'bmwp_two_factor_recovery_codes';

	private int $editor_id;
	private int $other_editor_id;
	private int $subscriber_id;
	private int $admin_id;

	public function set_up(): void {
		parent::set_up();

		// hooks() bails out without Imagick (needed for the QR code only).
		if ( ! has_action( 'wp_ajax_bmwp_validate_two_factor' ) ) {
			add_action( 'wp_ajax_bmwp_validate_two_factor', [ TwoFactorAuthentication::class, '_ajax_validate' ] );
			add_action( 'wp_ajax_nopriv_bmwp_validate_two_factor', [ TwoFactorAuthentication::class, '_ajax_validate' ] );
			add_action( 'wp_ajax_bmwp_activate_two_factor', [ TwoFactorAuthentication::class, '_ajax_activate' ] );
			add_action( 'wp_ajax_nopriv_bmwp_activate_two_factor', [ TwoFactorAuthentication::class, '_ajax_activate' ] );
			add_action( 'wp_ajax_bmwp_deactivate_two_factor', [ TwoFactorAuthentication::class, '_ajax_deactivate' ] );
		}

		add_action( 'bm_wpexp_before_two_factor_login_template', static function ( $template, $args ) {
			throw new Template_Exception( $template, $args );
		}, 10, 2 );

		add_filter( 'wp_redirect', static function ( $location, $status ) {
			throw new Redirect_Exception( (string) $location, (int) $status );
		}, PHP_INT_MAX, 2 );

		$_SERVER['REMOTE_ADDR'] = '192.0.2.10';

		$this->editor_id       = self::factory()->user->create( [ 'role' => 'editor', 'user_email' => 'editor@example.org' ] );
		$this->other_editor_id = self::factory()->user->create( [ 'role' => 'editor' ] );
		$this->subscriber_id   = self::factory()->user->create( [ 'role' => 'subscriber' ] );
		$this->admin_id        = self::factory()->user->create( [ 'role' => 'administrator' ] );
	}

	public function tear_down(): void {
		$_POST    = [];
		$_GET     = [];
		$_REQUEST = [];
		unset( $_SERVER['REQUEST_METHOD'] );

		parent::tear_down();
	}

	// ---------------------------------------------------------------------
	// Helpers.
	// ---------------------------------------------------------------------

	private function current_code( int $user_id ): string {
		return ( new Google2FA() )->getCurrentOtp( TwoFactorAuthentication::get_secret_for_user( $user_id ) );
	}

	private function invalid_code( int $user_id ): string {
		return '000000' === $this->current_code( $user_id ) ? '111111' : '000000';
	}

	private function enable_for( int $user_id ): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $user_id );
		TwoFactorAuthentication::generate_and_save_recovery_codes( $user_id );
		TwoFactorAuthentication::set_user_two_factor_enabled( true, $user_id );
	}

	private function ajax( string $action, array $request ): ?array {
		$_POST    = $request;
		$_REQUEST = $request;

		try {
			$this->_handleAjax( $action );
		} catch ( WPAjaxDieContinueException | WPAjaxDieStopException $e ) {
			// Expected: wp_send_json_* ends the request.
		}

		$response             = json_decode( $this->_last_response, true );
		$this->_last_response = '';

		return is_array( $response ) ? $response : null;
	}

	/**
	 * Run a setup request as a logged-out visitor in the forced setup.
	 */
	private function setup_request( string $action, string $session, array $fields = [] ): ?array {
		wp_set_current_user( 0 );

		return $this->ajax( 'bmwp_' . $action . '_two_factor', array_merge( [
			'nonce'                                => wp_create_nonce( TwoFactorAuthentication::nonce_action( $action ) ),
			TwoFactorAuthentication::SESSION_FIELD => $session,
		], $fields ) );
	}

	/**
	 * Run a setup request from the profile screen as the given user.
	 */
	private function profile_request( string $action, int $acting_user, int $target_user, array $fields = [], ?int $nonce_user = null ): ?array {
		wp_set_current_user( $acting_user );

		return $this->ajax( 'bmwp_' . $action . '_two_factor', array_merge( [
			'nonce'   => wp_create_nonce( TwoFactorAuthentication::nonce_action( $action, $nonce_user ?? $target_user ) ),
			'user_id' => $target_user,
		], $fields ) );
	}

	/**
	 * Submit a second-step login form.
	 *
	 * @return array{type: string, value: mixed}
	 */
	private function submit_login( callable $handler, array $fields, bool $with_nonce = true ): array {
		wp_set_current_user( 0 );

		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_POST                     = $fields;
		$_REQUEST                  = $fields;

		if ( $with_nonce ) {
			$_POST['_wpnonce'] = wp_create_nonce( TwoFactorAuthentication::LOGIN_NONCE_ACTION );
		}

		$cookie_user = null;

		add_action( 'set_auth_cookie', static function ( $cookie, $expire, $expiration, $user_id ) use ( &$cookie_user ) {
			$cookie_user = [ 'user_id' => $user_id, 'expire' => $expire ];
		}, 10, 4 );

		// wp_set_auth_cookie() would send headers; stop right after the action.
		add_filter( 'send_auth_cookies', '__return_false' );

		try {
			$handler();
		} catch ( Redirect_Exception $redirect ) {
			return [ 'type' => 'redirect', 'value' => $redirect->location, 'cookie' => $cookie_user ];
		} catch ( Template_Exception $template ) {
			return [ 'type' => 'template', 'value' => $template, 'cookie' => $cookie_user ];
		}

		return [ 'type' => 'none', 'value' => null, 'cookie' => $cookie_user ];
	}

	private function login_session( int $user_id, array $data = [] ): string {
		return TwoFactorAuthentication::create_session( $user_id, TwoFactorAuthentication::SESSION_PURPOSE_LOGIN, $data );
	}

	private function setup_session( int $user_id ): string {
		return TwoFactorAuthentication::create_session( $user_id, TwoFactorAuthentication::SESSION_PURPOSE_SETUP );
	}

	// ---------------------------------------------------------------------
	// Secrets, codes and recovery codes.
	// ---------------------------------------------------------------------

	public function test_secret_is_generated_once_and_persisted(): void {
		$this->assertSame( '', TwoFactorAuthentication::get_secret_for_user( $this->editor_id ) );

		$secret = TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );

		$this->assertMatchesRegularExpression( '/^[A-Z2-7]{32}$/', $secret );
		$this->assertSame( $secret, TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id ) );
	}

	public function test_validate_code_accepts_the_current_code_only(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );

		$this->assertTrue( TwoFactorAuthentication::validate_code( $this->current_code( $this->editor_id ), $this->editor_id ) );
		$this->assertFalse( TwoFactorAuthentication::validate_code( $this->invalid_code( $this->editor_id ), $this->editor_id ) );
		$this->assertFalse( TwoFactorAuthentication::validate_code( '123456', $this->other_editor_id ), 'No secret, no match.' );
	}

	public function test_recovery_codes_are_eight_unique_eight_digit_codes(): void {
		$codes = TwoFactorAuthentication::generate_and_save_recovery_codes( $this->editor_id );

		$this->assertCount( 8, array_unique( $codes ) );
		foreach ( $codes as $code ) {
			$this->assertMatchesRegularExpression( '/^\d{8}$/', $code );
		}
		$this->assertSame( $codes, TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );
	}

	public function test_consuming_a_recovery_code_removes_only_that_code(): void {
		$codes = TwoFactorAuthentication::generate_and_save_recovery_codes( $this->editor_id );

		TwoFactorAuthentication::consume_recovery_code( $this->editor_id, $codes[0] );

		$this->assertSame( array_slice( $codes, 1 ), TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );
		$this->assertFalse( TwoFactorAuthentication::validate_backup_code( $codes[0], $this->editor_id ) );
	}

	public function test_two_factor_is_required_for_editorial_roles_only(): void {
		$method = new \ReflectionMethod( TwoFactorAuthentication::class, 'is_required_for_user' );

		$this->assertTrue( $method->invoke( null, $this->editor_id ) );
		$this->assertTrue( $method->invoke( null, $this->admin_id ) );
		$this->assertFalse( $method->invoke( null, $this->subscriber_id ) );
	}

	// ---------------------------------------------------------------------
	// Verification sessions.
	// ---------------------------------------------------------------------

	public function test_sessions_are_random_bound_to_a_user_and_purpose(): void {
		$first  = $this->login_session( $this->editor_id );
		$second = $this->login_session( $this->editor_id );

		$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $first );
		$this->assertNotSame( $first, $second );

		$session = TwoFactorAuthentication::get_session( $first, TwoFactorAuthentication::SESSION_PURPOSE_LOGIN );
		$this->assertSame( $this->editor_id, $session['user_id'] );
		$this->assertNull( TwoFactorAuthentication::get_session( $first, TwoFactorAuthentication::SESSION_PURPOSE_SETUP ) );
	}

	public function test_sessions_can_be_ended_and_reject_malformed_tokens(): void {
		$token = $this->login_session( $this->editor_id );

		TwoFactorAuthentication::end_session( $token );

		$this->assertNull( TwoFactorAuthentication::get_session( $token ) );
		$this->assertNull( TwoFactorAuthentication::get_session( '' ) );
		$this->assertNull( TwoFactorAuthentication::get_session( 'not-a-token' ) );
	}

	public function test_session_tokens_are_not_stored_in_plain_text(): void {
		global $wpdb;

		$token = $this->login_session( $this->editor_id );

		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", '%' . $wpdb->esc_like( $token ) . '%' ) ) );
	}

	public function test_password_step_starts_a_setup_session_for_required_users(): void {
		try {
			TwoFactorAuthentication::handle_2fa_check_on_login( 'editor', get_user_by( 'ID', $this->editor_id ) );
			$this->fail( 'Expected the setup screen.' );
		} catch ( Template_Exception $template ) {
			$this->assertSame( '2fa-activation', $template->template );
			$session = TwoFactorAuthentication::get_session( $template->args['session'], TwoFactorAuthentication::SESSION_PURPOSE_SETUP );
			$this->assertSame( $this->editor_id, $session['user_id'] );
		}
	}

	public function test_password_step_starts_a_login_session_for_two_factor_users(): void {
		$this->enable_for( $this->editor_id );
		$_POST    = [ 'rememberme' => 'forever' ];
		$_REQUEST = [ 'redirect_to' => admin_url( 'edit.php' ) ];

		try {
			TwoFactorAuthentication::handle_login( 'editor', get_user_by( 'ID', $this->editor_id ) );
			$this->fail( 'Expected the code screen.' );
		} catch ( Template_Exception $template ) {
			$this->assertSame( '2fa-login', $template->template );
			$session = TwoFactorAuthentication::get_session( $template->args['session'], TwoFactorAuthentication::SESSION_PURPOSE_LOGIN );
			$this->assertSame( $this->editor_id, $session['user_id'] );
			$this->assertTrue( $session['remember'] );
			$this->assertSame( admin_url( 'edit.php' ), $session['redirect_to'] );
		}
	}

	public function test_users_without_a_second_step_are_let_through(): void {
		TwoFactorAuthentication::handle_2fa_check_on_login( 'subscriber', get_user_by( 'ID', $this->subscriber_id ) );
		TwoFactorAuthentication::handle_login( 'subscriber', get_user_by( 'ID', $this->subscriber_id ) );

		$this->enable_for( $this->editor_id );
		TwoFactorAuthentication::handle_2fa_check_on_login( 'editor', get_user_by( 'ID', $this->editor_id ) );

		$this->assertTrue( true, 'No screen rendered.' );
	}

	// ---------------------------------------------------------------------
	// Attempt limiting.
	// ---------------------------------------------------------------------

	public function test_attempts_are_limited_per_user(): void {
		for ( $i = 0; $i < 4; $i++ ) {
			TwoFactorAuthentication::register_failed_attempt( $this->editor_id );
			$this->assertFalse( TwoFactorAuthentication::is_locked_out( $this->editor_id ) );
		}

		$_SERVER['REMOTE_ADDR'] = '192.0.2.11';
		TwoFactorAuthentication::register_failed_attempt( $this->editor_id );

		$this->assertTrue( TwoFactorAuthentication::is_locked_out( $this->editor_id ), 'Counted per user, from any address.' );
		$this->assertFalse( TwoFactorAuthentication::is_locked_out( $this->other_editor_id ) );

		TwoFactorAuthentication::clear_failed_attempts( $this->editor_id );
		$this->assertFalse( TwoFactorAuthentication::is_locked_out( $this->editor_id ) );
	}

	public function test_attempts_are_limited_per_address(): void {
		add_filter( 'bm_wpexp_two_factor_max_attempts', static fn( $max, $scope ) => 'ip' === $scope ? 3 : 100, 10, 2 );

		TwoFactorAuthentication::register_failed_attempt( $this->editor_id );
		TwoFactorAuthentication::register_failed_attempt( $this->other_editor_id );
		TwoFactorAuthentication::register_failed_attempt( $this->admin_id );

		$this->assertTrue( TwoFactorAuthentication::is_locked_out( $this->subscriber_id ) );

		$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
		$this->assertFalse( TwoFactorAuthentication::is_locked_out( $this->subscriber_id ) );
	}

	// ---------------------------------------------------------------------
	// Forced setup at login (logged out).
	// ---------------------------------------------------------------------

	public function test_setup_validation_requires_an_active_setup_session(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );

		$response = $this->setup_request( 'validate', '', [
			'token'   => $this->current_code( $this->editor_id ),
			'user_id' => $this->editor_id,
		] );

		$this->assertFalse( $response['success'] );
		$this->assertSame( [], TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );
	}

	public function test_setup_validation_rejects_a_login_session(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );

		$response = $this->setup_request( 'validate', $this->login_session( $this->editor_id ), [
			'token' => $this->current_code( $this->editor_id ),
		] );

		$this->assertFalse( $response['success'] );
	}

	public function test_setup_validation_acts_on_the_session_user_only(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->other_editor_id );
		$session = $this->setup_session( $this->editor_id );

		$response = $this->setup_request( 'validate', $session, [
			'token'   => $this->current_code( $this->editor_id ),
			'user_id' => $this->other_editor_id,
		] );

		$this->assertTrue( $response['data']['is_valid'] );
		$this->assertCount( 8, TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );
		$this->assertSame( [], TwoFactorAuthentication::get_recovery_codes( $this->other_editor_id ) );
	}

	public function test_setup_is_not_available_once_two_factor_is_enabled(): void {
		$this->enable_for( $this->editor_id );
		$codes = TwoFactorAuthentication::get_recovery_codes( $this->editor_id );

		$response = $this->setup_request( 'validate', $this->setup_session( $this->editor_id ), [
			'token' => $this->current_code( $this->editor_id ),
		] );

		$this->assertFalse( $response['success'] );
		$this->assertSame( $codes, TwoFactorAuthentication::get_recovery_codes( $this->editor_id ), 'Recovery codes unchanged.' );
	}

	public function test_setup_requires_a_valid_nonce(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );
		wp_set_current_user( 0 );

		$response = $this->ajax( 'bmwp_validate_two_factor', [
			'nonce'                                => 'invalid',
			TwoFactorAuthentication::SESSION_FIELD => $this->setup_session( $this->editor_id ),
			'token'                                => $this->current_code( $this->editor_id ),
		] );

		$this->assertFalse( $response['success'] );
		$this->assertSame( [], TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );
	}

	public function test_setup_returns_recovery_codes_only_for_a_valid_code(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );
		$session = $this->setup_session( $this->editor_id );

		$invalid = $this->setup_request( 'validate', $session, [ 'token' => $this->invalid_code( $this->editor_id ) ] );
		$this->assertTrue( $invalid['success'] );
		$this->assertFalse( $invalid['data']['is_valid'] );
		$this->assertSame( [], $invalid['data']['recovery_codes'] );

		$valid = $this->setup_request( 'validate', $session, [ 'token' => $this->current_code( $this->editor_id ) ] );
		$this->assertTrue( $valid['data']['is_valid'] );
		$this->assertCount( 8, $valid['data']['recovery_codes'] );
	}

	public function test_setup_validation_is_attempt_limited(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );
		$session = $this->setup_session( $this->editor_id );

		for ( $i = 0; $i < 5; $i++ ) {
			$response = $this->setup_request( 'validate', $session, [ 'token' => $this->invalid_code( $this->editor_id ) ] );
		}

		$this->assertFalse( $response['success'] );
		$this->assertTrue( $response['data']['locked'] );

		$response = $this->setup_request( 'validate', $session, [ 'token' => $this->current_code( $this->editor_id ) ] );

		$this->assertFalse( $response['success'], 'A correct code is not accepted while paused.' );
		$this->assertSame( [], TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );
	}

	public function test_setup_activation_requires_validation_in_the_same_session(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );
		TwoFactorAuthentication::generate_and_save_recovery_codes( $this->editor_id );

		$response = $this->setup_request( 'activate', $this->setup_session( $this->editor_id ) );

		$this->assertFalse( $response['success'] );
		$this->assertFalse( TwoFactorAuthentication::has_user_two_factor( $this->editor_id ) );
	}

	public function test_setup_completes_and_ends_the_session(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );
		$session = $this->setup_session( $this->editor_id );

		$this->setup_request( 'validate', $session, [ 'token' => $this->current_code( $this->editor_id ) ] );
		$response = $this->setup_request( 'activate', $session );

		$this->assertTrue( $response['success'] );
		$this->assertTrue( TwoFactorAuthentication::has_user_two_factor( $this->editor_id ) );
		$this->assertNull( TwoFactorAuthentication::get_session( $session ) );
	}

	public function test_deactivation_is_not_available_when_logged_out(): void {
		$this->enable_for( $this->editor_id );

		$response = $this->setup_request( 'deactivate', $this->setup_session( $this->editor_id ) );

		// WordPress only registers the logged-in handler; it also refuses on its own.
		$this->assertFalse( has_action( 'wp_ajax_nopriv_bmwp_deactivate_two_factor' ) );
		$this->assertFalse( $response['success'] );
		$this->assertTrue( TwoFactorAuthentication::has_user_two_factor( $this->editor_id ) );
	}

	// ---------------------------------------------------------------------
	// Profile screen (logged in).
	// ---------------------------------------------------------------------

	public function test_profile_setup_flow_for_own_account(): void {
		TwoFactorAuthentication::get_or_generate_secret_for_user( $this->editor_id );

		$validate = $this->profile_request( 'validate', $this->editor_id, $this->editor_id, [ 'token' => $this->current_code( $this->editor_id ) ] );
		$this->assertTrue( $validate['data']['is_valid'] );

		$activate = $this->profile_request( 'activate', $this->editor_id, $this->editor_id );
		$this->assertTrue( $activate['success'] );
		$this->assertTrue( TwoFactorAuthentication::has_user_two_factor( $this->editor_id ) );
	}

	public function test_profile_requests_need_edit_user_for_the_target(): void {
		$this->enable_for( $this->other_editor_id );

		foreach ( [ 'validate', 'activate', 'deactivate' ] as $action ) {
			$response = $this->profile_request( $action, $this->editor_id, $this->other_editor_id, [ 'token' => $this->current_code( $this->other_editor_id ) ] );
			$this->assertFalse( $response['success'], $action );
		}

		$this->assertTrue( TwoFactorAuthentication::has_user_two_factor( $this->other_editor_id ) );
	}

	public function test_profile_nonces_are_bound_to_the_edited_user(): void {
		$this->enable_for( $this->editor_id );

		$response = $this->profile_request( 'deactivate', $this->admin_id, $this->editor_id, [], $this->other_editor_id );

		$this->assertFalse( $response['success'] );
		$this->assertTrue( TwoFactorAuthentication::has_user_two_factor( $this->editor_id ) );
	}

	public function test_administrators_can_disable_another_users_two_factor(): void {
		$this->enable_for( $this->editor_id );
		$this->enable_for( $this->admin_id );

		$response = $this->profile_request( 'deactivate', $this->admin_id, $this->editor_id );

		$this->assertTrue( $response['success'] );
		$this->assertFalse( TwoFactorAuthentication::has_user_two_factor( $this->editor_id ) );
		$this->assertSame( '', TwoFactorAuthentication::get_secret_for_user( $this->editor_id ) );
		$this->assertFalse( metadata_exists( 'user', $this->editor_id, self::RECOVERY_KEY ) );
		$this->assertTrue( TwoFactorAuthentication::has_user_two_factor( $this->admin_id ), 'Only the edited user is affected.' );
	}

	public function test_profile_screen_shows_the_edited_users_status(): void {
		if ( ! extension_loaded( 'imagick' ) ) {
			$this->markTestSkipped( 'Imagick is required to render the QR code.' );
		}

		$this->enable_for( $this->admin_id );
		wp_set_current_user( $this->admin_id );

		ob_start();
		TwoFactorAuthentication::user_profile_section_content( get_user_by( 'ID', $this->editor_id ) );
		$html = ob_get_clean();

		$this->assertStringContainsString( '@click.prevent="modalOpen = true"', $html, 'Offers to enable for the edited user.' );
		$this->assertStringNotContainsString( '@click.prevent="disable"', $html );
		$this->assertStringContainsString( wp_create_nonce( TwoFactorAuthentication::nonce_action( 'deactivate', $this->editor_id ) ), $html );
		$this->assertStringContainsString( "body.append( 'user_id', '" . $this->editor_id . "' )", $html );
	}

	// ---------------------------------------------------------------------
	// Second login step.
	// ---------------------------------------------------------------------

	public function test_login_step_requires_an_active_session(): void {
		$this->enable_for( $this->editor_id );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_login' ], [
			'user_id'          => (string) $this->editor_id,
			'two_factor_token' => $this->current_code( $this->editor_id ),
		] );

		$this->assertSame( 'redirect', $result['type'] );
		$this->assertStringContainsString( 'bmwp_2fa=expired', $result['value'] );
		$this->assertNull( $result['cookie'] );
	}

	public function test_login_step_requires_a_nonce(): void {
		$this->enable_for( $this->editor_id );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_login' ], [
			TwoFactorAuthentication::SESSION_FIELD => $this->login_session( $this->editor_id ),
			'two_factor_token'                     => $this->current_code( $this->editor_id ),
		], false );

		$this->assertStringContainsString( 'bmwp_2fa=expired', $result['value'] );
		$this->assertNull( $result['cookie'] );
	}

	public function test_login_step_signs_in_the_session_user(): void {
		$this->enable_for( $this->editor_id );
		$this->enable_for( $this->other_editor_id );
		$session = $this->login_session( $this->editor_id, [ 'remember' => false, 'redirect_to' => admin_url( 'edit.php' ) ] );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_login' ], [
			TwoFactorAuthentication::SESSION_FIELD => $session,
			'user_id'                              => (string) $this->other_editor_id,
			'two_factor_token'                     => $this->current_code( $this->editor_id ),
		] );

		$this->assertSame( $this->editor_id, $result['cookie']['user_id'] );
		$this->assertSame( 0, $result['cookie']['expire'] );
		$this->assertSame( admin_url( 'edit.php' ), $result['value'] );
		$this->assertNull( TwoFactorAuthentication::get_session( $session ), 'Sessions are single-use.' );
	}

	public function test_login_step_honours_remember_me_from_the_password_step(): void {
		$this->enable_for( $this->editor_id );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_login' ], [
			TwoFactorAuthentication::SESSION_FIELD => $this->login_session( $this->editor_id, [ 'remember' => true ] ),
			'two_factor_token'                     => $this->current_code( $this->editor_id ),
		] );

		$this->assertGreaterThan( time(), $result['cookie']['expire'] );
	}

	public function test_login_step_keeps_the_session_after_a_wrong_code(): void {
		$this->enable_for( $this->editor_id );
		$session = $this->login_session( $this->editor_id );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_login' ], [
			TwoFactorAuthentication::SESSION_FIELD => $session,
			'two_factor_token'                     => $this->invalid_code( $this->editor_id ),
		] );

		$this->assertSame( 'template', $result['type'] );
		$this->assertSame( '2fa-login', $result['value']->template );
		$this->assertSame( $session, $result['value']->args['session'] );
		$this->assertNotEmpty( $result['value']->args['error'] );
		$this->assertNull( $result['cookie'] );
		$this->assertNotNull( TwoFactorAuthentication::get_session( $session ) );
	}

	public function test_login_step_pauses_after_repeated_wrong_codes(): void {
		$this->enable_for( $this->editor_id );
		$session = $this->login_session( $this->editor_id );

		for ( $i = 0; $i < 5; $i++ ) {
			$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_login' ], [
				TwoFactorAuthentication::SESSION_FIELD => $session,
				'two_factor_token'                     => $this->invalid_code( $this->editor_id ),
			] );
		}

		$this->assertSame( 'redirect', $result['type'] );
		$this->assertStringContainsString( 'bmwp_2fa=locked', $result['value'] );
		$this->assertNull( TwoFactorAuthentication::get_session( $session ) );

		// A new session for the same user stays paused, even with a correct code.
		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_login' ], [
			TwoFactorAuthentication::SESSION_FIELD => $this->login_session( $this->editor_id ),
			'two_factor_token'                     => $this->current_code( $this->editor_id ),
		] );

		$this->assertStringContainsString( 'bmwp_2fa=locked', $result['value'] );
		$this->assertNull( $result['cookie'] );
	}

	public function test_backup_code_signs_in_once(): void {
		$this->enable_for( $this->editor_id );
		$code = TwoFactorAuthentication::get_recovery_codes( $this->editor_id )[2];

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_backup_login' ], [
			TwoFactorAuthentication::SESSION_FIELD => $this->login_session( $this->editor_id ),
			'backup_code'                          => $code,
		] );

		$this->assertSame( $this->editor_id, $result['cookie']['user_id'] );
		$this->assertCount( 7, TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );

		$again = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_backup_login' ], [
			TwoFactorAuthentication::SESSION_FIELD => $this->login_session( $this->editor_id ),
			'backup_code'                          => $code,
		] );

		$this->assertSame( 'template', $again['type'] );
		$this->assertNull( $again['cookie'] );
	}

	public function test_backup_code_step_requires_an_active_session(): void {
		$this->enable_for( $this->editor_id );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'validate_backup_login' ], [
			'user_id'     => (string) $this->editor_id,
			'backup_code' => TwoFactorAuthentication::get_recovery_codes( $this->editor_id )[0],
		] );

		$this->assertStringContainsString( 'bmwp_2fa=expired', $result['value'] );
		$this->assertCount( 8, TwoFactorAuthentication::get_recovery_codes( $this->editor_id ) );
	}

	public function test_backup_code_form_needs_a_session(): void {
		$session = $this->login_session( $this->editor_id );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'load_backup_codes_form' ], [
			TwoFactorAuthentication::SESSION_FIELD => $session,
		] );

		$this->assertSame( '2fa-backup', $result['value']->template );
		$this->assertSame( $session, $result['value']->args['session'] );

		$result = $this->submit_login( [ TwoFactorAuthentication::class, 'load_backup_codes_form' ], [ 'user_id' => (string) $this->editor_id ] );
		$this->assertStringContainsString( 'bmwp_2fa=expired', $result['value'] );
	}

	public function test_login_screen_explains_expired_and_paused_sessions(): void {
		$_GET['bmwp_2fa'] = 'expired';
		$this->assertContains( 'bmwp_2fa_expired', TwoFactorAuthentication::add_session_expired_error( new \WP_Error() )->get_error_codes() );

		$_GET['bmwp_2fa'] = 'locked';
		$this->assertContains( 'bmwp_2fa_locked', TwoFactorAuthentication::add_session_expired_error( new \WP_Error() )->get_error_codes() );
	}
}
