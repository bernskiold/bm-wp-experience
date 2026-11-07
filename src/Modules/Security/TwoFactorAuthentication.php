<?php

namespace Bernskiold\WP\Experience\Modules\Security;

use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Bernskiold\WP\Experience\Plugin;
use Bernskiold\WP\Experience\Core\Hookable;
use PragmaRX\Google2FA\Google2FA;

class TwoFactorAuthentication implements Hookable {

	protected readonly Google2FA $two_factor;
	private const USER_SECRET_META_KEY       = 'bmwp_two_factor_secret';
	private const TWO_FACTOR_STATUS_META_KEY = 'bmwp_two_factor_enabled';
	private const RECOVERY_CODES_META_KEY    = 'bmwp_two_factor_recovery_codes';
	public const LAST_USED_META_KEY          = 'bm_wpexp_2fa_last_used_ts';
	public const ASSET_HANDLE                = 'bm-wp-experience-two-factor';

	/**
	 * Verification sessions bind the second step of the login (and the
	 * forced setup) to the user who completed the password step.
	 */
	public const SESSION_FIELD          = 'bmwp_2fa_session';
	private const SESSION_PREFIX        = 'bmwp_2fa_session_';
	private const SESSION_LIFETIME      = 10 * MINUTE_IN_SECONDS;
	public const SESSION_PURPOSE_LOGIN  = 'login';
	public const SESSION_PURPOSE_SETUP  = 'setup';
	public const LOGIN_NONCE_ACTION     = 'bmwp-2fa-login';
	private const ATTEMPTS_PREFIX       = 'bmwp_2fa_attempts_';

	public function __construct() {
		$this->two_factor = new Google2FA();
	}

	public static function hooks(): void {

        if (!extension_loaded('imagick')){
            add_action('admin_notices', [self::class, 'admin_notice_no_imagick']);
            return;
        }
		// User profile section.
		add_action( 'admin_enqueue_scripts', [ self::class, 'enqueue_profile_assets' ] );
		add_action( 'show_user_profile', [ self::class, 'user_profile_section_content' ] );
		add_action( 'edit_user_profile', [ self::class, 'user_profile_section_content' ] );

		// AJAX actions.
		add_action( 'wp_ajax_bmwp_validate_two_factor', [ self::class, '_ajax_validate' ] );
		add_action( 'wp_ajax_nopriv_bmwp_validate_two_factor', [ self::class, '_ajax_validate' ] );
		add_action( 'wp_ajax_bmwp_activate_two_factor', [ self::class, '_ajax_activate' ] );
		add_action( 'wp_ajax_nopriv_bmwp_activate_two_factor', [ self::class, '_ajax_activate' ] );
		add_action( 'wp_ajax_bmwp_deactivate_two_factor', [ self::class, '_ajax_deactivate' ] );

		// Add two factor to login flow.
		add_action( 'wp_login', [ self::class, 'handle_2fa_check_on_login' ], 2, 2 );
		add_action( 'wp_login', [ self::class, 'handle_login' ], 3, 2 );
		add_action( 'login_form_2fa_validation', [ self::class, 'validate_login' ] );
		add_action( 'login_form_2fa_backup', [ self::class, 'validate_backup_login' ] );
		add_action( 'login_form_load_backup_codes', [ self::class, 'load_backup_codes_form' ] );
		add_filter( 'wp_login_errors', [ self::class, 'add_session_expired_error' ] );
	}

    public static function admin_notice_no_imagick(): void {
        ?>
        <div class="notice notice-error">
            <p><?php _e( 'The Two Factor Authentication module requires the Imagick PHP extension to be installed.', 'bm-wp-experience' ); ?></p>
        </div>
        <?php
    }

	/**
	 * Register the two-factor setup script and the shared stylesheet.
	 */
	public static function register_assets(): void {
		if ( wp_script_is( self::ASSET_HANDLE, 'registered' ) ) {
			return;
		}

		$asset_file = Plugin::get_path( 'assets/scripts/dist/two-factor.asset.php' );
		$asset      = file_exists( $asset_file ) ? require $asset_file : [];

		wp_register_script(
			self::ASSET_HANDLE,
			Plugin::get_assets_url( 'scripts/dist/two-factor.js' ),
			$asset['dependencies'] ?? [],
			$asset['version'] ?? Plugin::get_version(),
			[
				'in_footer' => true,
				'strategy'  => 'defer',
			]
		);

		wp_register_style(
			self::ASSET_HANDLE,
			Plugin::get_assets_url( 'styles/dist/two-factor.css' ),
			[],
			Plugin::get_version()
		);
	}

	/**
	 * Enqueue the setup assets on the profile and user edit screens, where
	 * the two-factor section is rendered.
	 */
	public static function enqueue_profile_assets( string $hook_suffix ): void {
		if ( ! in_array( $hook_suffix, [ 'profile.php', 'user-edit.php' ], true ) ) {
			return;
		}

		self::register_assets();

		wp_enqueue_script( self::ASSET_HANDLE );
		wp_enqueue_style( self::ASSET_HANDLE );
	}

	public static function user_profile_section_content( \WP_User $user ): void {
		$user_id = $user->ID;
		include Plugin::get_view_path( 'admin/two-factor' );
	}

	public function generate_qr_code_url( \WP_User $user ): string {
		$website = get_bloginfo( 'name' );
		$secret  = self::get_or_generate_secret_for_user( $user->ID );

		return $this->two_factor->getQRCodeUrl( $website, $user->user_email, $secret );
	}

	public static function get_or_generate_secret_for_user( int $user_id ): string {
		$existing = self::get_secret_for_user( $user_id );

		if ( $existing ) {
			return $existing;
		}

		$new = self::generate_secret() ?? '';
		self::set_secret_for_user( $user_id, $new );

		return $new;
	}

	public static function get_secret_for_user( int $user_id ): ?string {
		$value = get_user_meta( $user_id, self::USER_SECRET_META_KEY, true );

		if ( ! is_string( $value ) ) {
			return null;
		}

		return $value;
	}

	public static function set_secret_for_user( int $user_id, string $secret ): bool {
		return update_user_meta( $user_id, self::USER_SECRET_META_KEY, $secret );
	}

	public static function generate_secret(): ?string {
		try {
			$secret = ( new self() )->two_factor->generateSecretKey( 32 );
		} catch ( \Exception $e ) {
			error_log( $e->getMessage() );
			$secret = null;
		}

		return $secret;
	}

	public function generate_qr_code_image( \WP_User $user, bool $data_prefix = true ): string {
		$url    = $this->generate_qr_code_url( $user );
		$writer = new Writer( new ImageRenderer( new RendererStyle( 400 ), new ImagickImageBackEnd() ) );

		$base64 = base64_encode( $writer->writeString( $url ) );

		if ( $data_prefix ) {
			return "data:image/png;base64, $base64";
		}

		return $base64;
	}

	public static function the_qr_code_image( array $classes = [], ?int $user_id = null ): void {
		if ( null === $user_id ) {
			$user = wp_get_current_user();
		} else {
			$user = get_user_by( 'ID', $user_id );
		}

		if ( ! $user ) {
			return;
		}

		$image_src = ( new self() )->generate_qr_code_image( $user );
		?>
		<img src="<?php echo esc_attr( $image_src ); ?>" class="<?php echo esc_attr( implode( ' ', $classes ) ); ?>" />
		<?php
	}

	public static function validate_code( string $code, ?int $user_id = null ): bool {
		$user_id = self::maybe_get_current_user_id( $user_id );
		$secret  = self::get_secret_for_user( $user_id );

		if ( ! $secret ) {
			return false;
		}

		// Each code is accepted once: only codes from a time step after the
		// last accepted one match. The validity window is unchanged.
		$last_used = (int) get_user_meta( $user_id, self::LAST_USED_META_KEY, true );
		$matched   = ( new self() )->two_factor->verifyKeyNewer( $secret, $code, $last_used );

		if ( false === $matched ) {
			return false;
		}

		update_user_meta( $user_id, self::LAST_USED_META_KEY, (int) $matched );

		return true;
	}

	public static function validate_backup_code( string $code, ?int $user_id = null ): bool {
		$user_id = $user_id ?? get_current_user_id();
		$codes   = self::get_recovery_codes( $user_id );

		return in_array( $code, $codes, true );
	}

	/**
	 * Remove a used recovery code so it cannot be replayed.
	 */
	public static function consume_recovery_code( int $user_id, string $code ): void {
		$remaining = array_values( array_filter(
			self::get_recovery_codes( $user_id ),
			static fn( $stored ) => ! hash_equals( (string) $stored, $code )
		) );

		update_user_meta( $user_id, self::RECOVERY_CODES_META_KEY, $remaining );
	}

	// ---------------------------------------------------------------------
	// Verification sessions.
	// ---------------------------------------------------------------------

	/**
	 * Start a verification session for a user who has just passed the
	 * password step. Returns the token to hand to the browser.
	 */
	public static function create_session( int $user_id, string $purpose, array $data = [] ): string {
		$token = bin2hex( random_bytes( 32 ) );

		set_transient( self::session_key( $token ), array_merge( $data, [
			'user_id'   => $user_id,
			'purpose'   => $purpose,
			'validated' => false,
		] ), self::SESSION_LIFETIME );

		return $token;
	}

	/**
	 * Get an active verification session, optionally for a given purpose.
	 */
	public static function get_session( string $token, ?string $purpose = null ): ?array {
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return null;
		}

		$session = get_transient( self::session_key( $token ) );

		if ( ! is_array( $session ) || empty( $session['user_id'] ) ) {
			return null;
		}

		if ( null !== $purpose && $purpose !== ( $session['purpose'] ?? null ) ) {
			return null;
		}

		return $session;
	}

	protected static function update_session( string $token, array $session ): void {
		set_transient( self::session_key( $token ), $session, self::SESSION_LIFETIME );
	}

	public static function end_session( string $token ): void {
		if ( preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			delete_transient( self::session_key( $token ) );
		}
	}

	protected static function session_key( string $token ): string {
		return self::SESSION_PREFIX . hash( 'sha256', $token );
	}

	protected static function get_request_session_token(): string {
		return sanitize_text_field( wp_unslash( (string) ( $_REQUEST[ self::SESSION_FIELD ] ?? '' ) ) );
	}

	// ---------------------------------------------------------------------
	// Attempt limiting.
	// ---------------------------------------------------------------------

	protected static function get_max_attempts( string $scope ): int {
		$default = 'ip' === $scope ? 20 : 5;

		return (int) apply_filters( 'bm_wpexp_two_factor_max_attempts', $default, $scope );
	}

	protected static function get_lockout_duration(): int {
		return (int) apply_filters( 'bm_wpexp_two_factor_lockout_duration', 15 * MINUTE_IN_SECONDS );
	}

	protected static function get_client_ip(): string {
		return (string) apply_filters( 'bm_wpexp_two_factor_client_ip', sanitize_text_field( wp_unslash( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) ) ) );
	}

	/**
	 * @return array<string, string> Scope => transient key.
	 */
	protected static function attempt_keys( int $user_id ): array {
		$keys = [ 'user' => self::ATTEMPTS_PREFIX . 'u_' . $user_id ];
		$ip   = self::get_client_ip();

		if ( '' !== $ip ) {
			$keys['ip'] = self::ATTEMPTS_PREFIX . 'ip_' . md5( $ip );
		}

		return $keys;
	}

	/**
	 * Whether further verification attempts are paused for this user or
	 * the current client.
	 */
	public static function is_locked_out( int $user_id ): bool {
		foreach ( self::attempt_keys( $user_id ) as $scope => $key ) {
			$attempts = (int) get_transient( $key );

			if ( $attempts >= self::get_max_attempts( $scope ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Record a failed attempt. Each failure restarts the lockout window.
	 */
	public static function register_failed_attempt( int $user_id ): void {
		foreach ( self::attempt_keys( $user_id ) as $key ) {
			set_transient( $key, (int) get_transient( $key ) + 1, self::get_lockout_duration() );
		}
	}

	public static function clear_failed_attempts( int $user_id ): void {
		delete_transient( self::ATTEMPTS_PREFIX . 'u_' . $user_id );
	}

	/**
	 * Verify a code with attempt limiting applied.
	 *
	 * @param callable $verify Receives the user ID and returns whether the code is valid.
	 *
	 * @return string 'valid', 'invalid' or 'locked'.
	 */
	protected static function attempt( int $user_id, callable $verify ): string {
		if ( self::is_locked_out( $user_id ) ) {
			return 'locked';
		}

		if ( $verify( $user_id ) ) {
			self::clear_failed_attempts( $user_id );

			return 'valid';
		}

		self::register_failed_attempt( $user_id );

		return self::is_locked_out( $user_id ) ? 'locked' : 'invalid';
	}

	// ---------------------------------------------------------------------
	// Setup (AJAX).
	// ---------------------------------------------------------------------

	/**
	 * Nonce action for the setup requests. Profile nonces are bound to the
	 * user being edited.
	 */
	public static function nonce_action( string $action, int $user_id = 0 ): string {
		return 'bmwp-' . $action . '-two-factor-nonce' . ( $user_id ? '-' . $user_id : '' );
	}

	/**
	 * Resolve which user a setup request acts on.
	 *
	 * Logged-in users (the profile screen) act on the posted user, which
	 * requires the edit_user capability. During the forced setup at login
	 * the user is logged out; the user then comes from the verification
	 * session started after the password step, never from the request.
	 *
	 * @return array{0: int, 1: ?string}|null User ID and session token, or null if not allowed.
	 */
	protected static function resolve_setup_request( string $action ): ?array {
		$nonce = sanitize_text_field( wp_unslash( (string) ( $_REQUEST['nonce'] ?? '' ) ) );

		if ( is_user_logged_in() ) {
			$user_id = (int) ( $_REQUEST['user_id'] ?? 0 );

			if ( $user_id < 1 || ! current_user_can( 'edit_user', $user_id ) ) {
				return null;
			}

			if ( ! wp_verify_nonce( $nonce, self::nonce_action( $action, $user_id ) ) ) {
				return null;
			}

			return [ $user_id, null ];
		}

		if ( ! wp_verify_nonce( $nonce, self::nonce_action( $action ) ) ) {
			return null;
		}

		$token   = self::get_request_session_token();
		$session = self::get_session( $token, self::SESSION_PURPOSE_SETUP );

		if ( ! $session ) {
			return null;
		}

		$user_id = (int) $session['user_id'];

		// The forced setup is only for users who have not enabled 2FA yet.
		if ( self::has_user_two_factor( $user_id ) ) {
			return null;
		}

		return [ $user_id, $token ];
	}

	public static function _ajax_validate(): void {
		$request = self::resolve_setup_request( 'validate' );

		if ( null === $request ) {
			wp_send_json_error( [ 'is_valid' => false, 'recovery_codes' => [] ] );
		}

		[ $user_id, $token ] = $request;

		$token_value = sanitize_text_field( wp_unslash( (string) ( $_REQUEST['token'] ?? '' ) ) );
		$result      = self::attempt( $user_id, static fn( int $id ) => self::validate_code( $token_value, $id ) );

		if ( 'locked' === $result ) {
			wp_send_json_error( [
				'is_valid'       => false,
				'locked'         => true,
				'recovery_codes' => [],
			] );
		}

		if ( 'valid' !== $result ) {
			wp_send_json_success( [
				'is_valid'       => false,
				'recovery_codes' => [],
			] );
		}

		if ( null !== $token ) {
			$session              = (array) self::get_session( $token );
			$session['validated'] = true;
			self::update_session( $token, $session );
		}

		wp_send_json_success( [
			'is_valid'       => true,
			'recovery_codes' => self::generate_and_save_recovery_codes( $user_id ),
		] );
	}

	public static function _ajax_activate(): void {
		$request = self::resolve_setup_request( 'activate' );

		if ( null === $request ) {
			wp_send_json_error();
		}

		[ $user_id, $token ] = $request;

		// Only enable once a code has been validated, which is what stores
		// the recovery codes.
		if ( ! self::get_secret_for_user( $user_id ) || empty( self::get_recovery_codes( $user_id ) ) ) {
			wp_send_json_error();
		}

		if ( null !== $token ) {
			$session = self::get_session( $token, self::SESSION_PURPOSE_SETUP );

			if ( empty( $session['validated'] ) ) {
				wp_send_json_error();
			}

			self::end_session( $token );
		}

		self::set_user_two_factor_enabled( true, $user_id );

		wp_send_json_success();
	}

	public static function _ajax_deactivate(): void {
		// Only available from the profile screen, for a logged-in user who
		// may edit the target user.
		if ( ! is_user_logged_in() ) {
			wp_send_json_error();
		}

		$request = self::resolve_setup_request( 'deactivate' );

		if ( null === $request ) {
			wp_send_json_error();
		}

		[ $user_id ] = $request;

		self::set_user_two_factor_enabled( false, $user_id );
		self::set_secret_for_user( $user_id, '' );
		delete_user_meta( $user_id, self::RECOVERY_CODES_META_KEY );

		wp_send_json_success();
	}

	public static function has_user_two_factor( ?int $user_id = null ): bool {
		return (bool) get_user_meta( self::maybe_get_current_user_id( $user_id ), self::TWO_FACTOR_STATUS_META_KEY, true );
	}

	public static function set_user_two_factor_enabled( bool $enabled = true, ?int $user_id = null ): bool {
		return update_user_meta( self::maybe_get_current_user_id( $user_id ), self::TWO_FACTOR_STATUS_META_KEY, $enabled );
	}

	protected static function maybe_get_current_user_id( ?int $user_id = null ): int {
		return $user_id ?? get_current_user_id();
	}

	/**
	 * Generate eight unique, eight-digit numeric recovery codes.
	 *
	 * Same format as the former pragmarx/recovery setup (numeric, 1 block of
	 * 8 characters, 8 codes), using a CSPRNG directly.
	 *
	 * @return string[]
	 */
	public static function generate_recovery_codes( int $count = 8, int $length = 8 ): array {
		$codes = [];

		while ( count( $codes ) < $count ) {
			$code = '';

			for ( $i = 0; $i < $length; $i++ ) {
				$code .= (string) random_int( 0, 9 );
			}

			$codes[ $code ] = $code;
		}

		return array_values( $codes );
	}

	public static function generate_and_save_recovery_codes( int $user_id ): array {
		$codes = self::generate_recovery_codes();

		update_user_meta( $user_id, self::RECOVERY_CODES_META_KEY, $codes );

		return $codes;
	}

	public static function get_recovery_codes( int $user_id ): array {
		$codes = get_user_meta( $user_id, self::RECOVERY_CODES_META_KEY, true );

		if ( ! is_array( $codes ) ) {
			$codes = [];
		}

		return $codes;
	}

	public static function handle_2fa_check_on_login( string $username, \WP_User $user ): void {
		// We're alright if the user already has 2FA enabled.
		if ( self::has_user_two_factor( $user->ID ) ) {
			return;
		}

		// Check if the user should be required to enable 2FA (respecting the
		// per-role restriction, not just the global constant).
		if ( ! self::is_required_for_user( $user->ID ) ) {
			return;
		}

		// Log the user out to force them over to 2FA.
		wp_clear_auth_cookie();

		self::load_login_template( '2fa-activation', [
			'user'    => $user,
			'session' => self::create_session( $user->ID, self::SESSION_PURPOSE_SETUP ),
		] );
	}

	public static function handle_login( string $username, \WP_User $user ): void {
		// No need to handle if user doesn't have 2FA activated.
		if ( ! self::has_user_two_factor( $user->ID ) ) {
			return;
		}

		// The user is already logged in at this point. We log them out,
		// so that we can validate the token first. Then we re-authenticate them.
		wp_clear_auth_cookie();

		$session = self::create_session( $user->ID, self::SESSION_PURPOSE_LOGIN, [
			'remember'    => ! empty( $_POST['rememberme'] ),
			'redirect_to' => isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_REQUEST['redirect_to'] ) ) : '',
		] );

		self::load_login_template( '2fa-login', [
			'user'    => $user,
			'session' => $session,
		] );
	}

	/**
	 * Resolve the verification session for a second-step login request.
	 * Redirects back to the login screen when there is no active session.
	 *
	 * @return array{0: string, 1: array}|null Token and session.
	 */
	protected static function resolve_login_request(): ?array {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return null;
		}

		$token   = self::get_request_session_token();
		$session = self::get_session( $token, self::SESSION_PURPOSE_LOGIN );
		$nonce   = sanitize_text_field( wp_unslash( (string) ( $_POST['_wpnonce'] ?? '' ) ) );

		if ( ! $session || ! wp_verify_nonce( $nonce, self::LOGIN_NONCE_ACTION ) ) {
			wp_safe_redirect( add_query_arg( 'bmwp_2fa', 'expired', wp_login_url() ) );
			exit;
		}

		return [ $token, $session ];
	}

	protected static function complete_login( string $token, array $session ): void {
		self::end_session( $token );

		$user_id = (int) $session['user_id'];

		wp_set_auth_cookie( $user_id, ! empty( $session['remember'] ) );

		$redirect_to = ! empty( $session['redirect_to'] ) ? $session['redirect_to'] : admin_url();

		wp_safe_redirect( wp_validate_redirect( $redirect_to, admin_url() ) );
		exit;
	}

	public static function validate_login(): void {
		$request = self::resolve_login_request();

		if ( null === $request ) {
			return;
		}

		[ $token, $session ] = $request;

		$user_id = (int) $session['user_id'];
		$code    = sanitize_text_field( wp_unslash( (string) ( $_POST['two_factor_token'] ?? '' ) ) );
		$result  = self::attempt( $user_id, static fn( int $id ) => self::validate_code( $code, $id ) );

		if ( 'valid' === $result ) {
			self::complete_login( $token, $session );
		}

		self::render_failed_attempt( '2fa-login', $result, $token, $user_id,
			__( 'The code you entered is not valid. Please try again.', 'bm-wp-experience' ) );
	}

	public static function validate_backup_login(): void {
		$request = self::resolve_login_request();

		if ( null === $request ) {
			return;
		}

		[ $token, $session ] = $request;

		$user_id = (int) $session['user_id'];
		$code    = sanitize_text_field( wp_unslash( (string) ( $_POST['backup_code'] ?? '' ) ) );
		$result  = self::attempt( $user_id, static fn( int $id ) => self::validate_backup_code( $code, $id ) );

		if ( 'valid' === $result ) {
			// A recovery code is single-use; consume it so it cannot be replayed.
			self::consume_recovery_code( $user_id, $code );
			self::complete_login( $token, $session );
		}

		self::render_failed_attempt( '2fa-backup', $result, $token, $user_id,
			__( 'The backup code you entered is not valid. Please try again.', 'bm-wp-experience' ) );
	}

	/**
	 * Show the form again after a failed attempt, or end the session once
	 * attempts are paused.
	 */
	protected static function render_failed_attempt( string $template, string $result, string $token, int $user_id, string $error ): void {
		if ( 'locked' === $result ) {
			self::end_session( $token );
			wp_safe_redirect( add_query_arg( 'bmwp_2fa', 'locked', wp_login_url() ) );
			exit;
		}

		self::load_login_template( $template, [
			'user'    => get_user_by( 'ID', $user_id ),
			'session' => $token,
			'error'   => $error,
		] );
	}

	public static function load_backup_codes_form(): void {
		$request = self::resolve_login_request();

		if ( null === $request ) {
			return;
		}

		[ $token, $session ] = $request;

		self::load_login_template( '2fa-backup', [
			'user'    => get_user_by( 'ID', (int) $session['user_id'] ),
			'session' => $token,
		] );
	}

	/**
	 * Explain on the login screen why the user was sent back to it.
	 */
	public static function add_session_expired_error( \WP_Error $errors ): \WP_Error {
		$reason = sanitize_key( (string) ( $_GET['bmwp_2fa'] ?? '' ) );

		if ( 'expired' === $reason ) {
			$errors->add( 'bmwp_2fa_expired', __( 'Your verification session has expired. Please log in again.', 'bm-wp-experience' ) );
		} elseif ( 'locked' === $reason ) {
			$errors->add( 'bmwp_2fa_locked', __( 'Too many incorrect codes. Please wait a few minutes and log in again.', 'bm-wp-experience' ) );
		}

		return $errors;
	}

	protected static function load_login_template( string $template, array $args = [] ): void {
		/**
		 * Fires before a two-factor login screen is rendered.
		 *
		 * @param string $template Template name (e.g. "2fa-login").
		 * @param array  $args     Template variables.
		 */
		do_action( 'bm_wpexp_before_two_factor_login_template', $template, $args );

		if ( ! function_exists( 'login_header' ) ) {
			include_once ABSPATH . 'wp-login.php';
		}

		if ( ! function_exists( 'submit_button' ) ) {
			require_once ABSPATH . '/wp-admin/includes/template.php';
		}

		extract( $args );

		// Enqueued before login_header() so the stylesheet prints in the head
		// and the script in login_footer().
		self::register_assets();
		wp_enqueue_style( self::ASSET_HANDLE );

		if ( '2fa-activation' === $template ) {
			wp_enqueue_script( self::ASSET_HANDLE );
		}

		login_header();

		include_once Plugin::get_view_path( 'public/' . $template );

		login_footer();
		exit;
	}

	protected static function get_roles_where_required(): array {
		return apply_filters( 'bm_wpexp_roles_requiring_two_factor', [
			'administrator',
			'editor',
			'author',
			'contributor',
		] );
	}

	protected static function is_required_for_website(): bool {
		return defined( 'BM_WP_REQUIRE_TWO_FACTOR' ) && BM_WP_REQUIRE_TWO_FACTOR === true;
	}

	protected static function is_required_for_user( ?int $user_id = null ): bool {
		if ( ! self::is_required_for_website() ) {
			return false;
		}

		$user_id = self::maybe_get_current_user_id( $user_id );
		$user    = get_user_by( 'ID', $user_id );

		if ( ! $user ) {
			return false;
		}

		$matches = array_intersect( self::get_roles_where_required(), $user->roles );

		return ! empty( $matches );
	}
}
