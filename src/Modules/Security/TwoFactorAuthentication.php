<?php

namespace BernskioldMedia\WP\Experience\Modules\Security;

use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use BernskioldMedia\WP\Experience\Plugin;
use BMWPEXP_Vendor\BernskioldMedia\WP\PluginBase\Interfaces\Hookable;
use PragmaRX\Google2FA\Google2FA;
use PragmaRX\Recovery\Recovery;

class TwoFactorAuthentication implements Hookable {

	protected Google2FA $two_factor;
	private const USER_SECRET_META_KEY       = 'bmwp_two_factor_secret';
	private const TWO_FACTOR_STATUS_META_KEY = 'bmwp_two_factor_enabled';
	private const RECOVERY_CODES_META_KEY    = 'bmwp_two_factor_recovery_codes';

	public function __construct() {
		$this->two_factor = new Google2FA();
	}

	public static function hooks(): void {

        if (!extension_loaded('imagick')){
            add_action('admin_notices', [self::class, 'admin_notice_no_imagick']);
            return;
        }
		// User profile section.
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
	}

    public static function admin_notice_no_imagick(): void {
        ?>
        <div class="notice notice-error">
            <p><?php _e( 'The Two Factor Authentication module requires the Imagick PHP extension to be installed.', 'bm-wp-experience' ); ?></p>
        </div>
        <?php
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

		return (bool) ( new self() )->two_factor->verifyKey( $secret, $code );
	}

	public static function validate_backup_code( string $code, ?int $user_id = null ): bool {
		$user_id = $user_id ?? get_current_user_id();
		$codes   = self::get_recovery_codes( $user_id );

		return in_array( $code, $codes, true );
	}

	public static function _ajax_validate(): void {
		if ( ! isset( $_REQUEST['nonce'] ) || ! wp_verify_nonce( $_REQUEST['nonce'], 'bmwp-validate-two-factor-nonce' ) ) {
			return;
		}

		$token   = wp_strip_all_tags( $_REQUEST['token'] );
		$user_id = (int) wp_strip_all_tags( $_REQUEST['user_id'] );

		$is_valid = self::validate_code( $token, $user_id );

		if ( ! $is_valid ) {
			wp_send_json_success( [
				'is_valid'       => false,
				'recovery_codes' => [],
			] );
		}

		wp_send_json_success( [
			'is_valid'       => true,
			'recovery_codes' => self::generate_and_save_recovery_codes( $user_id ),
		] );
	}

	public static function _ajax_activate(): void {
		if ( ! isset( $_REQUEST['nonce'] ) || ! wp_verify_nonce( $_REQUEST['nonce'], 'bmwp-activate-two-factor-nonce' ) ) {
			return;
		}

		$user_id = (int) wp_strip_all_tags( $_REQUEST['user_id'] );

		self::set_user_two_factor_enabled( true, $user_id );

		wp_send_json_success();
	}

	public static function _ajax_deactivate(): void {
		if ( ! isset( $_REQUEST['nonce'] ) || ! wp_verify_nonce( $_REQUEST['nonce'], 'bmwp-deactivate-two-factor-nonce' ) ) {
			wp_send_json_error();
		}

		error_log( print_r( $_POST, true ) );

		$user_id = (int) wp_strip_all_tags( $_REQUEST['user_id'] );

		self::set_user_two_factor_enabled( false, $user_id );
		self::set_secret_for_user( $user_id, '' );

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

	public static function generate_and_save_recovery_codes( int $user_id ): array {
		$recovery = new Recovery();
		$codes    = $recovery->numeric()->setCount( 8 )->setBlocks( 1 )->setChars( 8 )->toArray();

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

		// Check if the user should be required to enable 2FA.
		if ( ! self::is_required_for_website() ) {
			return;
		}

		// Log the user out to force them over to 2FA.
		wp_clear_auth_cookie();

		self::load_login_template( '2fa-activation', [
			'user' => $user,
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

		self::load_login_template( '2fa-login', [
			'user' => $user,
		] );
	}

	public static function validate_login(): void {
		if ( ! isset( $_POST['user_id'] ) ) {
			return;
		}

		$user_id     = (int) wp_strip_all_tags( $_POST['user_id'] );
		$remember_me = (int) wp_strip_all_tags( $_POST['rememberme'] );
		$token       = wp_strip_all_tags( $_POST['two_factor_token'] );

		$is_valid = self::validate_code( $token, $user_id );

		if ( $is_valid ) {
			wp_set_auth_cookie( $user_id, $remember_me );

			$redirect_url = ! empty( $_POST['redirect_to'] ) ? wp_strip_all_tags( $_POST['redirect_to'] ) : get_admin_url();

			wp_safe_redirect( esc_url_raw( $redirect_url ) );
			exit;
		}

		self::load_login_template( '2fa-login', [
			'user'  => get_user_by( 'ID', $user_id ),
			'error' => __( 'The code you entered is not valid. Please try again.', 'bm-wp-experience' ),
		] );
	}

	public static function validate_backup_login(): void {
		if ( ! isset( $_POST['user_id'] ) ) {
			return;
		}

		$user_id     = (int) wp_strip_all_tags( $_POST['user_id'] );
		$remember_me = (int) wp_strip_all_tags( $_POST['rememberme'] );
		$code        = wp_strip_all_tags( $_POST['backup_code'] );

		$is_valid = self::validate_backup_code( $code, $user_id );

		if ( $is_valid ) {
			wp_set_auth_cookie( $user_id, $remember_me );

			$redirect_url = ! empty( $_POST['redirect_to'] ) ? wp_strip_all_tags( $_POST['redirect_to'] ) : get_admin_url();

			wp_safe_redirect( esc_url_raw( $redirect_url ) );
			exit;
		}

		self::load_login_template( '2fa-backup', [
			'user'  => get_user_by( 'ID', $user_id ),
			'error' => __( 'The backup code you entered is not valid. Please try again.', 'bm-wp-experience' ),
		] );
	}

	public static function load_backup_codes_form(): void {
		self::load_login_template( '2fa-backup', [
			'user' => get_user_by( 'ID', (int) wp_strip_all_tags( $_GET['user_id'] ) ),
		] );
	}

	protected static function load_login_template( string $template, array $args = [] ): void {
		if ( ! function_exists( 'login_header' ) ) {
			include_once ABSPATH . 'wp-login.php';
		}

		if ( ! function_exists( 'submit_button' ) ) {
			require_once ABSPATH . '/wp-admin/includes/template.php';
		}

		extract( $args );

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
