<?php

use Bernskiold\WP\Experience\Modules\Security\TwoFactorAuthentication;

?>
<form
	class="two-factor-activation-form"
	name="2fa_activation"
	id="loginform"
	data-bmwp-two-factor
	data-ajax-url="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>"
	data-session="<?php echo esc_attr( $session ); ?>"
	data-nonce-validate="<?php echo esc_attr( wp_create_nonce( TwoFactorAuthentication::nonce_action( 'validate' ) ) ); ?>"
	data-nonce-activate="<?php echo esc_attr( wp_create_nonce( TwoFactorAuthentication::nonce_action( 'activate' ) ) ); ?>"
	action="<?php echo esc_url( add_query_arg( 'action', '2fa_activation',
	wp_login_url() ) ); ?>" method="post">
	<div class="two-factor-step" data-step="1">
		<h3><?php esc_html_e( 'Activate Two-Factor Authentication', 'bm-wp-experience' ); ?></h3>
		<p><?php esc_html_e( 'You are required to activate two-factor authentication for your account to strengthen security.', 'bm-wp-experience' ); ?></p>
		<p><?php _e( 'We recommend using an application such as
				<a href="https://1password.com" target="_blank">1Password</a> that lets you both store passwords securely, as well two factor codes.', 'bm-wp-experience' ); ?></p>
		<p><?php _e( 'You can also use a dedicated app such as <a href="https://authy.com" target="_blank">Authy</a> if you don\'t want a full password manager.',
				'bm-wp-experience' ); ?></p>
		<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="next"><?php esc_html_e( 'Get Started', 'bm-wp-experience' ); ?></button>
	</div>
	<div class="two-factor-step" data-step="2" hidden>
		<p><?php esc_html_e( 'Please scan the QR code below with your authenticator application . ', 'bm-wp-experience' ); ?></p>
		<?php TwoFactorAuthentication::the_qr_code_image( [ 'two-factor-qr-code' ], $user->ID ); ?>
		<div class="two-factor-step-actions">
			<button type="button" class="two-factor-step-button button" data-two-factor-action="previous"><?php esc_html_e( 'Go back', 'bm-wp-experience' ); ?></button>
			<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="next"><?php esc_html_e( 'Proceed to Validate', 'bm-wp-experience' ); ?></button>
		</div>
	</div>
	<div class="two-factor-step" data-step="3" hidden>
		<p><?php esc_html_e( 'Great! Your authenticator app should now be giving you a six-digit code back. Please enter it in below. ', 'bm-wp-experience' ); ?></p>
		<div id="login_error" class="two-factor-error" data-two-factor-error hidden>
			<?php esc_html_e( 'Unfortunately the code you entered was not valid . Please try again.', 'bm-wp-experience' ); ?>
		</div>
		<input
			class="two-factor-token-input input"
			type="number"
			name="token"
			id="token"
			data-two-factor-token
			inputmode="numeric"
			pattern="[0-9]*"
			autocomplete="one-time-code"
		/>
		<div class="two-factor-step-actions">
			<button type="button" class="two-factor-step-button button" data-two-factor-action="previous"><?php esc_html_e( 'Go back', 'bm-wp-experience' ); ?></button>
			<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="validate"><?php esc_html_e( 'Verify the Code', 'bm-wp-experience' ); ?></button>
		</div>
	</div>
	<div class="two-factor-step" data-step="4" hidden>
		<p><?php esc_html_e( 'Please store the follow recovery codes securely in case you loose access. You will not be able to see these again.', 'bm-wp-experience' ); ?></p>
		<p class="two-factor-recovery-codes" data-two-factor-recovery-codes></p>
		<div class="two-factor-step-actions">
			<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="activate"><?php esc_html_e( 'Finish Setup', 'bm-wp-experience' ); ?></button>
		</div>
	</div>
</form>
