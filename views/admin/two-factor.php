<?php

use Bernskiold\WP\Experience\Modules\Security\TwoFactorAuthentication;

?>
<div
	class="two-factor-section"
	data-bmwp-two-factor
	data-ajax-url="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>"
	data-user-id="<?php echo esc_attr( $user_id ); ?>"
	data-nonce-validate="<?php echo esc_attr( wp_create_nonce( TwoFactorAuthentication::nonce_action( 'validate', $user_id ) ) ); ?>"
	data-nonce-activate="<?php echo esc_attr( wp_create_nonce( TwoFactorAuthentication::nonce_action( 'activate', $user_id ) ) ); ?>"
	data-nonce-deactivate="<?php echo esc_attr( wp_create_nonce( TwoFactorAuthentication::nonce_action( 'deactivate', $user_id ) ) ); ?>"
>
	<h2><?php esc_html_e( 'Two-Factor Authentication', 'bm-wp-experience' ); ?></h2>
	<p><?php esc_html_e( 'Protect your account and increase security by enabling two-factor authentication.', 'bm-wp-experience' ); ?></p>

	<table class="form-table">
		<tr>
			<th><?php esc_html_e( 'Activation Status', 'bm-wp-experience' ); ?></th>
			<td>
				<?php if ( TwoFactorAuthentication::has_user_two_factor( $user_id ) ) : ?>
					<p style="margin-bottom: 0.5rem;"><?php _e( 'Two factor authentication is <span style="color: green; font-weight: bold;">enabled</span>.',
							'bm-wp-experience' ); ?></p>
					<button type="button" class="button" data-two-factor-action="disable"><?php esc_html_e( 'Disable Two-Factor Authentication', 'bm-wp-experience' ); ?></button>
				<?php else : ?>
					<p style="margin-bottom: 0.5rem;"><?php _e( 'Two factor authentication is
						<span style="color: red; font-weight: bold;">disabled</span>. Please enable to better secure your account.', 'bm-wp-experience' ); ?></p>
					<button type="button" class="button" data-two-factor-action="open"><?php esc_html_e( 'Enable Two-Factor Authentication', 'bm-wp-experience' ); ?></button>
				<?php endif; ?>
			</td>
		</tr>
	</table>

	<div class="two-factor-overlay" data-two-factor-overlay data-two-factor-action="close" hidden></div>
	<div class="two-factor-modal" data-two-factor-modal hidden>
		<div class="two-factor-modal-step" data-step="1">
			<h2><?php esc_html_e( 'Activate Two-Factor Authentication', 'bm-wp-experience' ); ?></h2>
			<p><?php _e( 'We recommend using an application such as
				<a href="https://1password.com" target="_blank">1Password</a> that lets you both store passwords securely, as well two factor codes.', 'bm-wp-experience' ); ?></p>
			<p><?php _e( 'You can also use a dedicated app such as <a href="https://authy.com" target="_blank">Authy</a> if you don\'t want a full password manager.',
					'bm-wp-experience' ); ?></p>
			<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="next"><?php esc_html_e( 'Get Started', 'bm-wp-experience' ); ?></button>
		</div>
		<div class="two-factor-modal-step" data-step="2" hidden>
			<p><?php esc_html_e( 'Please scan the QR code below with your authenticator application . ', 'bm-wp-experience' ); ?></p>
			<?php TwoFactorAuthentication::the_qr_code_image( [ 'two-factor-qr-code' ], $user_id ); ?>
			<div class="two-factor-modal-step-actions">
				<button type="button" class="two-factor-step-button button" data-two-factor-action="previous"><?php esc_html_e( 'Go back', 'bm-wp-experience' ); ?></button>
				<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="next"><?php esc_html_e( 'Proceed to Validate',
						'bm-wp-experience' ); ?></button>
			</div>
		</div>
		<div class="two-factor-modal-step" data-step="3" hidden>
			<p><?php esc_html_e( 'Great! Your authenticator app should now be giving you a six-digit code back. Please enter it in below. ', 'bm-wp-experience' ); ?></p>
			<div class="notice notice-error inline two-factor-error" data-two-factor-error hidden>
				<p><?php esc_html_e( 'Unfortunately the code you entered was not valid . Please try again', 'bm-wp-experience' ); ?>.</p>
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
			<div class="two-factor-modal-step-actions">
				<button type="button" class="two-factor-step-button button" data-two-factor-action="previous"><?php esc_html_e( 'Go back', 'bm-wp-experience' ); ?></button>
				<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="validate"><?php esc_html_e( 'Verify the Code', 'bm-wp-experience' ); ?></button>
			</div>
		</div>
		<div class="two-factor-modal-step" data-step="4" hidden>
			<p><?php esc_html_e( 'Please store the follow recovery codes securely in case you loose access. You will not be able to see these again.', 'bm-wp-experience' ); ?></p>
			<p class="two-factor-recovery-codes" data-two-factor-recovery-codes></p>
			<div class="two-factor-modal-step-actions">
				<button type="button" class="two-factor-step-button button button-primary" data-two-factor-action="activate"><?php esc_html_e( 'Finish Setup', 'bm-wp-experience' ); ?></button>
			</div>
		</div>
	</div>

</div>
