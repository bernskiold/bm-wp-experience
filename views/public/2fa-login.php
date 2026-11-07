<?php

use Bernskiold\WP\Experience\Modules\Security\TwoFactorAuthentication;

$backup_codes_action = add_query_arg( 'action', 'load_backup_codes', wp_login_url() );
?>

<?php if ( isset( $error ) ) : ?>
	<div id="login_error">
		<strong><?php esc_html_e( 'Error', 'bm-wp-experience' ); ?></strong>: <?php echo esc_html( $error ); ?>
	</div>
<?php endif; ?>

<form class="two-factor-validation-form two-factor-one-time-code-form" name="2fa_validation" id="loginform" action="<?php echo esc_url( add_query_arg( 'action', '2fa_validation',
	wp_login_url() ) ); ?>" method="post">
	<p><?php esc_html_e( 'Please enter the verification code from your authenticator app.', 'bm-wp-experience' ); ?></p>

	<p>
		<label class="screen-reader-text" for="two_factor_token"><?php esc_html_e( 'Authentication Code:', 'bm-wp-experience' ); ?></label>
		<input
			class="two-factor-token-input input"
			type="number"
			name="two_factor_token"
			id="two_factor_token"
			inputmode="numeric"
			pattern="[0-9]*"
			autocomplete="one-time-code"
			autofocus
		/>
	</p>

	<input type="hidden" name="<?php echo esc_attr( TwoFactorAuthentication::SESSION_FIELD ); ?>" value="<?php echo esc_attr( $session ); ?>" />
	<?php wp_nonce_field( TwoFactorAuthentication::LOGIN_NONCE_ACTION ); ?>

	<?php submit_button( __( 'Log In', 'bm-wp-experience' ) ); ?>
</form>

<form id="nav" class="two-factor-backup-code-action" action="<?php echo esc_url( $backup_codes_action ); ?>" method="post">
	<input type="hidden" name="<?php echo esc_attr( TwoFactorAuthentication::SESSION_FIELD ); ?>" value="<?php echo esc_attr( $session ); ?>" />
	<?php wp_nonce_field( TwoFactorAuthentication::LOGIN_NONCE_ACTION ); ?>
	<button type="submit" class="button-link"><?php esc_html_e( 'Login using backup code', 'bm-wp-experience' ); ?></button>
</form>
