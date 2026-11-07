<?php

use Bernskiold\WP\Experience\Modules\Security\TwoFactorAuthentication;
?>

<?php if ( isset( $error ) ) : ?>
	<div id="login_error"><strong><?php esc_html_e( 'Error', 'bm-wp-experience' ); ?></strong>: <?php echo esc_html( $error ); ?></div>
<?php endif ?>

<form class="two-factor-validation-form two-factor-backup-code-form" name="2fa_backup_code_validation" id="loginform" action="<?php echo esc_url( add_query_arg( 'action',
	'2fa_backup', wp_login_url() ) ); ?>" method="post">
	<p><?php esc_html_e( 'Please enter one of your backup codes to log into your account.', 'bm-wp-experience' ); ?></p>

	<p>
		<label for="backup_code" class="screen-reader-text"><?php esc_html_e( 'Backup Code:', 'bm-wp-experience' ); ?></label>
		<input name="backup_code" id="backup_code" class="input two-factor-backup-code-input" value="" pattern="[0-9]*" autofocus type="number" />
	</p>

	<input type="hidden" name="backup_code_used" value="1" />
	<input type="hidden" name="<?php echo esc_attr( TwoFactorAuthentication::SESSION_FIELD ); ?>" value="<?php echo esc_attr( $session ); ?>" />
	<?php wp_nonce_field( TwoFactorAuthentication::LOGIN_NONCE_ACTION ); ?>

	<?php submit_button( __( 'Log In', 'bm-wp-experience' ) ); ?>
</form>
