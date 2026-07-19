<?php

use Bernskiold\WP\Experience\Modules\Security\TwoFactorAuthentication;

?>
<form class="two-factor-activation-form" name="2fa_activation" id="loginform" x-data="twoFactorActivation" action="<?php echo esc_url( add_query_arg( 'action', '2fa_activation',
	wp_login_url() ) ); ?>" method="post">
	<div class="two-factor-step" x-show="activeStep === 1">
		<h3><?php esc_html_e( 'Activate Two-Factor Authentication', 'bm-wp-experience' ); ?></h3>
		<p><?php esc_html_e( 'You are required to activate two-factor authentication for your account to strengthen security.', 'bm-wp-experience' ); ?></p>
		<p><?php _e( 'We recommend using an application such as
				<a href="https://1password.com" target="_blank">1Password</a> that lets you both store passwords securely, as well two factor codes.', 'bm-wp-experience' ); ?></p>
		<p><?php _e( 'You can also use a dedicated app such as <a href="https://authy.com" target="_blank">Authy</a> if you don\'t want a full password manager.',
				'bm-wp-experience' ); ?></p>
		<button class="two-factor-step-button button button-primary" @click.prevent="activeStep++"><?php esc_html_e( 'Get Started', 'bm-wp-experience' ); ?></button>
	</div>
	<div class="two-factor-step" x-show="activeStep === 2">
		<p><?php esc_html_e( 'Please scan the QR code below with your authenticator application . ', 'bm-wp-experience' ); ?></p>
		<?php TwoFactorAuthentication::the_qr_code_image( [ 'two-factor-qr-code' ], $user->ID ); ?>
		<div class="two-factor-step-actions">
			<button class="two-factor-step-button button" @click.prevent="activeStep--"><?php esc_html_e( 'Go back', 'bm-wp-experience' ); ?></button>
			<button class="two-factor-step-button button button-primary" @click.prevent="activeStep++"><?php esc_html_e( 'Proceed to Validate', 'bm-wp-experience' ); ?></button>
		</div>
	</div>
	<div class="two-factor-step" x-show="activeStep === 3">
		<p><?php esc_html_e( 'Great! Your authenticator app should now be giving you a six-digit code back. Please enter it in below. ', 'bm-wp-experience' ); ?></p>
		<div id="login_error" class="two-factor-error" x-show="activationError" x-cloak x-transition>
			<?php esc_html_e( 'Unfortunately the code you entered was not valid . Please try again.', 'bm-wp-experience' ); ?>
		</div>
		<input
			class="two-factor-token-input input"
			type="number"
			name="token"
			id="token"
			x-model="token"
			inputmode="numeric"
			pattern="[0-9]*"
			autocomplete="one-time-code"
		/>
		<div class="two-factor-step-actions">
			<button class="two-factor-step-button button" @click.prevent="activeStep--"><?php esc_html_e( 'Go back', 'bm-wp-experience' ); ?></button>
			<button class="two-factor-step-button button button-primary" @click.prevent="validate"><?php esc_html_e( 'Verify the Code', 'bm-wp-experience' ); ?></button>
		</div>
	</div>
	<div class="two-factor-step" x-show="activeStep === 4">
		<p><?php esc_html_e( 'Please store the follow recovery codes securely in case you loose access. You will not be able to see these again.', 'bm-wp-experience' ); ?></p>
		<p class="two-factor-recovery-codes" x-text="recoveryCodes"></p>
		<div class="two-factor-step-actions">
			<button class="two-factor-step-button button button-primary" @click.prevent="activate"><?php esc_html_e( 'Finish Setup', 'bm-wp-experience' ); ?></button>
		</div>
	</div>
</form>

<script src="<?php echo esc_url( \Bernskiold\WP\Experience\Plugin::get_assets_url( 'scripts/alpinejs.js' ) ); ?>" defer></script>
<script>
	document.addEventListener( 'alpine:init', () => {
		Alpine.data( 'twoFactorActivation', () => ( {
			activeStep: 1,
			token: '',
			recoveryCodes: '',
			activationError: false,
			disable() {
				const body = new FormData();
				body.append( 'action', 'bmwp_deactivate_two_factor' );
				body.append( 'nonce', '<?php echo esc_js( wp_create_nonce( 'bmwp-deactivate-two-factor-nonce' ) ); ?>' );
				body.append( 'user_id', '<?php echo esc_js( $user->ID ); ?>' );

				fetch( '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>', {
					method: 'POST',
					credentials: 'same-origin',
					body,
				} )
					.then( ( response ) => response.json() )
					.then( ( response ) => {
						location.reload();
					} );
			},
			validate() {
				const body = new FormData();
				body.append( 'action', 'bmwp_validate_two_factor' );
				body.append( 'nonce', '<?php echo esc_js( wp_create_nonce( 'bmwp-validate-two-factor-nonce' ) ); ?>' );
				body.append( 'token', this.token );
				body.append( 'user_id', '<?php echo esc_js( $user->ID ); ?>' );

				fetch( '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>', {
					method: 'POST',
					credentials: 'same-origin',
					body,
				} )
					.then( ( response ) => response.json() )
					.then( ( { data } ) => {
						if ( data.is_valid ) {
							this.activeStep++;
							this.recoveryCodes = data.recovery_codes.join( ' ' );
							this.activationError = false;
						} else {
							this.activationError = true;
						}
					} );
			},
			activate() {
				const body = new FormData();
				body.append( 'action', 'bmwp_activate_two_factor' );
				body.append( 'nonce', '<?php echo esc_js( wp_create_nonce( 'bmwp-activate-two-factor-nonce' ) ); ?>' );
				body.append( 'token', this.token );
				body.append( 'user_id', '<?php echo esc_js( $user->ID ); ?>' );

				fetch( '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>', {
					method: 'POST',
					credentials: 'same-origin',
					body,
				} )
					.then( ( response ) => response.json() )
					.then( ( response ) => {
						if ( response.success ) {
							this.activeStep = 1;
							this.modalOpen = false;
							location.reload();
						}
					} );
			},
		} ) );
	} );
</script>
<style>
	[x-cloak] {
		display: none;
	}

	.two-factor-step h3,
	#login form .two-factor-step p {
		margin-bottom: 1em;
	}

	.two-factor-step-actions {
		background-color: #f9f9f9;
		border-top: 1px solid #eee;
		padding: 1.5rem 2.5rem 1.5rem 2.5rem;
		margin: 2.5rem -2.5rem -2.5rem;
		display: flex;
		justify-content: space-between;
	}

	.two-factor-token-input {
		font-size: 22px;
	}

	.two-factor-token-input::-webkit-inner-spin-button,
	.two-factor-token-input::-webkit-outer-spin-button {
		-webkit-appearance: none;
		margin: 0;
	}

	.two-factor-qr-code {
		width: 280px;
		height: 280px;
		display: block;
		margin: 1rem auto;
	}

	.two-factor-recovery-codes {
		background-color: #f9f9f9;
		padding: 1rem;
		font-family: monospace;
	}
</style>
