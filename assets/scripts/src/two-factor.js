/**
 * Two-factor authentication setup.
 *
 * Drives the multi-step setup UI rendered by `views/admin/two-factor.php`
 * (user profile, inside a modal) and `views/public/2fa-activation.php`
 * (forced setup on the login screen).
 *
 * Markup contract:
 * - Root: `[data-bmwp-two-factor]` with `data-ajax-url` and
 *   `data-nonce-{validate,activate,deactivate}` attributes, plus either
 *   `data-user-id` (profile screen, nonces bound to that user) or
 *   `data-session` (forced setup at login, the verification session token).
 * - Steps: `[data-step="1".."4"]`; only the active one is visible.
 * - Controls: `[data-two-factor-action="…"]` (see `actions` below).
 * - Optional modal: `[data-two-factor-modal]` and `[data-two-factor-overlay]`.
 * - `[data-two-factor-token]` input, `[data-two-factor-error]` message and
 *   `[data-two-factor-recovery-codes]` output.
 */

/**
 * POST an admin-ajax action and resolve with the decoded JSON response.
 *
 * @param {string} url    The admin-ajax.php URL.
 * @param {Object} fields Form fields to send.
 * @return {Promise<Object>} The decoded JSON response.
 */
export function post( url, fields ) {
	const body = new FormData();

	Object.entries( fields ).forEach( ( [ key, value ] ) => {
		body.append( key, value );
	} );

	return window
		.fetch( url, {
			method: 'POST',
			credentials: 'same-origin',
			body,
		} )
		.then( ( response ) => response.json() );
}

/**
 * Set up a single two-factor root element.
 *
 * @param {HTMLElement} root The `[data-bmwp-two-factor]` element.
 * @return {Object} The controller, exposed for testing.
 */
export function init( root ) {
	const { ajaxUrl, userId, session } = root.dataset;
	const steps = Array.from( root.querySelectorAll( '[data-step]' ) );
	const modal = root.querySelector( '[data-two-factor-modal]' );
	const overlay = root.querySelector( '[data-two-factor-overlay]' );
	const tokenInput = root.querySelector( '[data-two-factor-token]' );
	const error = root.querySelector( '[data-two-factor-error]' );
	const recoveryCodes = root.querySelector(
		'[data-two-factor-recovery-codes]'
	);

	const state = {
		activeStep: 1,
		modalOpen: false,
	};

	const render = () => {
		steps.forEach( ( step ) => {
			step.hidden = Number( step.dataset.step ) !== state.activeStep;
		} );

		if ( modal ) {
			modal.hidden = ! state.modalOpen;
		}

		if ( overlay ) {
			overlay.hidden = ! state.modalOpen;
		}
	};

	const setError = ( hasError ) => {
		if ( error ) {
			error.hidden = ! hasError;
		}
	};

	const token = () => ( tokenInput ? tokenInput.value : '' );

	// Who the request is for: the edited user on the profile screen, or the
	// verification session during the forced setup.
	const subject = () => {
		const fields = {};

		if ( userId ) {
			fields.user_id = userId;
		}

		if ( session ) {
			fields.bmwp_2fa_session = session;
		}

		return fields;
	};

	const actions = {
		open() {
			state.modalOpen = true;
			render();
		},
		close() {
			state.modalOpen = false;
			render();
		},
		next() {
			state.activeStep++;
			render();
		},
		previous() {
			state.activeStep--;
			render();
		},
		validate() {
			return post( ajaxUrl, {
				action: 'bmwp_validate_two_factor',
				nonce: root.dataset.nonceValidate,
				token: token(),
				...subject(),
			} ).then( ( response ) => {
				const data = response?.data;

				// Failed nonce checks and errors carry no data; like before,
				// they leave the UI untouched.
				if ( ! data ) {
					return;
				}

				if ( data.is_valid ) {
					state.activeStep++;
					recoveryCodes.textContent = data.recovery_codes.join( ' ' );
					setError( false );
					render();
				} else {
					setError( true );
				}
			} );
		},
		activate() {
			return post( ajaxUrl, {
				action: 'bmwp_activate_two_factor',
				nonce: root.dataset.nonceActivate,
				token: token(),
				...subject(),
			} ).then( ( response ) => {
				if ( response?.success ) {
					state.activeStep = 1;
					state.modalOpen = false;
					render();
					window.location.reload();
				}
			} );
		},
		disable() {
			return post( ajaxUrl, {
				action: 'bmwp_deactivate_two_factor',
				nonce: root.dataset.nonceDeactivate,
				...subject(),
			} ).then( () => {
				window.location.reload();
			} );
		},
	};

	root.addEventListener( 'click', ( event ) => {
		const control = event.target.closest( '[data-two-factor-action]' );

		if ( ! control || ! root.contains( control ) ) {
			return;
		}

		const action = actions[ control.dataset.twoFactorAction ];

		if ( action ) {
			event.preventDefault();
			action();
		}
	} );

	render();

	return { state, actions };
}

/**
 * Initialise every two-factor root on the page.
 */
export function initAll() {
	document.querySelectorAll( '[data-bmwp-two-factor]' ).forEach( init );
}

if ( document.readyState === 'loading' ) {
	document.addEventListener( 'DOMContentLoaded', initAll );
} else {
	initAll();
}
