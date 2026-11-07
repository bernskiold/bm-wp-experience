/**
 * Unit tests for the two-factor setup script.
 */

/**
 * External dependencies
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Internal dependencies
 */
import { init } from '../../assets/scripts/src/two-factor';

const markup = ( { modal = true, subject = 'data-user-id="7"' } = {} ) => `
	<div data-bmwp-two-factor data-ajax-url="/wp-admin/admin-ajax.php" ${ subject }
		data-nonce-validate="nv" data-nonce-activate="na" data-nonce-deactivate="nd">
		<button type="button" data-two-factor-action="open">Enable</button>
		<button type="button" data-two-factor-action="disable">Disable</button>
		${ modal ? '<div data-two-factor-overlay data-two-factor-action="close" hidden></div>' : '' }
		<div ${ modal ? 'data-two-factor-modal hidden' : '' }>
			<div data-step="1"><button type="button" data-two-factor-action="next">Start</button></div>
			<div data-step="2" hidden>
				<button type="button" data-two-factor-action="previous">Back</button>
				<button type="button" data-two-factor-action="next">Next</button>
			</div>
			<div data-step="3" hidden>
				<div data-two-factor-error hidden>Invalid</div>
				<input data-two-factor-token />
				<button type="button" data-two-factor-action="validate">Verify</button>
			</div>
			<div data-step="4" hidden>
				<p data-two-factor-recovery-codes></p>
				<button type="button" data-two-factor-action="activate">Finish</button>
			</div>
		</div>
	</div>`;

const flush = () => new Promise( ( resolve ) => setTimeout( resolve, 0 ) );

const visibleSteps = ( root ) =>
	Array.from( root.querySelectorAll( '[data-step]' ) )
		.filter( ( step ) => ! step.hidden )
		.map( ( step ) => step.dataset.step );

const click = ( root, selector ) =>
	root.querySelector( selector ).dispatchEvent(
		new window.MouseEvent( 'click', {
			bubbles: true,
			cancelable: true,
		} )
	);

const respond = ( body ) =>
	window.fetch.mockResolvedValueOnce( {
		json: () => Promise.resolve( body ),
	} );

const sentFields = ( call = 0 ) =>
	Object.fromEntries( window.fetch.mock.calls[ call ][ 1 ].body.entries() );

let root;
let reload;

beforeEach( () => {
	document.body.innerHTML = markup();
	root = document.querySelector( '[data-bmwp-two-factor]' );
	window.fetch = vi.fn();
	reload = vi.fn();
	Object.defineProperty( window, 'location', {
		configurable: true,
		value: { reload },
	} );
	init( root );
} );

describe( 'two-factor setup', () => {
	it( 'starts closed on step 1', () => {
		expect( root.querySelector( '[data-two-factor-modal]' ).hidden ).toBe(
			true
		);
		expect( root.querySelector( '[data-two-factor-overlay]' ).hidden ).toBe(
			true
		);
		expect( visibleSteps( root ) ).toEqual( [ '1' ] );
	} );

	it( 'opens the modal and closes it from the overlay', () => {
		click( root, '[data-two-factor-action="open"]' );
		expect( root.querySelector( '[data-two-factor-modal]' ).hidden ).toBe(
			false
		);
		expect( root.querySelector( '[data-two-factor-overlay]' ).hidden ).toBe(
			false
		);

		click( root, '[data-two-factor-overlay]' );
		expect( root.querySelector( '[data-two-factor-modal]' ).hidden ).toBe(
			true
		);
	} );

	it( 'moves between steps', () => {
		click( root, '[data-step="1"] [data-two-factor-action="next"]' );
		expect( visibleSteps( root ) ).toEqual( [ '2' ] );

		click( root, '[data-step="2"] [data-two-factor-action="previous"]' );
		expect( visibleSteps( root ) ).toEqual( [ '1' ] );
	} );

	it( 'prevents the default action so surrounding forms are not submitted', () => {
		const event = new window.MouseEvent( 'click', {
			bubbles: true,
			cancelable: true,
		} );
		root.querySelector( '[data-two-factor-action="next"]' ).dispatchEvent(
			event
		);

		expect( event.defaultPrevented ).toBe( true );
	} );

	it( 'posts the token and shows recovery codes on a valid code', async () => {
		click( root, '[data-step="1"] [data-two-factor-action="next"]' );
		click( root, '[data-step="2"] [data-two-factor-action="next"]' );
		root.querySelector( '[data-two-factor-token]' ).value = '123456';

		respond( {
			success: true,
			data: {
				is_valid: true,
				recovery_codes: [ '11111111', '22222222' ],
			},
		} );
		click( root, '[data-two-factor-action="validate"]' );
		await flush();

		expect( window.fetch ).toHaveBeenCalledWith(
			'/wp-admin/admin-ajax.php',
			expect.objectContaining( {
				method: 'POST',
				credentials: 'same-origin',
			} )
		);
		expect( sentFields() ).toEqual( {
			action: 'bmwp_validate_two_factor',
			nonce: 'nv',
			token: '123456',
			user_id: '7',
		} );
		expect( visibleSteps( root ) ).toEqual( [ '4' ] );
		expect(
			root.querySelector( '[data-two-factor-recovery-codes]' ).textContent
		).toBe( '11111111 22222222' );
		expect( root.querySelector( '[data-two-factor-error]' ).hidden ).toBe(
			true
		);
	} );

	it( 'shows the error and stays put on an invalid code', async () => {
		click( root, '[data-step="1"] [data-two-factor-action="next"]' );
		click( root, '[data-step="2"] [data-two-factor-action="next"]' );

		respond( {
			success: true,
			data: { is_valid: false, recovery_codes: [] },
		} );
		click( root, '[data-two-factor-action="validate"]' );
		await flush();

		expect( visibleSteps( root ) ).toEqual( [ '3' ] );
		expect( root.querySelector( '[data-two-factor-error]' ).hidden ).toBe(
			false
		);
	} );

	it( 'leaves the UI untouched when the request is rejected', async () => {
		click( root, '[data-step="1"] [data-two-factor-action="next"]' );
		click( root, '[data-step="2"] [data-two-factor-action="next"]' );

		respond( 0 );
		click( root, '[data-two-factor-action="validate"]' );
		await flush();

		expect( visibleSteps( root ) ).toEqual( [ '3' ] );
		expect( root.querySelector( '[data-two-factor-error]' ).hidden ).toBe(
			true
		);
	} );

	it( 'reloads after a successful activation only', async () => {
		respond( { success: false } );
		click( root, '[data-two-factor-action="activate"]' );
		await flush();
		expect( reload ).not.toHaveBeenCalled();

		respond( { success: true } );
		click( root, '[data-two-factor-action="activate"]' );
		await flush();

		expect( sentFields( 1 ) ).toMatchObject( {
			action: 'bmwp_activate_two_factor',
			nonce: 'na',
			user_id: '7',
		} );
		expect( reload ).toHaveBeenCalledTimes( 1 );
	} );

	it( 'reloads after disabling, whatever the response', async () => {
		respond( { success: false } );
		click( root, '[data-two-factor-action="disable"]' );
		await flush();

		expect( sentFields() ).toEqual( {
			action: 'bmwp_deactivate_two_factor',
			nonce: 'nd',
			user_id: '7',
		} );
		expect( reload ).toHaveBeenCalledTimes( 1 );
	} );

	it( 'sends the verification session on the login screen', async () => {
		document.body.innerHTML = markup( {
			modal: false,
			subject: 'data-session="abc123"',
		} );
		const loginRoot = document.querySelector( '[data-bmwp-two-factor]' );
		init( loginRoot );
		loginRoot.querySelector( '[data-two-factor-token]' ).value = '123456';

		respond( {
			success: true,
			data: { is_valid: false, recovery_codes: [] },
		} );
		click( loginRoot, '[data-two-factor-action="validate"]' );
		await flush();

		expect( sentFields() ).toEqual( {
			action: 'bmwp_validate_two_factor',
			nonce: 'nv',
			token: '123456',
			bmwp_2fa_session: 'abc123',
		} );

		respond( { success: true } );
		click( loginRoot, '[data-two-factor-action="activate"]' );
		await flush();

		expect( sentFields( 1 ) ).toEqual( {
			action: 'bmwp_activate_two_factor',
			nonce: 'na',
			token: '123456',
			bmwp_2fa_session: 'abc123',
		} );
	} );

	it( 'shows the error when the server reports the request as rejected', async () => {
		click( root, '[data-step="1"] [data-two-factor-action="next"]' );
		click( root, '[data-step="2"] [data-two-factor-action="next"]' );

		respond( {
			success: false,
			data: { is_valid: false, locked: true, recovery_codes: [] },
		} );
		click( root, '[data-two-factor-action="validate"]' );
		await flush();

		expect( visibleSteps( root ) ).toEqual( [ '3' ] );
		expect( root.querySelector( '[data-two-factor-error]' ).hidden ).toBe(
			false
		);
	} );

	it( 'works without a modal (login screen)', () => {
		document.body.innerHTML = markup( { modal: false } );
		const loginRoot = document.querySelector( '[data-bmwp-two-factor]' );
		init( loginRoot );

		expect( visibleSteps( loginRoot ) ).toEqual( [ '1' ] );
		click( loginRoot, '[data-step="1"] [data-two-factor-action="next"]' );
		expect( visibleSteps( loginRoot ) ).toEqual( [ '2' ] );
	} );
} );
