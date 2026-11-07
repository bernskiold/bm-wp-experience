/**
 * Asks for confirmation before the plugin is deactivated from the plugins
 * screen.
 *
 * The message is printed before this script by
 * `Plugins::enqueue_deactivation_warning()`.
 */
const message = window.bmexpDeactivationWarning?.message;

if ( message ) {
	document.addEventListener( 'click', ( event ) => {
		const trigger = event.target.closest(
			'.wp-list-table.plugins tr[data-slug="bm-wp-experience"] .deactivate'
		);

		// eslint-disable-next-line no-alert -- Same confirm prompt as before.
		if ( trigger && ! window.confirm( message ) ) {
			event.preventDefault();
		}
	} );
}
