/**
 * Removes the default editor autocompleters (such as the user mention
 * completer) unless `BM_WP_ALLOW_USER_AUTOCOMPLETE` is enabled.
 *
 * The `bmexp_supports` settings object is printed before this script by
 * `Admin_Assets::admin_scripts()`.
 */
const settings = window.bmexp_supports || {};

if (
	! settings.allow_autocomplete &&
	typeof window.wp !== 'undefined' &&
	typeof window.wp.hooks?.removeFilter === 'function'
) {
	window.wp.hooks.removeFilter(
		'editor.Autocomplete.completers',
		'editor/autocompleters/set-default-completers'
	);
}
