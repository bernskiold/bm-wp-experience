/**
 * ESLint flat config.
 *
 * ESLint 10 (shipped with recent `@wordpress/scripts`) only reads flat configs.
 * The wp-scripts default config is reused so the plugin and its rules never
 * drift out of step with the wp-scripts version in use.
 */

/**
 * External dependencies
 */
const globals = require( 'globals' );

/**
 * Internal dependencies
 */
const defaultConfig = require( '@wordpress/scripts/config/eslint.config.cjs' );

module.exports = [
	{
		ignores: [
			'assets/scripts/dist/**',
			'assets/styles/dist/**',
			'build/**',
			'node_modules/**',
			'vendor/**',
			'languages/**',
			// Legacy scripts, replaced in the WordPress 7 modernisation.
			'assets/scripts/alpinejs.js',
			'assets/scripts/admin-customize-support.js',
		],
	},

	...defaultConfig,

	{
		languageOptions: {
			globals: {
				...globals.browser,
				wp: 'readonly',
			},
		},
	},
];
