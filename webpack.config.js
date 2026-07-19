/**
 * Webpack Configuration
 *
 * Extends the default @wordpress/scripts webpack configuration to compile
 * the plugin's SCSS stylesheets from `assets/styles/src` into minified CSS
 * in `assets/styles/dist`.
 *
 * @link https://developer.wordpress.org/block-editor/reference-guides/packages/packages-scripts/
 *
 * @author  Bernskiold <info@bernskiold.com>
 * @package Bernskiold\WP\Experience
 **/

const path = require( 'path' );
const defaultConfig = require( '@wordpress/scripts/config/webpack.config' );
const RemoveEmptyScriptsPlugin = require( 'webpack-remove-empty-scripts' );

const stylesheets = [
	'admin-bar',
	'admin',
	'admin-download-manager',
	'admin-theme',
	'block-editor',
];

module.exports = {
	...defaultConfig,
	entry: stylesheets.reduce( ( entries, name ) => {
		entries[ name ] = path.resolve( __dirname, `assets/styles/src/${ name }.scss` );
		return entries;
	}, {} ),
	output: {
		...defaultConfig.output,
		path: path.resolve( __dirname, 'assets/styles/dist' ),
		// Clean the dist directory on build, but keep the tracked `.gitkeep`.
		clean: {
			keep: /\.gitkeep$/,
		},
	},
	plugins: [
		// Prevents empty `.js` files from being generated for style-only entries.
		new RemoveEmptyScriptsPlugin(),
		...defaultConfig.plugins,
	],
};
