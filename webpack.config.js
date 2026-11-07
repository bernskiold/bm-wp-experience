/**
 * Webpack configuration.
 *
 * Extends the default `@wordpress/scripts` webpack configuration with two
 * builds:
 *
 * - Stylesheets: `assets/styles/src/*.scss` -> `assets/styles/dist/*.css`.
 * - Scripts: `assets/scripts/src/*.js` -> `assets/scripts/dist/*.js`, each
 *   with a generated `*.asset.php` listing its dependencies and version.
 *
 * See https://developer.wordpress.org/block-editor/reference-guides/packages/packages-scripts/
 */

const path = require( 'path' );
const defaultConfig = require( '@wordpress/scripts/config/webpack.config' );
const DependencyExtractionWebpackPlugin = require( '@wordpress/dependency-extraction-webpack-plugin' );
const RemoveEmptyScriptsPlugin = require( 'webpack-remove-empty-scripts' );

const stylesheets = [
	'admin-bar',
	'admin',
	'admin-download-manager',
	'admin-theme',
	'block-editor',
	'two-factor',
];

const scripts = [
	'admin-customize-support',
	'plugins-deactivation-warning',
	'two-factor',
];

/*
 * `defaultConfig.plugins` holds shared plugin instances. Exporting several
 * configs would otherwise reuse the same DependencyExtractionWebpackPlugin
 * instance across compilers, so give each config a fresh one.
 */
const withFreshPlugins = ( plugins ) =>
	plugins.map( ( plugin ) =>
		plugin?.constructor?.name === 'DependencyExtractionWebpackPlugin'
			? new DependencyExtractionWebpackPlugin()
			: plugin
	);

const toEntries = ( names, directory, extension ) =>
	names.reduce( ( entries, name ) => {
		entries[ name ] = path.resolve(
			__dirname,
			`${ directory }/${ name }.${ extension }`
		);
		return entries;
	}, {} );

const styles = {
	...defaultConfig,
	entry: toEntries( stylesheets, 'assets/styles/src', 'scss' ),
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
		...withFreshPlugins( defaultConfig.plugins ),
	],
};

const scriptsConfig = {
	...defaultConfig,
	entry: toEntries( scripts, 'assets/scripts/src', 'js' ),
	output: {
		...defaultConfig.output,
		path: path.resolve( __dirname, 'assets/scripts/dist' ),
		clean: true,
	},
	plugins: withFreshPlugins( defaultConfig.plugins ),
};

module.exports = [ styles, scriptsConfig ];
