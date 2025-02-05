/**
 * Laravel Mix Configuration
 *
 * We use Laravel Mix as an easy-to-understand interface for webpack,
 * which can otherwise be quite complicated. Mix is super simple and
 * works very well.
 *
 * @link https://laravel.com/docs/5.6/mix
 *
 * @author  Bernskiold <info@bernskiold.com>
 * @package BernskioldMedia\WP\Experience
 **/

const mix = require( 'laravel-mix' );

/**************************************************************
 * Build Process
 *
 * This part handles all the compilation and concatenation of
 * all the theme's resources.
 *************************************************************/

/*
 * Asset Directory Path
 */
const assetPaths = {
	scripts: 'assets/scripts',
	styles: 'assets/styles',
	images: 'assets/images',
	fonts: 'assets/fonts',
};

/*
 * Set Laravel Mix options.
 *
 * @link https://laravel-mix.com/docs/5.0/css-preprocessors
 */
mix.options( {
	processCssUrls: false,
	postCss: [
		require( 'postcss-preset-env' )( {
			stage: 4,
			browsers: [
				'> 1%',
				'last 2 versions',
				'ie >= 11',
			],
			autoprefixer: { grid: true },
		} ),
	],
} );

/*
 * Process the SCSS
 *
 * @link https://laravel-mix.com/docs/5.0/css-preprocessors
 * @link https://github.com/sass/dart-sass#javascript-api
 */
const sassConfig = {
	sassOptions: {
		outputStyle: 'compressed',
		indentType: 'tab',
		indentWidth: 1,
	},
};

// Process the scss files.
mix.sass( `${ assetPaths.styles }/src/admin-bar.scss`, `${ assetPaths.styles }/dist`, sassConfig )
   .sass( `${ assetPaths.styles }/src/admin.scss`, `${ assetPaths.styles }/dist`, sassConfig )
	.sass( `${ assetPaths.styles }/src/admin-download-manager.scss`, `${ assetPaths.styles }/dist`, sassConfig )
   .sass( `${ assetPaths.styles }/src/admin-theme.scss`, `${ assetPaths.styles }/dist`, sassConfig )
	.sass( `${assetPaths.styles}/src/block-editor.scss`, `${assetPaths.styles}/dist`, sassConfig );
