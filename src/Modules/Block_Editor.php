<?php
/**
 * Tweak the Block Editor
 *
 * Most often we we build sites with the block editor,
 * we want to lock it down as much as possible. These options
 * exist here.
 */

namespace Bernskiold\WP\Experience\Modules;

use Bernskiold\WP\Experience\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Block_Editor extends Module {

	public static function hooks(): void {
		// Disable the block directory in the editor.
		add_action( 'plugins_loaded', [ self::class, 'disable_block_directory' ] );

		// Disable remote block patterns pulled from the .org pattern directory.
		add_filter( 'should_load_remote_block_patterns', [ self::class, 'should_load_remote_block_patterns' ] );

		// Lock down editor settings (Font Library, Openverse) that let editors
		// pull in external fonts and media on a whim.
		add_filter( 'block_editor_settings_all', [ self::class, 'filter_block_editor_settings' ] );

		// As of WordPress 7.0 the post editor is always iframed. Styles that
		// should affect the editor content must be enqueued through
		// enqueue_block_assets (which loads inside the iframe) rather than
		// admin_enqueue_scripts (which only loads in the parent frame).
		add_action( 'enqueue_block_assets', [ self::class, 'block_editor_styles' ] );
	}

	/**
	 * Disable the block directory.
	 *
	 * As we typically don't want people to install their own blocks
	 * from within the editor on a whim, we disable the block directory
	 * very broadly.
	 *
	 * To enable the directory, define BM_WP_ENABLE_BLOCK_DIRECTORY
	 * as true in your config.
	 */
	public static function disable_block_directory(): void {
		// If we have explicitly set to enable the block directory, don't run this.
		if ( defined( 'BM_WP_ENABLE_BLOCK_DIRECTORY' ) && BM_WP_ENABLE_BLOCK_DIRECTORY ) {
			return;
		}

		remove_action( 'enqueue_block_editor_assets', 'wp_enqueue_editor_block_directory_assets' );
		remove_action( 'enqueue_block_editor_assets', 'gutenberg_enqueue_block_editor_assets_block_directory' );
	}

	/**
	 * Disable remote block patterns.
	 *
	 * WordPress pulls block patterns from the wordpress.org pattern
	 * directory into the inserter. On managed builds we don't want editors
	 * inserting arbitrary remote patterns, so we disable this by default.
	 *
	 * To keep remote patterns, define BM_WP_ENABLE_REMOTE_BLOCK_PATTERNS
	 * as true in your config.
	 */
	public static function should_load_remote_block_patterns( bool $should_load ): bool {
		if ( defined( 'BM_WP_ENABLE_REMOTE_BLOCK_PATTERNS' ) && BM_WP_ENABLE_REMOTE_BLOCK_PATTERNS ) {
			return $should_load;
		}

		return false;
	}

	/**
	 * Lock down block editor settings.
	 *
	 * Disables the Font Library (WordPress 6.5+) and the Openverse external
	 * media inserter by default. Both let editors pull external assets into
	 * the site, which we typically want to control via the design system.
	 *
	 * Return the matching filters as true to re-enable either feature.
	 *
	 * @param array $settings The block editor settings.
	 */
	public static function filter_block_editor_settings( array $settings ): array {
		// Font Library: disable installing/uploading fonts from the editor.
		if ( true !== apply_filters( 'bm_wpexp_enable_font_library', false ) ) {
			$settings['fontLibraryEnabled'] = false;
		}

		// Openverse: disable the external free media inserter.
		if ( true !== apply_filters( 'bm_wpexp_enable_openverse', false ) ) {
			$settings['enableOpenverseMediaCategory'] = false;
		}

		return $settings;
	}

	/**
	 * Remove the Yoast SEO metabox if we're in the block editor.
	 * The sidebar options are much better for the block editor
	 * so we don't actually need it.
	 */
	public static function remove_yoast_metabox_in_block_editor(): void {
		if ( self::is_block_editor() ) {
			foreach ( get_post_types() as $post_type ) {
				remove_meta_box( 'wpseo_meta', $post_type, 'normal' );
			}
		}
	}

	public static function block_editor_styles(): void {
		// enqueue_block_assets also fires on the front end; we only want to
		// style the editor itself, so bail out everywhere but the admin editor.
		if ( ! is_admin() || ! self::is_block_editor() ) {
			return;
		}

		if ( true !== apply_filters( 'bm_wpexp_enable_block_editor_styling', true ) ) {
			return;
		}

		wp_enqueue_style( 'bm-block-editor', Plugin::get_assets_url( 'styles/dist/block-editor.css' ), [], Plugin::get_version() );
	}

	/**
	 * Check if we are currently in the block editor.
	 */
	public static function is_block_editor(): bool {
		if ( ! function_exists( 'get_current_screen' ) ) {
			return false;
		}

		$screen = get_current_screen();

		if ( method_exists( $screen, 'is_block_editor' ) ) {
			return $screen->is_block_editor();
		}

		return false;
	}
}
