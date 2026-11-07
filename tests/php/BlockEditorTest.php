<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Block_Editor;

class BlockEditorTest extends TestCase {

	public function test_font_library_and_openverse_are_disabled(): void {
		$settings = apply_filters( 'block_editor_settings_all', [ 'fontLibraryEnabled' => true, 'enableOpenverseMediaCategory' => true ], null );

		$this->assertFalse( $settings['fontLibraryEnabled'] );
		$this->assertFalse( $settings['enableOpenverseMediaCategory'] );
	}

	public function test_font_library_and_openverse_can_be_re_enabled(): void {
		add_filter( 'bm_wpexp_enable_font_library', '__return_true' );
		add_filter( 'bm_wpexp_enable_openverse', '__return_true' );

		$settings = Block_Editor::filter_block_editor_settings( [ 'fontLibraryEnabled' => true, 'enableOpenverseMediaCategory' => true ] );

		$this->assertTrue( $settings['fontLibraryEnabled'] );
		$this->assertTrue( $settings['enableOpenverseMediaCategory'] );
	}

	public function test_remote_block_patterns_are_disabled(): void {
		$this->assertFalse( apply_filters( 'should_load_remote_block_patterns', true ) );
	}

	public function test_block_directory_is_disabled(): void {
		Block_Editor::disable_block_directory();

		$this->assertFalse( has_action( 'enqueue_block_editor_assets', 'wp_enqueue_editor_block_directory_assets' ) );
	}

	public function test_editor_styles_are_not_loaded_on_the_front_end(): void {
		Block_Editor::block_editor_styles();

		$this->assertFalse( wp_style_is( 'bm-block-editor', 'enqueued' ) );
	}
}
