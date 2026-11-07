<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules;
use Bernskiold\WP\Experience\Plugin;

class PluginTest extends TestCase {

	public function test_plugin_is_loaded_as_a_singleton(): void {
		$this->assertInstanceOf( Plugin::class, bm_wp_experience() );
		$this->assertSame( bm_wp_experience(), Plugin::instance() );
	}

	public function test_class_version_matches_the_plugin_header(): void {
		$data = get_file_data( BM_WP_EXPERIENCE_FILE_PATH, [
			'version'  => 'Version',
			'requires' => 'Requires at least',
			'tested'   => 'Tested up to',
			'php'      => 'Requires PHP',
		] );

		$this->assertSame( $data['version'], Plugin::get_version() );
		$this->assertSame( '7.0', $data['requires'] );
		$this->assertSame( '7.1', $data['tested'] );
		$this->assertSame( '8.2', $data['php'] );
	}

	public function test_paths_and_urls_point_at_the_plugin(): void {
		$this->assertFileExists( Plugin::get_path( 'bm-wp-experience.php' ) );
		$this->assertFileExists( Plugin::get_view_path( 'admin/two-factor' ) );
		$this->assertStringEndsWith( '/assets/icons/bm.svg', Plugin::get_assets_url( 'icons/bm.svg' ) );
		$this->assertSame( 'bm-wp-experience', Plugin::get_textdomain() );
	}

	public function test_translations_are_loaded_on_init(): void {
		$this->assertNotFalse( has_action( 'init', [ Plugin::class, 'load_languages' ] ) );
	}

	public function test_modules_are_booted(): void {
		$this->assertNotFalse( has_filter( 'authenticate', [ Modules\Security::class, 'prevent_weak_password_auth' ] ) );
		$this->assertNotFalse( has_filter( 'rest_authentication_errors', [ Modules\Rest_Api::class, 'restrict' ] ) );
		$this->assertNotFalse( has_filter( 'sanitize_file_name', [ Modules\Media::class, 'sanitize_file_name_chars' ] ) );
		$this->assertNotFalse( has_filter( 'wp_robots', [ Modules\Environments::class, 'disable_indexing_outside_production' ] ) );
		$this->assertNotFalse( has_filter( 'block_editor_settings_all', [ Modules\Block_Editor::class, 'filter_block_editor_settings' ] ) );
		$this->assertNotFalse( has_filter( 'pre_wp_mail', [ Modules\Mail::class, 'send_mail_via_postal' ] ) );
		$this->assertNotFalse( has_action( 'admin_enqueue_scripts', [ Modules\Plugins::class, 'enqueue_deactivation_warning' ] ) );
	}

	public function test_the_update_checker_is_not_started_when_disabled(): void {
		$this->assertTrue( BM_WP_EXPERIENCE_DISABLE_UPDATER );
		$this->assertArrayNotHasKey( 'bm_wp_experience_updater', $GLOBALS );
	}
}
