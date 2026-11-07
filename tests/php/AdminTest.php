<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Admin\Admin_Assets;
use Bernskiold\WP\Experience\Modules\Plugins;

/**
 * Admin-only classes are booted when is_admin(), which is false in the test
 * run, so their callbacks are exercised directly.
 */
class AdminTest extends TestCase {

	private const DEACTIVATION_HANDLE = 'bm-wp-experience-plugins-deactivation-warning';
	private const CUSTOMIZE_HANDLE    = 'bm-wp-experience-customize-support';

	public function test_suggested_plugins_tab_comes_first(): void {
		$tabs = Plugins::add_suggested_plugin_install_link( [ 'featured' => 'Featured', 'popular' => 'Popular' ] );

		$this->assertSame( [ 'bmedia', 'featured', 'popular' ], array_keys( $tabs ) );
		$this->assertSame( 'bernskioldmedia', Plugins::plugins_api_args()['user'] );
	}

	public function test_learn_more_link_is_only_added_to_this_plugin(): void {
		$meta = Plugins::show_plugin_meta( [], 'bm-wp-experience/bm-wp-experience.php', [], 'all' );
		$this->assertCount( 1, $meta );
		$this->assertStringContainsString( 'page=bmedia-about', $meta[0] );

		$this->assertSame( [], Plugins::show_plugin_meta( [], 'akismet/akismet.php', [], 'all' ) );
	}

	public function test_deactivation_warning_is_enqueued_on_the_plugins_screen_only(): void {
		Plugins::enqueue_deactivation_warning( 'index.php' );
		$this->assertFalse( wp_script_is( self::DEACTIVATION_HANDLE, 'enqueued' ) );

		Plugins::enqueue_deactivation_warning( 'plugins.php' );
		$this->assertTrue( wp_script_is( self::DEACTIVATION_HANDLE, 'enqueued' ) );

		$before = implode( '', array_filter( wp_scripts()->get_data( self::DEACTIVATION_HANDLE, 'before' ) ) );
		$this->assertStringStartsWith( 'window.bmexpDeactivationWarning = {"message":"Warning: This plugin provides', $before );
		$this->assertStringContainsString( '\n\nAre you sure you want to deactivate?', $before );
		$this->assertStringEndsWith( 'assets/scripts/dist/plugins-deactivation-warning.js', wp_scripts()->registered[ self::DEACTIVATION_HANDLE ]->src );
	}

	public function test_customize_support_script_receives_its_settings_inline(): void {
		Admin_Assets::admin_scripts();

		$this->assertTrue( wp_script_is( self::CUSTOMIZE_HANDLE, 'enqueued' ) );
		$this->assertSame(
			[ 'window.bmexp_supports = {"allow_autocomplete":false};' ],
			array_values( array_filter( wp_scripts()->get_data( self::CUSTOMIZE_HANDLE, 'before' ) ) )
		);
		$this->assertFalse( wp_scripts()->get_data( self::CUSTOMIZE_HANDLE, 'data' ), 'No wp_localize_script data.' );
		$this->assertArrayNotHasKey( 'group', wp_scripts()->registered[ self::CUSTOMIZE_HANDLE ]->extra, 'Printed in the head.' );
	}
}
