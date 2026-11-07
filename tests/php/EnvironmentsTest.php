<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Environments;
use WP_Admin_Bar;

class EnvironmentsTest extends TestCase {

	public function test_production_robots_are_left_alone(): void {
		$this->assertSame( 'production', wp_get_environment_type() );
		$this->assertSame( [ 'max-image-preview' => 'large' ], Environments::disable_indexing_outside_production( [ 'max-image-preview' => 'large' ] ) );
	}

	public function test_environment_label_is_shown_to_administrators(): void {
		require_once ABSPATH . WPINC . '/class-wp-admin-bar.php';
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );

		$bar = new WP_Admin_Bar();
		Environments::show_in_admin_bar( $bar );

		$node = $bar->get_node( 'bm-environment' );
		$this->assertNotNull( $node );
		$this->assertSame( 'Production', $node->title );
		$this->assertStringContainsString( 'environment--production', $node->meta['class'] );
	}

	public function test_environment_label_is_hidden_from_editors(): void {
		require_once ABSPATH . WPINC . '/class-wp-admin-bar.php';
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'editor' ] ) );

		$bar = new WP_Admin_Bar();
		Environments::show_in_admin_bar( $bar );

		$this->assertNull( $bar->get_node( 'bm-environment' ) );
	}

	public function test_staging_notice_is_not_shown_in_production(): void {
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );

		ob_start();
		Environments::show_public_staging_notice();

		$this->assertSame( '', ob_get_clean() );
	}
}
