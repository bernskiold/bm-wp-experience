<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Cleanup;

class CleanupTest extends TestCase {

	public function tear_down(): void {
		unset( $_GET['s'] );

		parent::tear_down();
	}

	public function test_head_bloat_is_removed(): void {
		$this->assertFalse( has_action( 'wp_head', 'wp_generator' ) );
		$this->assertFalse( has_action( 'wp_head', 'rsd_link' ) );
		$this->assertFalse( has_action( 'wp_head', 'wlwmanifest_link' ) );
		$this->assertFalse( has_action( 'wp_head', 'wp_shortlink_wp_head' ) );
		$this->assertFalse( has_action( 'wp_head', 'adjacent_posts_rel_link_wp_head' ) );
		$this->assertFalse( has_action( 'wp_head', 'print_emoji_detection_script' ) );
		$this->assertFalse( has_action( 'wp_print_styles', 'print_emoji_styles' ) );
		$this->assertFalse( has_filter( 'wp_mail', 'wp_staticize_emoji_for_email' ) );
		$this->assertFalse( has_action( 'wp_head', 'feed_links' ) );
		$this->assertFalse( has_action( 'wp_head', 'rest_output_link_wp_head' ) );
		$this->assertFalse( has_action( 'template_redirect', 'rest_output_link_header' ) );
		$this->assertFalse( has_action( 'wp_head', 'wp_oembed_add_discovery_links' ) );
	}

	public function test_generator_is_removed_from_feeds(): void {
		$this->assertFalse( apply_filters( 'the_generator', '<generator>WordPress</generator>', 'rss2' ) );
	}

	public function test_tinymce_emoji_plugin_is_removed(): void {
		$this->assertSame( [ 'lists', 'link' ], array_values( Cleanup::disable_emojicons_tinymce( [ 'lists', 'wpemoji', 'link' ] ) ) );
	}

	public function test_admin_email_verification_is_disabled(): void {
		$this->assertSame( 0, apply_filters( 'admin_email_check_interval', 6 * MONTH_IN_SECONDS ) );
	}

	public function test_blank_search_is_turned_into_a_search(): void {
		$_GET['s'] = '';
		$this->assertSame( [ 's' => ' ' ], Cleanup::blank_search_fix( [] ) );

		$_GET['s'] = 'hello';
		$this->assertSame( [ 's' => 'hello' ], Cleanup::blank_search_fix( [ 's' => 'hello' ] ) );

		unset( $_GET['s'] );
		$this->assertSame( [], Cleanup::blank_search_fix( [] ) );
	}

	public function test_pretty_search_redirects_to_the_search_base(): void {
		$this->set_permalink_structure( '/%postname%/' );
		$this->intercept_redirects();

		$this->go_to( home_url( '/?s=hello world' ) );

		try {
			Cleanup::nice_search_url();
			$this->fail( 'Expected a redirect.' );
		} catch ( Redirect_Exception $redirect ) {
			$this->assertSame( home_url( '/search/hello%20world' ), $redirect->location );
		}
	}

	public function test_jetpack_promotions_are_disabled(): void {
		$this->assertFalse( apply_filters( 'jetpack_just_in_time_msgs', true ) );
		$this->assertFalse( apply_filters( 'jetpack_show_promotions', true ) );
	}
}
