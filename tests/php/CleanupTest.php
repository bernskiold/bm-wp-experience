<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Cleanup;

class CleanupTest extends TestCase {

	public function tear_down(): void {
		unset( $_GET['s'], $_SERVER['REQUEST_METHOD'] );

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

	public function test_random_content_redirect_is_disabled(): void {
		$this->assertFalse( apply_filters( 'wp_enable_random_content_redirect', true ) );
	}

	public function test_random_content_redirect_can_be_re_enabled(): void {
		add_filter( 'bm_wpexp_enable_random_content_redirect', '__return_true' );

		$this->assertTrue( apply_filters( 'wp_enable_random_content_redirect', true ) );

		// Opting in does not override another plugin that turns it off.
		$this->assertFalse( apply_filters( 'wp_enable_random_content_redirect', false ) );
	}

	/**
	 * @dataProvider random_content_redirect_states
	 */
	public function test_random_url_only_redirects_when_enabled( bool $enabled ): void {
		if ( ! function_exists( 'wp_is_random_content_redirect_enabled' ) ) {
			$this->markTestSkipped( 'Random content redirects require WordPress 7.2.' );
		}

		if ( $enabled ) {
			add_filter( 'bm_wpexp_enable_random_content_redirect', '__return_true' );
		}

		$post_id = self::factory()->post->create();
		$this->set_permalink_structure( '/%postname%/' );
		$this->intercept_redirects();

		$_SERVER['REQUEST_METHOD'] = 'GET';
		$this->go_to( home_url( '/random/' ) );

		try {
			wp_random_content_redirect();
			$this->assertFalse( $enabled, 'Expected a redirect to the random post.' );
		} catch ( Redirect_Exception $redirect ) {
			$this->assertTrue( $enabled, 'Expected no redirect.' );
			$this->assertSame( get_permalink( $post_id ), $redirect->location );
		}

		$this->assertSame( $enabled, [] !== $GLOBALS['wp_rewrite']->random_rewrite_rules() );
	}

	public static function random_content_redirect_states(): array {
		return [
			'disabled by default' => [ false ],
			'enabled by filter'   => [ true ],
		];
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
