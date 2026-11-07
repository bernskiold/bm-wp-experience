<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Users;

class UsersTest extends TestCase {

	public function tear_down(): void {
		unset( $_GET['author'] );

		parent::tear_down();
	}

	public function test_author_id_scans_are_redirected_home(): void {
		$this->intercept_redirects();
		$_GET['author'] = '1';

		try {
			Users::block_author_enumeration();
			$this->fail( 'Expected a redirect.' );
		} catch ( Redirect_Exception $redirect ) {
			$this->assertSame( home_url(), $redirect->location );
			$this->assertSame( 301, $redirect->status );
		}
	}

	public function test_enumeration_blocking_can_be_disabled(): void {
		$this->intercept_redirects();
		$_GET['author'] = '1';
		add_filter( 'bm_wpexp_block_user_enumeration', '__return_false' );

		Users::block_author_enumeration();

		$this->assertTrue( true, 'No redirect.' );
	}

	public function test_non_numeric_author_params_are_ignored(): void {
		$this->intercept_redirects();
		$_GET['author'] = 'admin';

		Users::block_author_enumeration();

		$this->assertTrue( true, 'No redirect.' );
	}

	public function test_enumeration_blocking_runs_before_canonical_redirects(): void {
		$this->assertSame( 0, has_action( 'template_redirect', [ Users::class, 'block_author_enumeration' ] ) );
	}

	public function test_gravatar_can_be_replaced_with_a_local_avatar(): void {
		$args = Users::disable_gravatar( [ 'size' => 96 ] );

		$this->assertStringStartsWith( 'data:image/svg+xml;base64,', $args['url'] );
		$this->assertStringContainsString( '<svg', base64_decode( substr( $args['url'], strlen( 'data:image/svg+xml;base64,' ) ) ) );
	}

	public function test_gravatar_is_enabled_by_default(): void {
		$this->assertFalse( has_filter( 'pre_get_avatar_data', [ Users::class, 'disable_gravatar' ] ) );
	}

	public function test_agency_users_are_detected_by_email_domain(): void {
		$this->assertTrue( Users::is_agency( (object) [ 'user_email' => 'someone@bernskiold.com' ] ) );
		$this->assertTrue( Users::is_agency( (object) [ 'user_email' => 'someone@BernskioldMedia.se' ] ) );
		$this->assertFalse( Users::is_agency( (object) [ 'user_email' => 'client@example.com' ] ) );

		add_filter( 'bm_wpexp_authors_email_domains', static fn() => [ 'example.com' ] );
		$this->assertTrue( Users::is_agency( (object) [ 'user_email' => 'client@example.com' ] ) );
	}
}
