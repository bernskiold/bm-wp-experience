<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Security;
use WP_Error;
use WP_User;

class SecurityTest extends TestCase {

	public function test_the_file_editor_is_disabled(): void {
		$this->assertTrue( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
	}

	public function test_weak_passwords_are_rejected_at_login_in_production(): void {
		$this->assertSame( 'production', wp_get_environment_type() );

		self::factory()->user->create( [ 'user_login' => 'weakling', 'user_pass' => 'password' ] );

		$result = wp_authenticate( 'weakling', 'password' );

		$this->assertWPError( $result );
		$this->assertSame( 'Auth Error', $result->get_error_code() );
		$this->assertStringContainsString( wp_lostpassword_url(), $result->get_error_message() );
	}

	public function test_weak_password_check_is_case_and_whitespace_insensitive(): void {
		$user = new WP_User( self::factory()->user->create() );

		foreach ( [ 'PASSWORD', ' Qwerty ', 'letmein' ] as $password ) {
			$this->assertWPError( Security::prevent_weak_password_auth( $user, 'someone', $password ), $password );
		}
	}

	public function test_strong_passwords_pass_through(): void {
		self::factory()->user->create( [ 'user_login' => 'strong', 'user_pass' => 'c0rrect-h0rse-battery-staple' ] );

		$this->assertInstanceOf( WP_User::class, wp_authenticate( 'strong', 'c0rrect-h0rse-battery-staple' ) );
	}

	public function test_an_earlier_authentication_error_is_kept(): void {
		$error = new WP_Error( 'incorrect_password', 'Nope' );

		$this->assertSame( $error, Security::prevent_weak_password_auth( $error, 'someone', 'c0rrect-h0rse' ) );
	}

	public function test_weak_password_list_is_filterable(): void {
		add_filter( 'bm_wpexp_weak_passwords', static fn( array $list ) => array_merge( $list, [ 'bernskiold' ] ) );

		$this->assertContains( 'bernskiold', Security::get_weak_passwords() );
		$this->assertWPError( Security::prevent_weak_password_auth( new WP_User( self::factory()->user->create() ), 'someone', 'Bernskiold' ) );
	}
}
