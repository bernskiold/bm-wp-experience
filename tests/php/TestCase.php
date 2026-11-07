<?php

namespace Bernskiold\WP\Experience\Tests;

use WP_UnitTestCase;

abstract class TestCase extends WP_UnitTestCase {

	/**
	 * Turn redirects into exceptions for the duration of a test.
	 */
	protected function intercept_redirects(): void {
		add_filter(
			'wp_redirect',
			static function ( $location, $status ) {
				throw new Redirect_Exception( (string) $location, (int) $status );
			},
			PHP_INT_MAX,
			2
		);
	}

	/**
	 * Call a protected/private static method.
	 */
	protected function call_static( string $class, string $method, array $args = [] ) {
		$reflection = new \ReflectionMethod( $class, $method );

		return $reflection->invokeArgs( null, $args );
	}
}
