<?php

namespace Bernskiold\WP\Experience\Tests;

/**
 * Thrown from the `wp_redirect` filter (and the auth cookie action) so code
 * paths that end in `exit` can be asserted on without stopping PHPUnit.
 */
class Redirect_Exception extends \RuntimeException {

	public function __construct( public readonly string $location, public readonly int $status = 302 ) {
		parent::__construct( "Redirected to {$location}" );
	}
}
