<?php

namespace Bernskiold\WP\Experience\Tests;

/**
 * Thrown before a two-factor login screen renders (which would exit), so the
 * template and its variables can be asserted on.
 */
class Template_Exception extends \RuntimeException {

	public function __construct( public readonly string $template, public readonly array $args ) {
		parent::__construct( "Rendered {$template}" );
	}
}
