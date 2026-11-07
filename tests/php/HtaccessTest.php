<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Install;
use Bernskiold\WP\Experience\Modules\Htaccess\ResponseHeaders;
use Bernskiold\WP\Experience\Modules\Htaccess\XMLRPC_Protection;

class HtaccessTest extends TestCase {

	private string $path;
	private ?string $original = null;

	public function set_up(): void {
		parent::set_up();

		$this->path = ABSPATH . '.htaccess';

		if ( file_exists( $this->path ) ) {
			$this->original = file_get_contents( $this->path );
		}

		file_put_contents( $this->path, "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n" );
	}

	public function tear_down(): void {
		if ( null === $this->original ) {
			@unlink( $this->path );
		} else {
			file_put_contents( $this->path, $this->original );
		}

		parent::tear_down();
	}

	public function test_xmlrpc_protection_is_added_once_and_keeps_existing_rules(): void {
		$this->assertTrue( XMLRPC_Protection::activate() );
		$this->assertTrue( XMLRPC_Protection::activate() );

		$contents = file_get_contents( $this->path );

		$this->assertSame( 1, substr_count( $contents, '# BM Disable XMLRPC END' ) );
		$this->assertStringContainsString( '<Files xmlrpc.php>', $contents );
		$this->assertStringContainsString( '# BEGIN WordPress', $contents );
	}

	public function test_xmlrpc_protection_can_be_removed(): void {
		XMLRPC_Protection::activate();

		$this->assertTrue( XMLRPC_Protection::deactivate() );

		$contents = file_get_contents( $this->path );
		$this->assertStringNotContainsString( 'BM Disable XMLRPC', $contents );
		$this->assertStringContainsString( '# BEGIN WordPress', $contents );
	}

	public function test_activation_writes_the_xmlrpc_rule_while_xmlrpc_is_disabled(): void {
		Install::install();

		$this->assertStringContainsString( '# BM Disable XMLRPC END', file_get_contents( $this->path ) );
	}

	public function test_activation_removes_the_xmlrpc_rule_when_xmlrpc_is_kept(): void {
		XMLRPC_Protection::activate();
		add_filter( 'bm_wpexp_disable_xmlrpc', '__return_false' );

		Install::install();

		$this->assertStringNotContainsString( 'BM Disable XMLRPC', file_get_contents( $this->path ) );
		$this->assertStringContainsString( '# BM HTTP Response Headers', file_get_contents( $this->path ) );
	}

	public function test_response_headers_ruleset_can_be_toggled(): void {
		$this->assertTrue( ResponseHeaders::activate() );
		$enabled = file_get_contents( $this->path );

		$this->assertTrue( ResponseHeaders::deactivate() );
		$disabled = file_get_contents( $this->path );

		$this->assertNotSame( $enabled, $disabled );
		$this->assertStringContainsString( '# BEGIN WordPress', $disabled );
	}
}
