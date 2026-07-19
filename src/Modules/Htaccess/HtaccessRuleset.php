<?php

namespace Bernskiold\WP\Experience\Modules\Htaccess;

use Bernskiold\WP\Experience\Helpers;
use Bernskiold\WP\Experience\Plugin;

/**
 * @phpstan-consistent-constructor
 */
abstract class HtaccessRuleset {

	protected        $wp_filesystem;
	protected string $template;
	protected array  $rules = [
		'enabled'  => '',
		'disabled' => '',
	];

	public function __construct() {
		$this->wp_filesystem = Helpers::setup_wp_filesystem();
	}

	public static function activate(): bool {
		return ( new static() )->enable();
	}

	public static function deactivate(): bool {
		return ( new static() )->disable();
	}

	public function enable(): bool {
		if ( ! $this->ensure_exists_and_writeable() ) {
			return false;
		}

		if ( $this->is_enabled() ) {
			return true;
		}

		$existing_contents = preg_replace( $this->rules['disabled'], '', (string) $this->wp_filesystem->get_contents( $this->get_path() ) );
		$new_contents      = $this->wp_filesystem->get_contents( Plugin::get_path( 'stubs/htaccess/' . $this->template ) );

		$contents = $new_contents . PHP_EOL . $existing_contents;

		return $this->write( $contents );
	}

	public function disable(): bool {
		if ( ! $this->ensure_exists_and_writeable() ) {
			return false;
		}

		if ( ! $this->is_enabled() ) {
			return true;
		}

		$contents    = (string) $this->wp_filesystem->get_contents( $this->get_path() );
		$new_content = preg_replace( $this->rules['disabled'], '', $contents );

		return $this->write( $new_content );
	}

	protected function write( string $content ): bool {
		$fp = fopen( $this->get_path(), 'wb+' );

		if ( ! $fp ) {
			return false;
		}

		if ( flock( $fp, LOCK_EX ) ) {
			fwrite( $fp, $content );
			flock( $fp, LOCK_UN );
			fclose( $fp );

			return true;
		}

		fclose( $fp );

		return false;
	}

	protected function ensure_exists_and_writeable(): bool {
		$path = $this->get_path();
		if ( ! is_file( $path ) ) {
			$this->wp_filesystem->touch( $path );
		}

		if ( ! is_writeable( $this->get_path() ) ) {
			return false;
		}

		return true;
	}

	public function get_path(): string {
		return $this->wp_filesystem->abspath() . '.htaccess';
	}

	protected function is_enabled(): bool {
		$contents = (string) $this->wp_filesystem->get_contents( $this->get_path() );

		return (bool) preg_match( $this->rules['enabled'], $contents );
	}
}
