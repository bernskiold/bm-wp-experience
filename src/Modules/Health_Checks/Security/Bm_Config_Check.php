<?php

namespace Bernskiold\WP\Experience\Modules\Health_Checks\Security;

use Bernskiold\WP\Experience\Helpers;

class Bm_Config_Check extends Security_Check {

	public static string $key = 'bm_config_permissions';

	protected static function test(): array {
		$result = [
			'label'       => __( 'Configuration files properly secured.', 'bm-wp-experience' ),
			'status'      => 'good',
			'description' => sprintf( '<p>%s</p>', __( 'The application and environment configuration files are properly secured.', 'bm-wp-experience' ) ),
		];

		if ( ! self::all_files_pass() ) {
			$result['status']      = 'critical';
			$result['label']       = __( 'Configuration files needs securing.', 'bm-wp-experience' );
			$result['description'] = sprintf( '<p>%s</p>',
				__( 'It could be possible to access the files in the config directory. To fix, please CHMOD the file to a permission set less than, or equal to 440.',
					'bm-wp-experience' ) );
		}

		return $result;
	}

	protected static function all_files_pass(): bool {
		$files = glob( ABSPATH . 'config{,*/,*/*/,*/*/*/}*.php', GLOB_BRACE ) ?: [];

		foreach ( $files as $file ) {
			if ( Helpers::is_file_publicly_accessible( $file ) ) {
				return false;
			}
		}

		return true;
	}

	public static function get_label(): string {
		return __( 'Configuration File Permissions', 'bm-wp-experience' );
	}
}
