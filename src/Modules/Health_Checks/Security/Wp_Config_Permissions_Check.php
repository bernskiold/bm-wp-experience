<?php

namespace BernskioldMedia\WP\Experience\Modules\Health_Checks\Security;

use BernskioldMedia\WP\Experience\Helpers;

class Wp_Config_Permissions_Check extends Security_Check {

	public static string $key = 'bm_wp_config_permissions';

	protected static function test(): array {
		$result = [
			'label'       => __( 'The wp-config.php file is not readable.', 'bm-wp-experience' ),
			'status'      => 'good',
			'description' => sprintf( '<p>%s</p>',
				__( 'When the wp-config.php file is protected there is less risk of important configuration secrets becoming exposed.', 'bm-wp-experience' ) ),
		];

		if ( Helpers::is_file_publicly_accessible( ABSPATH . 'wp-config.php' ) ) {
			$result['status']      = 'critical';
			$result['label']       = __( 'The wp-config.php file is publicly readable.', 'bm-wp-experience' );
			$result['description'] = sprintf( '<p>%s</p>',
				__( 'It could be possible to access the wp-config.php file publicly. To fix, please CHMOD the file to a permission set less than, or equal to 440.',
					'bm-wp-experience' ) );
		}

		return $result;
	}

	public static function get_label(): string {
		return __( 'WP-Config File Permissions', 'bm-wp-experience' );
	}
}
