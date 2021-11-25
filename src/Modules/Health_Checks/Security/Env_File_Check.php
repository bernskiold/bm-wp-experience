<?php

namespace BernskioldMedia\WP\Experience\Modules\Health_Checks\Security;

use BernskioldMedia\WP\Experience\Helpers;

class Env_File_Check extends Security_Check {
    public static string $key = 'bm_env_file_check';

    protected static function test(): array {
        $result = [
            'label'       => __( 'The .env file is protected.', 'bm-wp-experience' ),
            'status'      => 'good',
            'description' => sprintf( '<p>%s</p>', __( 'The .env file with secrets is properly protected.', 'bm-wp-experience' ) ),
        ];

        $path = ABSPATH . '.env';

        if ( ! file_exists( $path ) ) {
            $result['label']       = __( 'There is no .env file present.' );
            $result['description'] = sprintf( '<p>%s</p>', __( 'You are not using a .env file on this environment. No need to do anything.', 'bm-wp-experience' ) );
        }

        if ( file_exists( $path ) && 440 < Helpers::get_file_permissions( $path ) ) {
            $result['status']      = 'critical';
            $result['label']       = __( 'The .env file is readable!', 'bm-wp-experience' );
            $result['description'] = sprintf(
                '<p>%s</p>',
                __(
                    'This issue poses a major security flaw on the system. This should be fixed immediately as personal data and/or passwords could be exposed.',
                    'bm-wp-experience'
                )
            );
        }

        return $result;
    }

    public static function get_label(): string {
        return __( '.env File Permissions', 'bm-wp-experience' );
    }
}
