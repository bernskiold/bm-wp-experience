<?php

namespace BernskioldMedia\WP\Experience\Modules\Health_Checks\Security;

use BernskioldMedia\WP\Experience\Modules\Updates;

class Maintenance_Plan_Check extends Security_Check {
    public static string $key = 'bm_maintenance_plan';

    protected static function test(): array {
        $result = [
            'label'       => __( 'This site is covered by a maintenance plan.', 'bm-wp-experience' ),
            'status'      => 'good',
            'description' => sprintf(
                '<p>%s</p>',
                __(
                    'This website is covered by a maintenance plan. That means it is getting the latest security updates and monitoring to keep it safe and secure.',
                    'bm-wp-experience'
                )
            ),
        ];

        if ( ! Updates::is_on_maintenance_plan() ) {
            $result['status']      = 'recommended';
            $result['label']       = __( 'This site is not covered by a maintenance plan.', 'bm-wp-experience' );
            $result['description'] = sprintf(
                '<p>%s</p>',
                __(
                    'Not having the site on a maintenance plan means that you need to take extra care updating WordPress, plugins and themes to keep it up to date with the latest security fixes. Contact us at <a href="mailto:support@bernskiold.com">support@bernskiold.com</a> to find out more.',
                    'bm-wp-experience'
                )
            );
        }

        return $result;
    }

    public static function get_label(): string {
        return __( 'Maintenance Plan Coverage', 'bm-wp-experience' );
    }
}
