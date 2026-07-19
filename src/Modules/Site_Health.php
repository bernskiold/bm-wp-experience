<?php

namespace Bernskiold\WP\Experience\Modules;

use Bernskiold\WP\Experience\Modules\Health_Checks\Security;

class Site_Health extends Module {
    protected static array $checks = [
        Security\Wp_Config_Permissions_Check::class,
        Security\Env_File_Check::class,
        Security\Bm_Config_Check::class,
        Security\Maintenance_Plan_Check::class,
    ];

    public static function hooks(): void {
        add_filter( 'site_status_tests', [ self::class, 'add_tests' ] );
    }

    public static function add_tests(array $tests): array {
        foreach ( self::$checks as $check_class ) {
            $tests[ $check_class::$type ][ $check_class::$key ] = [
                'label' => $check_class::get_label(),
                'test'  => [ $check_class, 'make' ],
            ];
        }

        return $tests;
    }
}
