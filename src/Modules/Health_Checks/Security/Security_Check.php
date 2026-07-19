<?php

namespace Bernskiold\WP\Experience\Modules\Health_Checks\Security;

use Bernskiold\WP\Experience\Modules\Health_Checks\Health_Check;

abstract class Security_Check extends Health_Check {
    public static function get_badge_label(): string {
        return __( 'Security', 'bm-wp-experience' );
    }

    public static function get_badge_color(): string {
        return 'blue';
    }
}
