<?php

namespace Bernskiold\WP\Experience\Integrations;

use Bernskiold\WP\Experience\Core\Hookable;

abstract class Integration implements Hookable {
    public static string $plugin_file;
}
