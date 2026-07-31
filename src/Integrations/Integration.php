<?php

namespace BernskioldMedia\WP\Experience\Integrations;

use BernskioldMedia\WP\Experience\Hookable;

abstract class Integration implements Hookable {
    public static string $plugin_file;
}
