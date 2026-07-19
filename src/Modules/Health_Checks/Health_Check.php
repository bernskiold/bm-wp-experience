<?php

namespace Bernskiold\WP\Experience\Modules\Health_Checks;

abstract class Health_Check {
    public static string $key;
    public static string $type = 'direct';

    public static function make(): array {
        return array_merge( [
            'label'       => '',
            'status'      => 'good',
            'badge'       => [
                'label' => static::get_badge_label(),
                'color' => static::get_badge_color(),
            ],
            'description' => '',
            'actions'     => '',
            'test'        => static::$key,
        ], static::test() );
    }

    abstract protected static function test(): array;

    abstract public static function get_label(): string;

    abstract protected static function get_badge_label(): string;

    abstract protected static function get_badge_color(): string;
}
