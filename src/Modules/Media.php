<?php
/**
 * Media Tweaks
 **/

namespace Bernskiold\WP\Experience\Modules;

class Media extends Module {
    public static function hooks(): void {
        add_filter('sanitize_file_name', [ self::class, 'sanitize_file_name_chars' ], 20);
    }

    /**
     * Sanitize the file names on upload.
     */
    public static function sanitize_file_name_chars(string $filename): string {
        $sanitized_filename = remove_accents($filename); // Convert to ASCII

        // Standard replacements
        $invalid = [
            ' '   => '-',
            '%20' => '-',
            '_'   => '-',
        ];

        $sanitized_filename = str_replace(array_keys($invalid), array_values($invalid), $sanitized_filename);

        $sanitized_filename = preg_replace('/[^A-Za-z0-9-\. ]/', '', $sanitized_filename); // Remove all non-alphanumeric except .
        $sanitized_filename = preg_replace('/\.(?=.*\.)/', '', $sanitized_filename); // Remove all but last .
        $sanitized_filename = preg_replace('/-+/', '-', $sanitized_filename); // Replace any more than one - in a row
        $sanitized_filename = str_replace('-.', '.', $sanitized_filename); // Remove last - if at the end
        $sanitized_filename = strtolower($sanitized_filename); // Lowercase

        return $sanitized_filename;
    }
}
