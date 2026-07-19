<?php
/**
 * Customizer
 *
 * Adds various opinionated tweaks to the customizer.
 */

namespace BernskioldMedia\WP\Experience\Modules;

if (! defined('ABSPATH')) {
    exit;
}

class Customizer extends Module {
    /**
     * Option key where to store the CSS last updated time.
     */
    protected const CSS_LAST_UPDATED_OPTION_KEY = 'bmwp_custom_css_last_updated_time';

    /**
     * The file name of the custom CSS from the customizer.
     *
     * @var string
     */
    protected static string $custom_css_file_name = 'app';

    /**
     * Custom CSS ID.
     */
    public const CUSTOM_CSS_ID = 'custom-adjustments';

    /**
     * Init.
     */
    public static function hooks(): void {
        if (false === apply_filters('bm_wpexp_custom_css_as_file', false)) {
            return;
        }

        // Create the custom CSS file on save.
        add_action('customize_save_after', [ self::class, 'save_custom_css_to_file' ]);

        // Load the custom CSS file.
        add_action('wp_enqueue_scripts', [ self::class, 'load_custom_css' ], 999);
        add_action('enqueue_block_editor_assets', [ self::class, 'load_custom_css' ], 999);

        // Remove the inline styles.
        remove_action('wp_head', 'wp_custom_css_cb', 101);
    }

    /**
     * Enqueue the custom CSS file.
     */
    public static function load_custom_css(): void {
        wp_register_style(self::CUSTOM_CSS_ID, self::get_custom_css_file_url(), [], self::get_custom_css_last_updated_time(), 'all');
        wp_style_add_data(self::CUSTOM_CSS_ID, 'path', self::get_custom_css_file_path());

        // Only load the file if it exists = if we have custom files.
        if (file_exists(self::get_custom_css_file_path())) {
            wp_enqueue_style(self::CUSTOM_CSS_ID);
        }
    }

    /**
     * Save the custom CSS to a file.
     */
    public static function save_custom_css_to_file(): void {
        $styles = wp_get_custom_css();

        self::maybe_create_custom_css_storage_directory();

        // If we don't have styles, we remove the file.
        if (empty($styles)) {
            self::remove_custom_css_file();
        } else {
            self::create_custom_css_file($styles);
        }

        self::set_custom_css_last_updated_time();
    }

    /**
     * Get the time when the custom CSS was last updated.
     *
     * @return string|int|null
     */
    protected static function get_custom_css_last_updated_time() {
        return get_option(self::CSS_LAST_UPDATED_OPTION_KEY, null);
    }

    /**
     * Set the time when the custom CSS was last updated.
     * Defaults to the current time if none given.
     */
    protected static function set_custom_css_last_updated_time(?int $time = null): void {
        if (null === $time) {
            $time = time();
        }

        update_option(self::CSS_LAST_UPDATED_OPTION_KEY, $time);
    }

    /**
     * Get the custom CSS storage directory path.
     */
    protected static function get_custom_css_storage_directory(): string {
        $path = WP_CONTENT_DIR . '/custom-css';

        return apply_filters('bm_wpexp_custom_css_storage_directory_path', $path);
    }

    /**
     * Get the custom CSS storage directory URL.
     */
    protected static function get_custom_css_storage_directory_uri(): string {
        $path = content_url( 'custom-css' );

        return apply_filters('bm_wpexp_custom_css_storage_directory_uri', $path);
    }

    /**
     * Create the storage directory if it doesn't exist.
     */
    protected static function maybe_create_custom_css_storage_directory(): void {
        if (! file_exists(self::get_custom_css_storage_directory())) {
            mkdir(self::get_custom_css_storage_directory(), 0755, true);
        }
    }

    /**
     * Get the custom CSS file name.
     */
    protected static function get_custom_css_file_name(): string {
        $base = apply_filters('bm_wpexp_custom_css_file_name', self::$custom_css_file_name);

        if (is_multisite()) {
            return $base . '-' . get_current_blog_id() . '.css';
        }

        return $base . '.css';
    }

    /**
     * Get the path to the custom CSS file.
     */
    public static function get_custom_css_file_path(): string {
        return self::get_custom_css_storage_directory() . '/' . self::get_custom_css_file_name();
    }

    /**
     * Get the custom CSS file URL.
     */
    public static function get_custom_css_file_url(): string {
        return self::get_custom_css_storage_directory_uri() . '/' . self::get_custom_css_file_name();
    }

    /**
     * Create the the custom CSS file.
     */
    protected static function create_custom_css_file(string $contents): void {
        file_put_contents(self::get_custom_css_file_path(), $contents);
    }

    /**
     * Remove the custom CSS file if it exists.
     */
    protected static function remove_custom_css_file(): void {
        $file_path = self::get_custom_css_file_path();

        if (file_exists($file_path)) {
            unlink($file_path);
        }
    }
}
