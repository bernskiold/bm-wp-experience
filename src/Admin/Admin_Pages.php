<?php
/**
 * Add Admin Pages
 *
 **/

namespace BernskioldMedia\WP\Experience\Admin;

use BernskioldMedia\WP\Experience\Modules\Users;
use BernskioldMedia\WP\Experience\Plugin;
use BMWPEXP_Vendor\BernskioldMedia\WP\PluginBase\Interfaces\Hookable;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Admin_Pages implements Hookable {

	public static function hooks(): void {
		add_action( 'admin_menu', [ self::class, 'register_pages' ] );
		add_action( 'admin_menu', [ self::class, 'add_reusable_blocks' ] );
		add_action( 'admin_menu', [ self::class, 'remove_import_export' ] );
	}

	/**
	 * Add reusable blocks to pages menu.
	 * Will be removed in future versions when WP core
	 * adds its own blocks section.
	 *
	 * @since 1.0.1
	 */
	public static function add_reusable_blocks(): void {
		add_submenu_page( 'edit.php?post_type=page', __( 'Reusable Blocks', 'bm-wp-experience' ), __( 'Reusable Blocks', 'bm-wp-experience' ), 'edit_pages', 'edit.php?post_type=wp_block' );
	}

	/**
	 * Register Pages
	 */
	public static function register_pages(): void {
		/*
		 * Add support page.
		 */
		if ( true === apply_filters( 'bm_wpexp_show_admin_page_support', true ) ) {
			add_menu_page( esc_html__( 'Help & Support', 'bm-wp-experience' ), esc_html__( 'Help & Support', 'bm-wp-experience' ), 'edit_posts', apply_filters( 'bm_wpexp_support_admin_page_slug', 'bm-support' ), [
				self::class,
				'view_support',
			], 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MTIgNTEyIj48cGF0aCBmaWxsPSIjZmZmIiBkPSJNMjU2IDhDMTE5LjAzMyA4IDggMTE5LjAzMyA4IDI1NnMxMTEuMDMzIDI0OCAyNDggMjQ4IDI0OC0xMTEuMDMzIDI0OC0yNDhTMzkyLjk2NyA4IDI1NiA4em0xNjguNzY2IDExMy4xNzZsLTYyLjg4NSA2Mi44ODVhMTI4LjcxMSAxMjguNzExIDAgMCAwLTMzLjk0MS0zMy45NDFsNjIuODg1LTYyLjg4NWEyMTcuMzIzIDIxNy4zMjMgMCAwIDEgMzMuOTQxIDMzLjk0MXpNMjU2IDM1MmMtNTIuOTM1IDAtOTYtNDMuMDY1LTk2LTk2czQzLjA2NS05NiA5Ni05NiA5NiA0My4wNjUgOTYgOTYtNDMuMDY1IDk2LTk2IDk2ek0zNjMuOTUyIDY4Ljg1M2wtNjYuMTQgNjYuMTRjLTI2Ljk5LTkuMzI1LTU2LjYxOC05LjMzLTgzLjYyNCAwbC02Ni4xMzktNjYuMTRjNjYuNzE2LTM4LjUyNCAxNDkuMjMtMzguNDk5IDIxNS45MDMgMHpNMTIxLjE3NiA4Ny4yMzRsNjIuODg1IDYyLjg4NWExMjguNzExIDEyOC43MTEgMCAwIDAtMzMuOTQxIDMzLjk0MWwtNjIuODg1LTYyLjg4NWEyMTcuMzIzIDIxNy4zMjMgMCAwIDEgMzMuOTQxLTMzLjk0MXptLTUyLjMyMyA2MC44MTRsNjYuMTM5IDY2LjE0Yy05LjMyNSAyNi45OS05LjMzIDU2LjYxOCAwIDgzLjYyNGwtNjYuMTM5IDY2LjE0Yy0zOC41MjMtNjYuNzE1LTM4LjUtMTQ5LjIyOSAwLTIxNS45MDR6bTE4LjM4MSAyNDIuNzc2bDYyLjg4NS02Mi44ODVhMTI4LjcxMSAxMjguNzExIDAgMCAwIDMzLjk0MSAzMy45NDFsLTYyLjg4NSA2Mi44ODVhMjE3LjM2NiAyMTcuMzY2IDAgMCAxLTMzLjk0MS0zMy45NDF6bTYwLjgxNCA1Mi4zMjNsNjYuMTM5LTY2LjE0YzI2Ljk5IDkuMzI1IDU2LjYxOCA5LjMzIDgzLjYyNCAwbDY2LjE0IDY2LjE0Yy02Ni43MTYgMzguNTI0LTE0OS4yMyAzOC40OTktMjE1LjkwMyAwem0yNDIuNzc2LTE4LjM4MWwtNjIuODg1LTYyLjg4NWExMjguNzExIDEyOC43MTEgMCAwIDAgMzMuOTQxLTMzLjk0MWw2Mi44ODUgNjIuODg1YTIxNy4zMjMgMjE3LjMyMyAwIDAgMS0zMy45NDEgMzMuOTQxem01Mi4zMjMtNjAuODE0bC02Ni4xNC02Ni4xNGM5LjMyNS0yNi45OSA5LjMzLTU2LjYxOCAwLTgzLjYyNGw2Ni4xNC02Ni4xNGMzOC41MjMgNjYuNzE1IDM4LjUgMTQ5LjIyOSAwIDIxNS45MDR6Ij48L3BhdGg+PC9zdmc+', 3 );
		}

		/*
		 * Add About Bernskiold page.
		 */
		if ( true === apply_filters( 'bm_wpexp_show_admin_page_about', true ) ) {
			add_submenu_page( '', esc_html__( 'About Bernskiold', 'bm-wp-experience' ), esc_html__( 'About Bernskiold', 'bm-wp-experience' ), 'edit_posts', 'bm-about', [
				self::class,
				'view_about_bm',
			] );
		}

		/*
		 * Add About Company Cloud Dashboard page.
		 */
		if ( defined( 'BM_WP_WEBSITE_UUID' ) && true === apply_filters( 'bm_wpexp_show_admin_page_cc_dashboard', true ) ) {
			add_menu_page( esc_html__( 'Company Cloud Dashboard', 'bm-wp-experience' ), esc_html__( 'My Website', 'bm-wp-experience' ), 'edit_posts', 'company-cloud', [
				self::class,
				'view_cc_dashboard',
			], 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MTIgNTEyIj48cGF0aCBmaWxsPSIjZmZmIiBkPSJNMzM5LjEgMjE2LjFDMzI4LjYgMjI2LjEgMzEyLjUgMjI2LjQgMzAwLjggMjE3LjZMMTkyLjYgMTM2LjVMNTEuOTkgMjQ4LjFDMzguMTkgMjYwIDE4LjA1IDI1Ny44IDcuMDEzIDI0My4xQy00LjAyOCAyMzAuMi0xLjc5IDIxMC4xIDEyLjAxIDE5OUwxNzIgNzEuMDFDMTgzLjQgNjEuOSAxOTkuNSA2MS42NSAyMTEuMiA3MC40TDMxOS40IDE1MS41TDQ2MCAzOS4wMUM0NzMuOCAyNy45NyA0OTMuOSAzMC4yMSA1MDQuMSA0NC4wMUM1MTYgNTcuODEgNTEzLjggNzcuOTUgNDk5LjEgODguOTlMMzM5LjEgMjE2LjF6TTE2MCAyNTZDMTYwIDIzOC4zIDE3NC4zIDIyNCAxOTIgMjI0QzIwOS43IDIyNCAyMjQgMjM4LjMgMjI0IDI1NlY0NDhDMjI0IDQ2NS43IDIwOS43IDQ4MCAxOTIgNDgwQzE3NC4zIDQ4MCAxNjAgNDY1LjcgMTYwIDQ0OFYyNTZ6TTMyIDM1MkMzMiAzMzQuMyA0Ni4zMyAzMjAgNjQgMzIwQzgxLjY3IDMyMCA5NiAzMzQuMyA5NiAzNTJWNDQ4Qzk2IDQ2NS43IDgxLjY3IDQ4MCA2NCA0ODBDNDYuMzMgNDgwIDMyIDQ2NS43IDMyIDQ0OFYzNTJ6TTM1MiAzMjBWNDQ4QzM1MiA0NjUuNyAzMzcuNyA0ODAgMzIwIDQ4MEMzMDIuMyA0ODAgMjg4IDQ2NS43IDI4OCA0NDhWMzIwQzI4OCAzMDIuMyAzMDIuMyAyODggMzIwIDI4OEMzMzcuNyAyODggMzUyIDMwMi4zIDM1MiAzMjB6TTQxNiAyNTZDNDE2IDIzOC4zIDQzMC4zIDIyNCA0NDggMjI0QzQ2NS43IDIyNCA0ODAgMjM4LjMgNDgwIDI1NlY0NDhDNDgwIDQ2NS43IDQ2NS43IDQ4MCA0NDggNDgwQzQzMC4zIDQ4MCA0MTYgNDY1LjcgNDE2IDQ0OFYyNTZ6Ii8+PC9zdmc+', 2 );
		}
	}

	/**
	 * Load the Support page view.
	 */
	public static function view_support(): void {
		$filtered_support_content = apply_filters( 'bm_wpexp_admin_page_support_content', null );

		if ( null !== $filtered_support_content ) {
			echo $filtered_support_content; // @codingStandardsIgnoreLine
		} else {
			include Plugin::get_view_path( 'admin/support' );
		}
	}

	/**
	 * Load the About BM page view.
	 */
	public static function view_about_bm(): void {
		include Plugin::get_view_path( 'admin/about-bm' );
	}

	/**
	 * Load the Company Cloud Dashboard page view.
	 */
	public static function view_cc_dashboard(): void {
		include Plugin::get_view_path( 'admin/cc-dashboard' );
	}

	public static function remove_import_export(): void {
		if ( defined( 'BM_WP_ENABLE_IMPORT_EXPORT' ) && BM_WP_ENABLE_IMPORT_EXPORT ) {
			return;
		}

        if( Users::is_agency(wp_get_current_user()) ) {
            return;
        }

		remove_submenu_page( 'tools.php', 'export.php' );
		remove_submenu_page( 'tools.php', 'import.php' );
	}
}
