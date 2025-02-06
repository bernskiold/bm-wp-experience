<?php

namespace BernskioldMedia\WP\Experience\Modules;

use BernskioldMedia\WP\Experience\Integrations\Matomo_Api;
use WP_Site;
use WP_User;

class Matomo_Sync extends Module
{
    protected static string $matomo_id_option = 'bm_wp_matomo_site_id';
    public static string $automatic_connection_option = 'bm_wp_matomo_automatic_connection';

    public static function hooks(): void
    {
        if (!self::is_module_enabled()) {
            return;
        }

        if (!Matomo_Api::has_api_key()) {
            return;
        }

        add_action('network_site_new_form', [self::class, 'add_field_to_register_site_form']);
        add_action('wp_initialize_site', [self::class, 'save_site_register_fields']);

        add_action('personal_options_update', [self::class, 'maybe_update_matomo_user']);
        add_action('edit_user_profile_update', [self::class, 'maybe_update_matomo_user']);

        add_action('add_user_to_blog', [self::class, 'maybe_add_user_to_matomo_site'], 10, 2);
        add_action('remove_user_from_blog', [self::class, 'maybe_remove_user_from_matomo_site'], 10, 1);
        add_action('delete_user', [self::class, 'maybe_delete_user_from_matomo'], 10, 3);

    }

    public static function add_field_to_register_site_form(): void
    {
        ?>
        <h3><?php esc_html_e('Matomo', 'bm-wp-experience'); ?></h3>
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="automatic_connection">
                        <?php esc_html_e('Automatic connection with Matomo', 'bm-wp-experience'); ?>
                    </label>
                </th>
                <td>
                    <input type="checkbox" id="automatic_connection"
                           name="blog[automatic_connection]"> <?php esc_html_e('Yes, enable automatic connection with Matomo',
                        'bm-wp-experience'); ?>
                    <p class="description"><?php esc_html_e('A Matomo ID will be created. Administrators of the site will automatically get access to Matomo.',
                            'bm-wp-experience'); ?></p>
                </td>
            </tr>
        </table>
        <?php
    }

    public static function save_site_register_fields(WP_Site $site): void
    {

        if (self::is_enabled_for_site($site->id)) {
            return;
        }

        if (isset($_POST['blog']['automatic_connection'])) {
            update_blog_option($site->id, self::$automatic_connection_option, 1);

            $matomo_id = self::maybe_create_site_and_get_matomo_id($site);
            if( !$matomo_id ){
                return;
            }
            self::add_users_to_matomo($site, $matomo_id);

        } else {
            update_blog_option($site->id, self::$automatic_connection_option, 0);
        }

    }

    public static function maybe_create_site_and_get_matomo_id($site){

        if( get_blog_option($site->id, self::$matomo_id_option, false) && get_blog_option($site->id, self::$matomo_id_option, false) !== ''){
            return get_blog_option($site->id, self::$matomo_id_option, true);
        }

        $matomo_id = Matomo_Api::create_site(get_blog_details(['blog_id' => $site->id])->blogname,
            $site->domain);

        if(!$matomo_id){
            return;
        }

        update_blog_option($site->id, self::$matomo_id_option, $matomo_id);

        return $matomo_id;
    }

    public static function add_users_to_matomo($site, $matomo_id){
        $users_to_add = get_users([
            'blog_id' => $site->id,
        ]);

        foreach ($users_to_add as $user) {
            Matomo_Api::add_user_to_site($matomo_id, $user->user_login, $user->user_email, self::get_matomo_role_from_wordpress_role($user->roles[0]));
        }
    }

    public static function maybe_update_matomo_user(int $user_id): void
    {

        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'update-user_'.$user_id)) {
            return;
        }

        if (!current_user_can('edit_user', $user_id)) {
            return;
        }

        if (!isset($_POST['role'])) {
            return;
        }

        if (!self::is_enabled_for_site()) {
            return;
        }

        $user = get_user_by('id', $user_id);

        if (!$user) {
            return;
        }

        if (in_array($_POST['role'], $user->roles)) {
            return;
        }

        $matomo_role = self::get_matomo_role_from_wordpress_role($_POST['role']);

        $matomo_id = self::get_matomo_id_for_current_or_given_blog();

        if (!$matomo_id) {
            return;
        }

        Matomo_Api::add_user_to_site($matomo_id, $user->user_login, $user->user_email,
            $matomo_role);

    }

    public static function maybe_add_user_to_matomo_site(int $user_id, string $role): void
    {
        if (!self::is_enabled_for_site()) {
            return;
        }

        $user = get_user_by('id', $user_id);

        if (!$user) {
            return;
        }

        $matomo_id = self::get_matomo_id_for_current_or_given_blog();

        if (!$matomo_id) {
            return;
        }

        $matomo_role = self::get_matomo_role_from_wordpress_role($role);

        if ($matomo_role !== Matomo_Api::ROLE_NO_ACCESS) {
            Matomo_Api::add_user_to_site($matomo_id, $user->user_login, $user->user_email, $matomo_role);
        }

    }

    public static function maybe_remove_user_from_matomo_site(int $user_id): void
    {
        if (!self::is_enabled_for_site()) {
            return;
        }

        $user = get_user_by('id', $user_id);

        if (!$user) {
            return;
        }

        $matomo_id = self::get_matomo_id_for_current_or_given_blog();

        if (!$matomo_id) {
            return;
        }

        if (!Matomo_Api::check_if_user_exists($user->user_email)) {
            return;
        }

        Matomo_Api::add_existing_user_to_site($matomo_id, $user->user_email, Matomo_Api::ROLE_NO_ACCESS);
    }

    public static function maybe_delete_user_from_matomo(int $user_id, $reassign, WP_User $user): void
    {
        if (!Matomo_Api::check_if_user_exists($user->user_email)) {
            return;
        }

        Matomo_Api::delete_user_from_matomo($user->user_email);
    }

    public static function get_matomo_role_from_wordpress_role(string $role): string
    {
        $role_map = self::get_wordpress_matomo_role_map();

        return $role_map[$role] ?? Matomo_Api::ROLE_NO_ACCESS;
    }

    public static function get_wordpress_matomo_role_map(): array
    {
        // Supported values can be found as constants on the Matomo_API class.
        return apply_filters('bm_wp_matomo_role_map', [
            'administrator' => Matomo_Api::ROLE_ADMIN,
            'editor' => Matomo_Api::ROLE_VIEW,
            'author' => Matomo_Api::ROLE_NO_ACCESS,
            'contributor' => Matomo_Api::ROLE_NO_ACCESS,
            'subscriber' => Matomo_Api::ROLE_NO_ACCESS,
        ]);
    }

    public static function get_matomo_id_for_current_or_given_blog($site_id = null): ?int
    {
        if( $site_id !== null ){
            return get_blog_option($site_id, self::$matomo_id_option, null);
        }

        $current_blog = get_current_blog_id();

        if (!$current_blog) {
            return null;
        }

        return get_blog_option($current_blog, self::$matomo_id_option, null);
    }

    public static function is_enabled_for_site(?int $site_id = null): bool
    {
        if (!self::is_module_enabled()) {
            return false;
        }

        if (!$site_id) {
            $site_id = get_current_blog_id();
        }

        return get_blog_option($site_id, self::$automatic_connection_option, false);
    }

    public static function is_module_enabled(): bool
    {
        if (defined('BM_WP_MATOMO_AUTOMATIC_CONNECTION') && BM_WP_MATOMO_AUTOMATIC_CONNECTION === true) {
            return true;
        }

        return false;
    }
}