<?php
/**
 * Handles the loading of scripts and styles for the
 * theme through the proper enqueuing methods.
 *
 **/

namespace BernskioldMedia\WP\Experience\Admin;

use BernskioldMedia\WP\Experience\Integrations\Matomo_Api;
use BernskioldMedia\WP\Experience\Modules\Matomo_Sync;
use BMWPEXP_Vendor\BernskioldMedia\WP\PluginBase\Admin\Multisite_Tab;

if (!defined('ABSPATH')) {
    exit;
}

class Admin_Analytics_Tab extends Multisite_Tab
{

    protected static string $nonce = 'bm-analytics-nonce';

    protected static string $slug = 'bm-analytics';

    protected static function get_title(): string
    {
        return __('BM Analytics', 'bm-wp-experience');
    }

    public static function notice(): void
    {
        if (!isset($_GET['updated'], $_GET['page']) || self::$slug !== $_GET['page']) {
            return;
        }

        ?>
        <div class="notice is-dismissible updated">
            <p><?php esc_html_e('The analytics settings has been updated', 'bm-wp-experience'); ?></p>
        </div>
        <?php
    }

    public static function save($site, $request_data): void
    {

        if (isset($request_data['matomo_ID']) && !isset($request_data['automatic_connection'])) {
            update_blog_option($site->id, 'bm_wp_matomo_site_id', $request_data['matomo_ID']);
        }

        if (isset($request_data['automatic_connection'])) {
            update_blog_option($site->id, Matomo_Sync::$automatic_connection_option,
                $request_data['automatic_connection'] ?? 0);
            $matomo_id = Matomo_Sync::maybe_create_site_and_get_matomo_id($site);
            Matomo_sync::add_users_to_matomo($site, $matomo_id);
        }
        else{
            update_blog_option($site->id, Matomo_Sync::$automatic_connection_option,
                0);
        }

        if (isset($request_data['instance_url'])) {
            update_blog_option($site->id, 'bm_wp_matomo_url', $request_data['instance_url']);
        }

        if (isset($request_data['require_cookies'])) {
            update_blog_option($site->id, 'bm_wp_matomo_require_cookie_consent', $request_data['require_cookies']);
        } else {
            update_blog_option($site->id, 'bm_wp_matomo_require_cookie_consent', false);
        }

        if (isset($request_data['enable_user_id'])) {
            update_blog_option($site->id, 'bm_wp_matomo_enable_user_id', $request_data['enable_user_id']);
        } else {
            update_blog_option($site->id, 'bm_wp_matomo_enable_user_id', false);
        }

        if (isset($request_data['enable_subdomains'])) {
            update_blog_option($site->id, 'bm_wp_matomo_enable_subdomains', $request_data['enable_subdomains']);
        } else {
            update_blog_option($site->id, 'bm_wp_matomo_enable_subdomains', false);
        }

        if (isset($request_data['subdomains_domain'])) {
            update_blog_option($site->id, 'bm_wp_matomo_subdomains_domain', $request_data['subdomains_domain']);
        }

    }

    public static function render(): void
    {

        $site = self::get_site_from_request();

        if (!$site) {
            return;
        }

        $matomo_id = get_blog_option($site->id, 'bm_wp_matomo_site_id');
        $instance_url = get_blog_option($site->id, 'bm_wp_matomo_url');
        $require_cookies = get_blog_option($site->id, 'bm_wp_matomo_require_cookie_consent');
        $enable_user_id = get_blog_option($site->id, 'bm_wp_matomo_enable_user_id');
        $enable_subdomains = get_blog_option($site->id, 'bm_wp_matomo_enable_subdomains');
        $domain = get_blog_option($site->id, 'bm_wp_matomo_subdomains_domain');

        $is_connection_enabled_for_site = Matomo_Sync::is_enabled_for_site($site->id);

        ?>
        <div class="wrap">
            <h1 id="edit-site"><?php printf(__('Analytics Settings for: %s', 'bm-wp-experience'),
                    $site->blogname); ?></h1>
            <p class="edit-site-actions">
                <a href="<?php esc_url(get_home_url($site->id, '/')); ?>"><?php esc_html_e('Visit',
                        'bm-wp-experience'); ?></a> | <a href="<?php esc_url(get_admin_url($site->id,
                    '/')); ?>"><?php esc_html_e('Dashboard', 'bm-wp-experience'); ?></a>
            </p>

            <?php
            network_edit_site_nav([
                'blog_id' => $site->id,
                'selected' => self::$slug, // current tab
            ]);
            ?>

            <form method="post" action="edit.php?action=<?php echo esc_attr(self::$slug); ?>">
                <table class="form-table">

                    <?php if (Matomo_Sync::is_module_enabled()): ?>
                        <tr>
                            <th scope="row">
                                <label for="automatic_connection">
                                    <?php esc_html_e('Automatic connection with Matomo', 'bm-wp-experience'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="checkbox" id="automatic_connection"
                                       name="automatic_connection" <?php if ($is_connection_enabled_for_site) {
                                    echo 'checked';
                                } ?>> <?php esc_html_e('Yes, enable automatic connection with Matomo',
                                    'bm-wp-experience'); ?>
                                <p class="description"><?php esc_html_e('A Matomo ID will be created. Administrators of the site will automatically get access to Matomo.',
                                        'bm-wp-experience'); ?></p>

                            </td>
                        </tr>
                    <?php endif; ?>
                    <tr>
                        <th scope="row">
                            <label for="matomo_ID">
                                <?php esc_html_e('Matomo ID', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" class="regular-text"
                                   name="matomo_ID" <?php if ($is_connection_enabled_for_site) {
                                echo esc_attr('disabled');
                            } ?> value="<?php echo esc_attr($matomo_id); ?>">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="instance_url">
                                <?php esc_html_e('Instance URL', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" class="regular-text"
                                   name="instance_url" <?php if ($is_connection_enabled_for_site) {
                                echo esc_attr('disabled');
                            } ?> value="<?php echo esc_attr($instance_url); ?>"
                                   placeholder="<?php echo esc_attr(Matomo_Api::get_api_url()); ?>">
                            <?php if (defined('BM_WP_MATOMO_INSTANCE') && BM_WP_MATOMO_INSTANCE != '' && !$is_connection_enabled_for_site): ?>
                                <p class="description"><?php esc_html_e(sprintf('You have defined an instance URL in the config: %s. To override this, enter a url in the field.',
                                        BM_WP_MATOMO_INSTANCE), 'bm-wp-experience'); ?></p>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="require_cookies">
                                <?php esc_html_e('Cookie Consent', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="checkbox" id="require_cookies"
                                   name="require_cookies" <?php if ($require_cookies) {
                                echo 'checked';
                            } ?>> <?php esc_html_e('Yes, enable automatic cookie consent integration',
                                'bm-wp-experience'); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="enable_user_id">
                                <?php esc_html_e('User ID', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="checkbox" id="enable_user_id"
                                   name="enable_user_id" <?php if ($enable_user_id) {
                                echo 'checked';
                            } ?>> <?php esc_html_e('Yes, send user id to analytics', 'bm-wp-experience'); ?>
                            <p class="description"><?php esc_html_e('Please note that passing user id to analytics requires informed and specific user consent under GDPR.',
                                    'bm-wp-experience'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="enable_subdomains">
                                <?php esc_html_e('Track Subdomains', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="checkbox" id="enable_subdomains"
                                   name="enable_subdomains" <?php if ($enable_subdomains) {
                                echo 'checked';
                            } ?>> <?php esc_html_e('Yes, enable tracking of subdomains', 'bm-wp-experience'); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="subdomains_domain">
                                <?php esc_html_e('Domain', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" class="regular-text" name="subdomains_domain"
                                   value="<?php echo esc_attr($domain); ?>">
                            <p class="description"><?php esc_html_e('If you have enables subdomains above you need to enter your website domain here, for example: example.com',
                                    'bm-wp-experience'); ?></p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(__('Save', 'bm-wp-experience')); ?>

                <?php wp_nonce_field(self::$nonce.'-'.$site->id); ?>
                <input type="hidden" name="id" value="<?php echo esc_attr($site->id); ?>">

            </form>

        </div>
        <?php
    }
}
