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

class Admin_Mail_Tab extends Multisite_Tab
{

    protected static string $nonce = 'bm-mail-nonce';

    protected static string $slug = 'bm-mail';

    protected static function get_title(): string
    {
        return __('Mail', 'bm-wp-experience');
    }

    public static function notice(): void
    {
        if (!isset($_GET['updated'], $_GET['page']) || self::$slug !== $_GET['page']) {
            return;
        }

        ?>
        <div class="notice is-dismissible updated">
            <p><?php esc_html_e('The mail settings has been updated', 'bm-wp-experience'); ?></p>
        </div>
        <?php
    }

    public static function save($site, $request_data): void
    {

        if (isset($request_data['from_name'])) {
            update_blog_option($site->id, 'bm_wp_notifications_from_name', $request_data['from_name']);
        }

        if (isset($request_data['from_email_address'])) {
            update_blog_option($site->id, 'bm_wp_notifications_from_email_address', $request_data['from_email_address']);
        }
    }

    public static function render(): void
    {

        $site = self::get_site_from_request();

        if (!$site) {
            return;
        }

        $from_email = get_blog_option($site->id, 'bm_wp_notifications_from_email_address');
        $from_name = get_blog_option($site->id, 'bm_wp_notifications_from_name');


        $placeholder_email = '';
        $placeholder_name = get_blog_option($site->id, 'blogname');

        if( defined( 'BM_WP_NOTIFICATIONS_FROM_EMAIL_ADDRESS' ) ){
            $placeholder_email = BM_WP_NOTIFICATIONS_FROM_EMAIL_ADDRESS;
        }

        if( defined( 'BM_WP_NOTIFICATIONS_FROM_NAME' ) ){
            $placeholder_name = BM_WP_NOTIFICATIONS_FROM_NAME;
        }

        ?>
        <div class="wrap">
            <h1 id="edit-site"><?php printf(__('E-mail settings for: %s', 'bm-wp-experience'),
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
                    <tr>
                        <th scope="row">
                            <label for="from_name">
                                <?php esc_html_e('Name email is sent from', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" class="regular-text"
                                   name="from_name" placeholder="<?php echo esc_attr( $placeholder_name ); ?>" value="<?php echo esc_attr($from_name); ?>">
                            <p class="description"><?php esc_html_e('This name will override the sender name, usually the site name, for notifications e.g. password reset, but also for emails sent with Gravity Forms and WooCommerce. If no name is added, a default will be used from the config shown as a placeholder here. If there\'s no settings in the config, the system settings will be used.', 'bm-wp-experience'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="from_email_address">
                                <?php esc_html_e('E-mail address', 'bm-wp-experience'); ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" class="regular-text"
                                   name="from_email_address" placeholder="<?php echo esc_attr( $placeholder_email ); ?>" value="<?php echo esc_attr($from_email); ?>">
                            <p class="description"><?php esc_html_e('This email address will override the system email address for notifications e.g. password reset, but also addresses added to the settings for example Gravity Forms and WooCommerce. If no address is added, a default will be used from the config shown as a placeholder here. If there\'s no settings in the config, the system settings will be used.', 'bm-wp-experience'); ?></p>
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
