<?php

namespace BernskioldMedia\WP\Experience\Modules;

use BernskioldMedia\WP\Experience\Integrations\Matomo_Api;

class Matomo extends Module
{

    public static function hooks(): void
    {

        // Allow disabling of module.
        if (true !== apply_filters('bm_wpexp_matomo_enabled', true)) {
            return;
        }

        add_filter('wpmu_blogs_columns', [self::class, 'add_matomo_column']);
        add_action('manage_sites_custom_column', [self::class, 'add_matomo_link_to_site_in_sites_list'], 10, 2);

        if (wp_get_environment_type() !== 'production' && false === apply_filters('bm_wpexp_matomo_load_outside_production',
                false)) {
            return;
        }

        // Don't enable if no site ID is set.
        if (empty(self::get_site_id())) {
            return;
        }



        add_action('wp_head', [self::class, 'analytics_code'], 9999); // Hook far down.

    }

    protected static function get_site_id(): string
    {
        $global = defined('BM_WP_MATOMO_SITE_ID') ? BM_WP_MATOMO_SITE_ID : '';

        if (is_multisite()) {
            return get_option('bm_wp_matomo_site_id', '');
        }

        return $global;
    }

    protected static function get_instance_url(): string
    {
        $default_url = 'https://analytics.bmedia.io/';
        $value = $default_url;
        if (is_multisite()) {
            $is_connection_enabled_for_site = Matomo_Sync::is_enabled_for_site( get_current_blog_id() );
            if( $is_connection_enabled_for_site ){
                $value = defined('BM_WP_MATOMO_INSTANCE_URL') ? BM_WP_MATOMO_INSTANCE_URL : $default_url;
            }
            else{
                $value =  get_option('bm_wp_matomo_url', $default_url);
                if( $value === ''){
                    $value = $default_url;
                }
            }

        }

        return trailingslashit(apply_filters('bm_wpexp_matomo_url', $value ));
    }

    protected static function get_enable_cookie_consent(): bool
    {
        $value = false;

        if (is_multisite()) {
            $value = get_option('bm_wp_matomo_require_cookie_consent', $value);
        }

        return apply_filters('bm_wpexp_matomo_require_cookie_consent', $value);
    }

    protected static function get_enable_user_id(): bool
    {
        $value = false;

        if (is_multisite()) {
            $value = get_option('bm_wp_matomo_enable_user_id', $value);
        }

        return apply_filters('bm_wpexp_matomo_enable_user_id', $value);
    }

    protected static function get_enable_subdomains(): bool
    {
        $value = false;

        if (is_multisite()) {
            $value = get_option('bm_wp_matomo_enable_subdomains', $value);
        }

        return apply_filters('bm_wpexp_matomo_enable_subdomains', $value);
    }

    protected static function get_subdomains_domain(): bool
    {
        $value = false;
        if (is_multisite()) {
            $value = get_option('bm_wp_matomo_subdomains_domain', $value);
        }

        return apply_filters('bm_wpexp_matomo_subdomains_domain', $value);
    }

    public static function analytics_code(): void
    {
        global $wp_query;

        $site_id = self::get_site_id();
        $enable_cookie_consent = self::get_enable_cookie_consent();
        $enable_user_id = self::get_enable_user_id();
        $enable_subdomains = self::get_enable_subdomains();
        $domain = self::get_subdomains_domain();
        $matomo_url = self::get_instance_url();

        ?>
        <script>
            var _paq = window._paq = window._paq || [];
            <?php if($enable_cookie_consent) : ?>
            _paq.push(["requireCookieConsent"]);
            <?php endif; ?>
            <?php do_action('bm_wpexp_matomo_configuration_before_pageview'); ?>
            <?php if($enable_user_id && is_user_logged_in()) : ?>
            _paq.push(["setUserId", '<?php echo esc_js(get_current_user_id()); ?>']);
            <?php endif; ?>
            <?php if(is_search()) : ?>
            _paq.push([
                "trackSiteSearch",
                "<?php echo esc_js(get_search_query()); ?>",
                false,
                <?php echo esc_js($wp_query->found_posts); ?>
            ]);
            <?php else : ?>
            _paq.push(["trackPageView"]);
            <?php endif; ?>
            _paq.push(["enableLinkTracking"]);
            (function () {
                var u = "<?php echo esc_js($matomo_url); ?>";
                _paq.push(["setTrackerUrl", u + "matomo.php"]);
                _paq.push(["setSiteId", "<?php echo esc_js($site_id); ?>"]);
                <?php if($enable_subdomains && !empty($domain)) : ?>
                _paq.push(["setCookieDomain", "*.<?php echo esc_js($domain); ?>"]);
                _paq.push(["setDomains", "*.<?php echo esc_js($domain); ?>"]);
                <?php endif; ?>
                var d = document, g = d.createElement("script"), s = d.getElementsByTagName("script")[0];
                g.async = true;
                g.src = u + "matomo.js";
                s.parentNode.insertBefore(g, s);
            })();
        </script>
        <?php
    }

    public static function analytics_noscript(): void
    {
        ?>
        <noscript>
            <p>
                <img src="<?php echo esc_attr(self::get_instance_url()); ?>/matomo.php?idsite=<?php echo esc_attr(self::get_site_id()); ?>&rec=1"
                     style="border:0;" alt=""/>
            </p>
        </noscript>
        <?php
    }

    public static function add_matomo_column($sites_columns){
        $sites_columns['bm_wp_matomo'] = __('Matomo Site ID','bm-wp-experience');

        return $sites_columns;
    }

    public static function add_matomo_link_to_site_in_sites_list($column_name, $blog_id)
    {
        if( 'bm_wp_matomo' !== $column_name ) {
            return;
        }

        $matomo_id = Matomo_Sync::get_matomo_id_for_current_or_given_blog($blog_id);

        if(empty($matomo_id)){
            return;
        }

        echo '<a href="'.Matomo_Api::get_api_url().'/index.php?module=CoreHome&action=index&idSite='.$matomo_id.'" target="_blank">'. $matomo_id .'</a>';
    }

}
