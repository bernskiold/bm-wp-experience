<?php

namespace BernskioldMedia\WP\Experience\Modules\Sso;

use BernskioldMedia\WP\Experience\Modules\Module;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;
use function apply_filters;
use function array_key_exists;
use function do_action;
use function get_rest_url;
use function is_wp_error;
use function username_exists;
use function wp_login_url;
use function wp_safe_redirect;
use function wp_set_auth_cookie;
use function wp_set_current_user;

class Okta extends Module
{
    public static function hooks(): void
    {
        if(!defined('OKTA_ENABLED') || !OKTA_ENABLED) {
            return;
        }

        try {
            self::validate_configuration();
        } catch (\Exception $e) {
            add_action('admin_notices', function() use ($e) {
                echo '<div class="notice notice-error"><p>' . esc_html($e->getMessage()) . '</p></div>';
            });
            return;
        }

        add_action('rest_api_init', [self::class, 'register_api_routes']);
        add_action('login_form_login', [self::class, 'show_login_button']);
    }

    public static function register_api_routes(): void
    {
        register_rest_route('okta', '/auth', [
            'methods' => 'GET',
            'callback' => [self::class, 'handle_auth'],
        ]);
    }

    public static function handle_auth(WP_REST_Request $request)
    {
        $code = $request->get_param('code');
        $token = self::convert_code_to_token($code);
        $user_details = self::get_user_details_from_access_token($token);
        $user = self::handle_okta_user($user_details);

        self::handle_login($user);
    }

    public static function show_login_button(): void {
        $button_label = apply_filters('bm_wp_okta_login_button_label', __('Login with Okta', 'bm-wp-experience'));
        ?>
        <div class="bmwp-okta-login-button-wrapper">
            <a href="<?php echo esc_url(self::get_login_url()); ?>" class="bmwp-okta-login-button">
                <?php echo esc_html($button_label); ?>
            </a>
        </div>
        <?php
    }

    protected static function get_login_url(): string
    {
        $scopes = array_merge(
            ['openid', 'profile', 'email'],
            defined('OKTA_SCOPES') ? OKTA_SCOPES : []
        );

        return self::build_api_url('authorize', [
            'client_id' => self::get_client_id(),
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => implode(' ', $scopes),
            'redirect_uri' => get_rest_url(null, 'okta/auth'),
            'state' => 'wordpress',
            'nonce' => wp_create_nonce('okta_auth'),
        ]);
    }

    protected static function handle_error(string $errorKey): void
    {
        $loginUrl = wp_login_url();
        $loginUrlWithError = add_query_arg('error', $errorKey, $loginUrl);

        wp_safe_redirect($loginUrlWithError);
        exit;
    }

    protected static function get_error_messages(string $errorKey): string
    {
        return match ($errorKey) {
            default => __('An unexpected error occurred when logging in. Please try again and if it still does not work, please contact us.', 'bm-wp-experience'),
        };
    }

    protected static function convert_code_to_token(string $code): string
    {
        $url = self::build_api_url('token', [
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => get_rest_url(null, 'okta/auth'),
        ]);

        $response = wp_safe_remote_post($url, [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Basic ' . self::get_authorization_secret(),
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Content-Length' => 0,
            ],
            'sslverify' => false,
        ]);

        if (is_wp_error($response)) {
            self::handle_error('bad_code_request');
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        $access_token = $body['access_token'] ?? null;

        if (empty($access_token)) {
            self::handle_error('no_token');
        }

        return $access_token;
    }

    protected static function get_user_details_from_access_token(string $access_token): array
    {
        $url = self::build_api_url('userinfo');

        $response = wp_safe_remote_post($url, [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer ' . $access_token,
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Content-Length' => 0,
            ],
            'sslverify' => false,
        ]);

        if (is_wp_error($response)) {
            self::handle_error('bad_userinfo_request');
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (empty($body)) {
            self::handle_error('no_userinfo');
        }

        return $body;
    }

    protected static function handle_okta_user(array $user_details): WP_User {

        // Allow hooking in to finding a user by Okta ID.
        $user_id = apply_filters('bm_wp_okta_parse_user_id', false, $user_details);

        // If we don't have a user ID, attempt to look one up.
        if($user_id === false) {
            $first_name = $user_details['given_name'] ?? '';
            $last_name = $user_details['family_name'] ?? '';
            $email = $user_details['email'] ?? null;

            $user_id = username_exists($email);
        }

        if(empty($email)) {
            self::handle_error('no_email');
        }

        $default_role = apply_filters('bm_wp_okta_default_role', get_option('default_role', 'subscriber'), $user_details);

        // If we don't have a user ID, create a new user.
        if(!$user_id) {
            $user_data = apply_filters('bm_wp_okta_create_user_data', [
                'user_login' => $email,
                'user_email' => $email,
                'display_name' => $first_name . ' ' . $last_name,
                'first_name' => $first_name,
                'last_name' => $last_name,
                'user_pass' => wp_generate_password(),
                'role' => $default_role,
            ], $user_details);

            $user_id = wp_insert_user($user_data);

            do_action('bm_wp_okta_user_created', $user_id, $user_data, $user_details);

            if(is_wp_error($user_id)) {
                self::handle_error('user_creation_failed');
            }
        }

        $user = get_user_by('id', $user_id);

        if(is_wp_error($user)) {
            self::handle_error('user_not_found');
        }

        // Add user to multisite.
        if(is_multisite()) {
            $blog_id = get_current_blog_id();
            if (!is_user_member_of_blog($user->ID, $blog_id)) {
                add_user_to_blog($blog_id, $user->ID, $default_role);
            }

            do_action('bm_wp_okta_user_added_to_blog', $user->ID, $blog_id, $default_role, $user_details);
        }

        return $user;
    }

    protected static function handle_login(WP_User $user): void {
        wp_set_current_user($user->ID, $user->user_login);
        wp_set_auth_cookie($user->ID, true);
        do_action('bm_wp_okta_user_logging_in', $user->ID, $user);
        do_action('wp_login', $user->user_login, $user);

        wp_safe_redirect(home_url());
        exit;
    }

    protected static function get_base_url(): string
    {
        return apply_filters('bm_wp_okta_base_url', OKTA_ORG_URL . '/oauth2/default/v1');
    }

    protected static function build_api_url(string $endpoint, array $query = []): string
    {
        $baseUrl = self::get_base_url() . '/' . $endpoint;

        if (!empty($query)) {
            $baseUrl .= '?' . http_build_query($query);
        }

        return $baseUrl;
    }

    protected static function get_client_secret(): string
    {
        return OKTA_CLIENT_SECRET;
    }

    protected static function get_client_id(): string
    {
        return OKTA_CLIENT_ID;
    }

    protected static function get_authorization_secret(): string
    {
        return base64_encode(self::get_client_id() . ':' . self::get_client_secret());
    }

    protected static function validate_configuration(): void
    {
        if(!defined('OKTA_ORG_URL') || !defined('OKTA_CLIENT_ID') || !defined('OKTA_CLIENT_SECRET')) {
            throw new \Exception('Okta configuration is missing. Please check your settings.');
        }

        if(empty(OKTA_ORG_URL) || empty(OKTA_CLIENT_ID) || empty(OKTA_CLIENT_SECRET)) {
            throw new \Exception('Okta configuration is invalid. Please check your settings.');
        }
    }
}