<?php

namespace BernskioldMedia\WP\Experience\Integrations;

class Matomo_Api
{

    public const ROLE_ADMIN = 'admin';
    public const ROLE_VIEW = 'view';
    const ROLE_NO_ACCESS = 'noaccess';

    public static function create_site(string $site_name, string $site_url): ?int
    {
        if (!self::has_api_key()) {
            return null;
        }

        $response = self::make_request('?module=API&method=SitesManager.addSite&format=json', [
            'siteName' => $site_name,
            'urls' => $site_url,
        ]);


        if (self::is_request_error($response)) {
            return null;
        }

        return (int) $response->value;
    }

    public static function add_user_to_site(
        $matomo_id,
        string $username,
        string $email,
        $access = 'view'
    ): void {

        if (self::check_if_user_exists($email)) {
            self::add_existing_user_to_site($matomo_id, $email, $access);
        } else {
            self::add_new_user_to_site($matomo_id, $username, $email, $access);
        }
    }

    public static function delete_user_from_matomo(string $email): void
    {
        $matomo_user = self::get_existing_user($email);

        if (!$matomo_user) {
            return;
        }

        if (!isset($matomo_user->login)) {
            return;
        }

        self::make_request('?module=API&method=UsersManager.deleteUser&format=json', [
            'userLogin' => $matomo_user->login,
        ]);
    }

    public static function check_if_user_exists(string $email): bool
    {
        $response = self::make_request('?module=API&method=UsersManager.userEmailExists&format=json', [
            'userEmail' => $email,
        ]);

        if (self::is_request_error($response)) {
            return false;
        }

        return (bool) $response->value;
    }

    public static function get_existing_user(string $email)
    {
        $response = self::make_request('?module=API&method=UsersManager.getUserByEmail&format=json', [
            'userEmail' => $email,
        ]);

        if (self::is_request_error($response)) {
            return null;
        }

        return $response;
    }

    public static function add_existing_user_to_site(
        string $matomo_id,
        string $email,
        string $access = self::ROLE_NO_ACCESS
    ): void {
        $matomo_user = self::get_existing_user($email);

        if (!$matomo_user) {
            return;
        }

        self::make_request('?module=API&method=UsersManager.setUserAccess&format=json', [
            'userLogin' => $matomo_user->login,
            'access' => $access,
            'idSites' => $matomo_id,
        ]);
    }

    public static function add_new_user_to_site(
        string $matomo_id,
        string $username,
        string $email,
        string $access = self::ROLE_NO_ACCESS
    ): void {

        $password = self::password_generator(20);

        $response = self::make_request('?module=API&method=UsersManager.addUser&format=json', [
            'userLogin' => $username,
            'password' => $password,
            'email' => $email,
            'initialIdSite' => $matomo_id,
            'passwordConfirmation' => $password,
        ]);



        if (self::is_request_error($response)) {
            return;
        }

        self::make_request('?module=API&method=UsersManager.setUserAccess&format=json', [
            'userLogin' => $username,
            'access' => $access,
            'idSites' => $matomo_id,
        ]);
    }

    public static function get_api_url(string $endpoint = ''): string
    {
        if (defined('BM_WP_MATOMO_INSTANCE_URL')) {
            $instance = BM_WP_MATOMO_INSTANCE_URL;
        } else {
            $instance = 'https://analytics.bmedia.io/';
        }

        return $instance.$endpoint;
    }

    public static function has_api_key(): bool
    {
        if (defined('BM_WP_MATOMO_API_KEY')) {
            return true;
        }

        return false;
    }

    public static function get_api_key(): string
    {
        return BM_WP_MATOMO_API_KEY;
    }

    public static function make_request(string $endpoint, array $body = [])
    {
        $url = self::get_api_url($endpoint);

        $response = wp_remote_post($url, [
            'body' => array_merge([
                'token_auth' => self::get_api_key(),
            ], $body),
        ]);

        if (!$response || is_wp_error($response)) {
            return json_decode("{'result': 'error', 'message': 'An error occurred with the API connection on the WordPress side.'}");
        }

        return json_decode($response['body'] ?? '');
    }

    public static function is_request_error($response)
    {
        if (isset($response->result) && $response->result == 'error') {
            if (WP_DEBUG) {
                error_log('An error occurred while making a request to Matomo:');
                error_log($response->message);
            }

            return $response->message;
        }

        return false;
    }

    /**
     * Taken from: https://gist.github.com/compermisos/cf11aed742d2e1fbd994e083b4b0fa78
     * Generates a strong password of N length containing at least one lower case letter,
     * one uppercase letter, one digit, and one special character. The remaining characters
     * in the password are chosen at random from those four sets.
     *
     * The available characters in each set are user friendly - there are no ambiguous
     * characters such as i, l, 1, o, 0, etc. This, coupled with the $add_dashes option,
     * makes it much easier for users to manually type or speak their passwords.
     *
     * Note: the $add_dashes option will increase the length of the password by
     * floor(sqrt(N)) characters.
     * **/
    public static function password_generator($length = 15, $available_sets = 'luds')
    {

        $sets = [];
        if (strpos($available_sets, 'l') !== false) {
            $sets[] = 'abcdefghjkmnpqrstuvwxyz';
        }
        if (strpos($available_sets, 'u') !== false) {
            $sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';
        }
        if (strpos($available_sets, 'd') !== false) {
            $sets[] = '23456789';
        }
        if (strpos($available_sets, 's') !== false) {
            $sets[] = '!@#$%&*?';
        }

        $all = '';
        $password = '';
        foreach ($sets as $set) {
            $password .= $set[self::tweak_array_rand(str_split($set))];
            $all .= $set;
        }

        $all = str_split($all);
        for ($i = 0; $i < $length - count($sets); $i++) {
            $password .= $all[self::tweak_array_rand($all)];
        }

        $password = str_shuffle($password);

        $dash_len = floor(sqrt($length));
        $dash_str = '';
        while (strlen($password) > $dash_len) {
            $dash_str .= substr($password, 0, $dash_len).'-';
            $password = substr($password, $dash_len);
        }
        $dash_str .= $password;
        return $dash_str;
    }

    //take a array and get random index, same function of array_rand, only diference is
    // intent use secure random algoritn on fail use mersene twistter, and on fail use defaul array_rand
    public static function tweak_array_rand($array)
    {
        if (function_exists('random_int')) {
            return random_int(0, count($array) - 1);
        } elseif (function_exists('mt_rand')) {
            return mt_rand(0, count($array) - 1);
        } else {
            return array_rand($array);
        }
    }
}