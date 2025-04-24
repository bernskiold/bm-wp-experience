<?php

namespace BernskioldMedia\WP\Experience\Modules;

use PHPMailer\PHPMailer\PHPMailer;
use Postal\Client;
use Postal\Error;
use Postal\SendMessage;
use WP_Error;

class Mail extends Module {

	public static function hooks(): void {
		add_filter( 'pre_wp_mail', [ self::class, 'send_mail_via_postal' ], 10, 2 );
		add_action( 'phpmailer_init', [ self::class, 'send_mail_via_smtp' ] );
		add_action( 'admin_notices', [ self::class, 'warn_improper_smtp_configuration' ] );

        add_filter('wp_mail_from', [ self::class, 'change_username_in_from_email_address_setting' ], 999 );
        add_filter('wp_mail_from_name', [ self::class, 'change_from_name_setting' ], 999 );
        add_filter('wp_mail_from', [ self::class, 'change_from_email_address_setting' ], 999 );

    }

	public static function warn_improper_smtp_configuration(): void {

        // Check if we've added the setting to send via smtp
		if ( ! self::should_send_via_smtp() ) {
			return;
		}

        // We can specify which sites to send via smtp. If they're not on the list, we don't want to check the config
        if( ! self::should_send_for_this_site() ){
            return;
        }

        // check that all configs are set
		if ( self::are_all_configs_set() ) {
			return;
		}

        // All configs are not set, so we show a warning
		?>
		<div class="notice notice-error">
			<p>
				<strong><?php esc_html_e( 'E-Mails Not Sending:', 'bm-wp-experience' ); ?></strong>
			</p>
			<p><?php esc_html_e( 'Sending via SMTP is currently enabled but the configuration has not been properly set in the configuration files. Sending via SMTP is therefore disabled and e-mail will be send via the default PHP sendmail functions.', 'bm-wp-experience' ); ?></p>
			<p><?php esc_html_e( 'You can fix this error by either disabling SMTP in the configuration, or providing proper configuration values.', 'bm-wp-experience' ); ?></p>
		</div>
		<?php
	}

	public static function send_mail_via_smtp( PHPMailer $mailer ): void {

		if ( ! self::should_send_via_smtp() ) {
			return;
		}

        // We can specify which sites to send via smtp. If they're not on the list, we don't want to check the config
        if( ! self::should_send_for_this_site() ){
            return;
        }

		if ( ! self::are_all_configs_set() ) {
			return;
		}

		$mailer->set( 'Host', self::get_smtp_host() );
		$mailer->set( 'Port', self::get_smtp_port() );
		$mailer->set( 'Username', self::get_smtp_username() );
		$mailer->set( 'Password', self::get_smtp_password() );
		$mailer->set( 'SMTPAuth', true );
		$mailer->set( 'SMTPSecure', self::get_smtp_secure_type() );
        $mailer->set( 'Encoding', 'quoted-printable' );
		$mailer->isSMTP();
	}

    protected static function should_send_for_this_site(): bool {

        // if is not multisite, we do not need to check if we should send for this site
        if( ! is_multisite() ){
            return true;
        }

        // if we haven't defined what sites we should send for, we should send for all sites
        if( ! defined( 'BM_WP_SMTP_SITE_IDS' ) ){
            return true;
        }

        // if we have defined what sites we should send for, we should check if we're on the list
        if( is_array( BM_WP_SMTP_SITE_IDS ) && in_array( get_current_blog_id(), BM_WP_SMTP_SITE_IDS ) ){
            return true;
        }

        return false;
    }

	protected static function should_send_via_smtp(): bool {
		if ( 'production' !== wp_get_environment_type() ) {
			return self::should_send_smtp_outside_production();
		}

		return self::should_send_smtp_in_production();
	}

	protected static function should_send_smtp_outside_production(): bool {
		return defined( 'BM_WP_SMTP_OUTSIDE_PRODUCTION' ) && true === BM_WP_SMTP_OUTSIDE_PRODUCTION;
	}

	protected static function should_send_smtp_in_production(): bool {
		return defined( 'BM_WP_SMTP_ENABLED' ) && true === BM_WP_SMTP_ENABLED;
	}

	protected static function get_smtp_host(): ?string {
		return defined( 'BM_WP_SMTP_HOST' ) ? BM_WP_SMTP_HOST : null;
	}

	protected static function get_smtp_username(): ?string {
		return defined( 'BM_WP_SMTP_USERNAME' ) ? BM_WP_SMTP_USERNAME : null;
	}

	protected static function get_smtp_password(): ?string {
		return defined( 'BM_WP_SMTP_PASSWORD' ) ? BM_WP_SMTP_PASSWORD : null;
	}

	protected static function get_smtp_port(): int {
		return defined( 'BM_WP_SMTP_PORT' ) ? (int) BM_WP_SMTP_PORT : 587;
	}

	protected static function get_smtp_secure_type(): ?string {
		return defined( 'BM_WP_SMTP_SECURITY' ) ? BM_WP_SMTP_SECURITY : 'tls';
	}

	protected static function are_all_configs_set(): bool {
		return ! empty( self::get_smtp_host() ) && ! empty( self::get_smtp_username() ) && ! empty( self::get_smtp_password() ) && is_int( self::get_smtp_port() );
	}

	protected static function get_postal_domain(): ?string {
		return defined( 'BM_WP_POSTAL_DOMAIN' ) ? BM_WP_POSTAL_DOMAIN : 'https://postal.oderland.com';
	}

	protected static function get_postal_api_key(): ?string {
		return defined( 'BM_WP_POSTAL_API_KEY' ) ? BM_WP_POSTAL_API_KEY : null;
	}

	protected static function should_send_via_postal(): bool {
		if ( 'production' !== wp_get_environment_type() ) {
			return self::should_send_postal_outside_production();
		}

		return self::should_send_postal_in_production();
	}

	protected static function should_send_postal_outside_production(): bool {
		return defined( 'BM_WP_POSTAL_OUTSIDE_PRODUCTION' ) && true === BM_WP_POSTAL_OUTSIDE_PRODUCTION;
	}

	protected static function should_send_postal_in_production(): bool {
		return defined( 'BM_WP_POSTAL_ENABLED' ) ? BM_WP_POSTAL_ENABLED : defined( 'BM_WP_POSTAL_API_KEY' );
	}

	public static function send_mail_via_postal( $null, $atts ): ?bool {

		if ( ! self::should_send_via_postal() ) {
			return null; // Null return means to use wp_mail default.
		}

        if( ! self::should_send_for_this_site() ){
            return null;
        }

		if ( null === self::get_postal_api_key() ) {
			return null; // Process by normal wp_mail.
		}

		$client  = new Client( self::get_postal_domain(), self::get_postal_api_key() );
		$message = new SendMessage( $client );

		if ( is_array( $atts['headers'] ) ) {
			$headers = $atts['headers'];
		} else {
			$headers = explode( "\n", str_replace( "\r\n", "\n", $atts['headers'] ) );
		}

		if ( ! empty( $headers ) ) {
			foreach ( $headers as $header ) {
				[ $name, $content ] = explode( ':', trim( $header ), 2 );
				$message->header( $name, $content );
			}
		}

		if ( is_array( $atts['to'] ) ) {
			foreach ( $atts['to'] as $email ) {
				$message->to( $email );
			}
		} else {
			$message->to( $atts['to'] );
		}

		$message->subject( $atts['subject'] );
		$message->tag( get_bloginfo( 'name' ) );

		$from_name  = apply_filters( 'wp_mail_from_name', get_bloginfo( 'name' ) );
		$from_email = apply_filters( 'wp_mail_from', null );

		if ( ! $from_email ) {
			$sitename   = wp_parse_url( network_home_url(), PHP_URL_HOST );
			$from_email = 'wordpress@';

			if ( null !== $sitename ) {
				if ( 'www.' === substr( $sitename, 0, 4 ) ) {
					$sitename = substr( $sitename, 4 );
				}

				$from_email .= $sitename;
			}
		}

		$message->from( "$from_name <$from_email>" );

		$content_type = apply_filters( 'wp_mail_content_type', 'text/plain' );

		if ( $content_type === 'text/plain' ) {
			$message->plainBody( $atts['message'] );
		} else {
			$message->htmlBody( $atts['message'] );
		}

		try {
			$result = $message->send();

			return count( $result->recipients() ) >= 1;
		} catch ( Error $error ) {
			do_action( 'wp_mail_failed', new WP_Error( 'wp_mail_failed', $error->getMessage(), $message ) );

			return false;
		}
	}

    /**
     * Change the first part of the from email address
     *
     * @param $from_email
     * @return string
     */
    public static function change_username_in_from_email_address_setting( $from_email ){
        // get whatever is before the @ and then the domain
        $parts = explode( '@', $from_email );

        $username = __( 'notification', 'bm-wp-experience' );


        if( defined( 'BM_WP_NOTIFICATIONS_FROM_EMAIL_USERNAME' ) ){
            $username = BM_WP_NOTIFICATIONS_FROM_EMAIL_USERNAME;
        }

        $username = apply_filters( 'bm_wpexp_notifications_from_email_username', $username );


        return $username.'@'.$parts[1];
    }

    public static function change_from_name_setting( $from_name ){

        $name = get_bloginfo( 'name' );

        if( defined( 'BM_WP_NOTIFICATIONS_FROM_NAME' ) ){
            $name = BM_WP_NOTIFICATIONS_FROM_NAME;
        }

        if( is_multisite() ) {
            if ( get_blog_option(get_current_blog_id(), 'bm_wp_notifications_from_name') && "" !== get_blog_option(get_current_blog_id(), 'bm_wp_notifications_from_name') ) {
                $name = get_blog_option(get_current_blog_id(), 'bm_wp_notifications_from_name');
            }
        }

        $name = apply_filters( 'bm_wpexp_notifications_from_name', $name);

        return $name;
    }

    public static function change_from_email_address_setting( $from_email ){

        if( defined( 'BM_WP_NOTIFICATIONS_FROM_EMAIL_ADDRESS' ) ){
            $from_email = BM_WP_NOTIFICATIONS_FROM_EMAIL_ADDRESS;
        }

        if( is_multisite() ) {
            if ( get_option('bm_wp_notifications_from_email_address') && "" !== get_option('bm_wp_notifications_from_email_address') ) {
                $from_email = get_option('bm_wp_notifications_from_email_address');
            }
        }

        $from_email = apply_filters( 'bm_wpexp_notifications_from_email_address', $from_email );


        return $from_email;
    }


}
