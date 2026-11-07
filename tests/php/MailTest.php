<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Mail;

class MailTest extends TestCase {

	public function test_from_address_uses_the_notification_username(): void {
		$this->assertSame( 'notification@example.org', apply_filters( 'wp_mail_from', 'wordpress@example.org' ) );
	}

	public function test_from_username_is_filterable(): void {
		add_filter( 'bm_wpexp_notifications_from_email_username', static fn() => 'noreply' );

		$this->assertSame( 'noreply@example.org', Mail::change_username_in_from_email_address_setting( 'wordpress@example.org' ) );
	}

	public function test_addresses_without_a_domain_are_left_untouched(): void {
		$this->assertSame( 'not-an-email', Mail::change_username_in_from_email_address_setting( 'not-an-email' ) );
	}

	public function test_from_name_defaults_to_the_site_name(): void {
		update_option( 'blogname', 'Acme Inc' );

		$this->assertSame( 'Acme Inc', apply_filters( 'wp_mail_from_name', 'WordPress' ) );

		add_filter( 'bm_wpexp_notifications_from_name', static fn() => 'Acme Support' );
		$this->assertSame( 'Acme Support', apply_filters( 'wp_mail_from_name', 'WordPress' ) );
	}

	public function test_postal_is_skipped_when_not_configured(): void {
		$this->assertNull( Mail::send_mail_via_postal( null, [ 'to' => 'a@example.org', 'subject' => 'Hi', 'message' => 'Hello' ] ) );
	}

	public function test_mail_still_goes_through_wp_mail(): void {
		reset_phpmailer_instance();

		$this->assertTrue( wp_mail( 'someone@example.org', 'Subject', 'Body' ) );

		$mailer = tests_retrieve_phpmailer_instance();
		$this->assertSame( 'notification@example.org', $mailer->From );
		$this->assertNotSame( 'smtp', $mailer->Mailer, 'SMTP is not enabled without configuration.' );
	}
}
