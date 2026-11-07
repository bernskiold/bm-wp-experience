<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Updates;

class UpdatesTest extends TestCase {

	public function test_update_tweaks_only_apply_on_a_maintenance_plan(): void {
		$this->assertFalse( Updates::is_on_maintenance_plan() );
		$this->assertFalse( has_filter( 'auto_core_update_send_email', [ Updates::class, 'dont_send_auto_update_emails' ] ) );
	}

	public function test_only_successful_core_update_emails_are_suppressed(): void {
		$this->assertFalse( Updates::dont_send_auto_update_emails( true, 'success' ) );
		$this->assertTrue( Updates::dont_send_auto_update_emails( true, 'fail' ) );
		$this->assertTrue( Updates::dont_send_auto_update_emails( true, 'critical' ) );
		$this->assertTrue( Updates::dont_send_auto_update_emails( true, '' ) );
	}
}
