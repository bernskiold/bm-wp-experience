<?php
/**
 * Admin Page View: About Bernskiold
 *
 * @package BernskioldMedia\WP\Experience
 */

namespace BernskioldMedia\WP\Experience;

$website_id = defined( 'BM_WP_WEBSITE_UUID' ) ? BM_WP_WEBSITE_UUID : null;

if ( ! $website_id ) {
	return;
}

?>
<div class="wrap" style="margin: -8px 0 0 -20px;">
	<iframe src="https://360.bmedia.io/embed/website-dashboard/<?php echo esc_attr( $website_id ); ?>" frameborder="0" style="width: 100%; height: 100vh;"></iframe>
</div>
<style>
	#wpfooter {display: none;}

	#wpbody-content {padding-bottom: 0;}
</style>
