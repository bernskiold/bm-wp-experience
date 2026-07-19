<?php

namespace Bernskiold\WP\Experience\Modules;

class Admin_Ad_Blocker extends Module {

	public static function hooks(): void {

		// This module only runs in admin.
		if ( ! is_admin() ) {
			return;
		}

		// Allow disabling of module.
		if ( true !== apply_filters( 'bm_wpexp_enable_admin_ad_blocker', true ) ) {
			return;
		}

		add_action( 'admin_head', [ self::class, 'styles' ] );
		add_action( 'admin_init', [ self::class, 'hide_ad_pages' ], 9999 );

	}

	public static function styles(): void {
		$selectors = self::get_ad_selectors();

		if ( empty( $selectors ) ) {
			return;
		}

		// @formatter:off
		?>
		<style>
<?php echo $selectors; ?> { display: none !important; }
		</style>
		<?php
		// @formatter:on
	}

	public static function hide_ad_pages(): void {

		// Remove premium only pages from Yoast unless we are running premium.
		if ( function_exists( 'YoastSEO' ) && ! YoastSEO()->helpers->product->is_premium() ) {
			remove_submenu_page( 'wpseo_dashboard', 'wpseo_licenses' );
			remove_submenu_page( 'wpseo_dashboard', 'wpseo_workouts' );
		}
	}

	protected static function get_ad_selectors(): string {
		$selectors = apply_filters( 'bm_wpexp_admin_ads_selectors', [
			'#yoast-helpscout-beacon',
			'.yoast-container__configuration-wizard',
			'.wpseo_content_wrapper #sidebar-container',
			'.yoast_premium_upsell',
			'#wpseo-local-seo-upsell',
			'.yoast-settings-section-upsell',
			'#bwp-get-social',
			'.bwp-button-paypal',
			'#bwp-sidebar-right',
			'.tjcc-custom-css #postbox-container-1',
			'.settings_page_wpcustomtaxfilterinadmin #postbox-container-1',
			'#duplicate-post-notice #newsletter-subscribe-form',
			'div[id^="dnh-wrm"]',
			'.notice-info.dst-notice',
			'#googleanalytics_terms_notice',
			'.fw-brz-dismiss',
			'div.elementor-message[data-notice_id="elementor_dev_promote"]',
			'.notice-success.wpcf7r-notice',
			'.dc-text__block.disable__comment__alert',
			'#ws_sidebar_pro_ad',
			'.pa-new-feature-notice',
			'#redux-connect-message',
			'.frash-notice-email',
			'.frash-notice-rate',
			'#smush-box-pro-features',
			'#wp-smush-bulk-smush-upsell-row',
			'#easy-updates-manager-dashnotice',
			'#metaslider-optin-notice',
			'#extendifysdk_announcement',
			'.updraft-ad-container',
			'.mo-admin-notice',
			'.post-smtp-donation',
			'div[data-dismissible="notice-owa-sale-forever"]',
			'.neve-notice-upsell',
			'#pagelayer_promo',
			'#simple-custom-post-order-epsilon-review-notice',
			'.sfsi_new_prmium_follw',
			'div.fs-slug-the-events-calendar[data-id="connect_account"]',
			'div.notice[data-notice="webp-converter-for-media"]',
			'.webpLoader__popup.webpPopup',
			'.put-dismiss-notice',
			'.wp-mail-smtp-review-notice',
			'#wp-mail-smtp-pro-banner',
			'body div.promotion.fs-notice',
			'.analytify-review-thumbnail',
			'.jitm-banner.is-upgrade-premium',
			'div[data-name*="wbcr_factory_notice_adverts"]',
			'.sui-subscription-notice',
			'#sui-cross-sell-footer',
			'.sui-cross-sell-modules',
			'.forminator-rating-notice',
			'.sui-dashboard-upsell-upsell',
			'.anwp-post-grid__rate',
			'.cff-settings-cta',
            '#wpdmpro_notice'
		] );

		return implode( ', ', $selectors );
	}

}
