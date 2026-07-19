<?php

namespace BernskioldMedia\WP\Experience\Rest;

use BMWPEXP_Vendor\BernskioldMedia\WP\PluginBase\Interfaces\Hookable;
use DateTime;
use OhDear\HealthCheckResults\CheckResult;
use OhDear\HealthCheckResults\CheckResults;
use WP_REST_Request;
use WP_REST_Response;
use WP_Site_Health;

class OhDear_Application_Health implements Hookable {

	public static function hooks(): void {
		if ( null === self::get_secret() ) {
			return;
		}

		add_action( 'rest_api_init', function() {
			register_rest_route( 'bm-wp-experience/v1', '/application-health', [
				'methods'  => 'GET',
				'callback' => [ self::class, 'callback' ],
			] );
		} );
	}

	public static function callback( WP_REST_Request $request ): WP_REST_Response {
		$secret = $request->get_header( 'oh-dear-health-check-secret' );

		if ( ! self::is_secret_valid( $secret ) ) {
			return new WP_REST_Response( [
				'error' => 'Unfortunately you do not have access to perform this action.',
			], 403 );
		}

		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		$check_results = new CheckResults( new DateTime() );
		$site_health   = WP_Site_Health::get_instance();
		$tests         = WP_Site_Health::get_tests();

		foreach ( $tests['direct'] as $test ) {
			$test_results = null;

			if ( is_string( $test['test'] ) ) {
				$test_function = sprintf( 'get_test_%s', $test['test'] );

				if ( method_exists( $site_health, $test_function ) && is_callable( [ $site_health, $test_function ] ) ) {
					$test_results = self::perform_test( [ $site_health, $test_function ] );
				}
			} elseif ( is_callable( $test['test'] ) ) {
				$test_results = self::perform_test( $test['test'] );
			}

			if ( $test_results ) {
				$check_results->addCheckResult( new CheckResult( $test_results['test'], $test['label'], wp_strip_all_tags( $test_results['description'] ), $test_results['label'],
					self::map_status( $test_results ), [
						'actions' => $test_results['actions'] ?? '',
					] ) );
			}
		}

		return new WP_REST_Response( json_decode( $check_results->toJson() ) );
	}

	protected static function perform_test( $callback ) {
		return apply_filters( 'site_status_test_result', call_user_func( $callback ) );
	}

	protected static function get_secret(): ?string {
		return defined( 'BM_WP_OH_DEAR_SECRET' ) ? BM_WP_OH_DEAR_SECRET : null;
	}

	protected static function is_secret_valid( ?string $request_secret ): bool {
		if ( ! $request_secret ) {
			return false;
		}

		$app_secret = self::get_secret();

		if ( ! $app_secret ) {
			return false;
		}

		return $request_secret === $app_secret;
	}

	protected static function map_status( array $test_results ): string {
		return match ( $test_results['status'] ) {
			'good'        => CheckResult::STATUS_OK,
			'recommended' => CheckResult::STATUS_WARNING,
			'critical'    => CheckResult::STATUS_FAILED,
			default       => CheckResult::STATUS_SKIPPED,
		};
	}

}
