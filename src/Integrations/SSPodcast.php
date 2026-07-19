<?php

namespace Bernskiold\WP\Experience\Integrations;

class SSPodcast extends Integration {

	public static string $plugin_file = 'seriously-simple-podcasting/seriously-simple-podcasting.php';

	public static function hooks(): void {
		add_filter( 'ssp_feed_number_of_posts', [ self::class, 'modify_number_of_posts_in_feed' ], 100 );
	}

	public static function modify_number_of_posts_in_feed() {
		return apply_filters( 'bm_wpexp_sspodcast_posts_in_feed', 100000 );
	}

}
