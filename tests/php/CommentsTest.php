<?php

namespace Bernskiold\WP\Experience\Tests;

use Bernskiold\WP\Experience\Modules\Comments;
use WP_REST_Request;

/**
 * Comments are disabled by default (BM_WP_ENABLE_COMMENTS is not defined).
 */
class CommentsTest extends TestCase {

	public function tear_down(): void {
		global $wp_rest_server;
		$wp_rest_server = null;

		parent::tear_down();
	}

	public function test_comments_and_pings_are_closed(): void {
		$post_id = self::factory()->post->create( [ 'comment_status' => 'open', 'ping_status' => 'open' ] );

		$this->assertFalse( comments_open( $post_id ) );
		$this->assertFalse( pings_open( $post_id ) );
	}

	public function test_existing_comments_are_hidden(): void {
		$post_id = self::factory()->post->create();
		self::factory()->comment->create( [ 'comment_post_ID' => $post_id ] );

		$this->assertSame( [], apply_filters( 'comments_array', get_comments( [ 'post_id' => $post_id ] ), $post_id ) );
	}

	public function test_pingback_header_and_flag_are_removed(): void {
		$this->assertSame( [ 'Content-Type' => 'text/html' ], apply_filters( 'wp_headers', [ 'X-Pingback' => 'x', 'Content-Type' => 'text/html' ] ) );
		$this->assertSame( 0, (int) get_option( 'default_pingback_flag' ) );
	}

	public function test_comment_feed_links_are_disabled(): void {
		$this->assertFalse( apply_filters( 'feed_links_show_comments_feed', true ) );
	}

	public function test_xmlrpc_new_comment_method_is_removed(): void {
		// XML_RPC empties the method list altogether by default; this checks
		// the comments module's own filter for sites that keep XML-RPC.
		$methods = Comments::disable_comments_via_xmlrpc( [ 'wp.newComment' => 'x', 'wp.getPosts' => 'y' ] );

		$this->assertArrayNotHasKey( 'wp.newComment', $methods );
		$this->assertArrayHasKey( 'wp.getPosts', $methods );
	}

	public function test_comments_cannot_be_created_via_the_rest_api(): void {
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );
		$post_id = self::factory()->post->create();

		$request = new WP_REST_Request( 'POST', '/wp/v2/comments' );
		$request->set_param( 'post', $post_id );
		$request->set_param( 'content', 'Hello' );

		$response = rest_get_server()->dispatch( $request );

		// Closed comments already stop the request; the insert filter is the
		// second line of defence.
		$this->assertSame( 403, $response->get_status() );
		$this->assertContains( $response->as_error()->get_error_code(), [ 'rest_comment_closed', 'rest_comment_insert_disabled' ] );

		$error = apply_filters( 'rest_pre_insert_comment', (object) [ 'comment_content' => 'Hello' ], $request );
		$this->assertWPError( $error );
		$this->assertSame( 'rest_comment_insert_disabled', $error->get_error_code() );
		$this->assertSame( 403, $error->get_error_data()['status'] );
		$this->assertSame( 0, (int) get_comments( [ 'post_id' => $post_id, 'count' => true ] ) );
	}

	public function test_comment_support_is_removed_from_post_types(): void {
		$this->assertTrue( post_type_supports( 'post', 'comments' ) );

		Comments::remove_post_type_support();

		$this->assertFalse( post_type_supports( 'post', 'comments' ) );
		$this->assertFalse( post_type_supports( 'post', 'trackbacks' ) );

		add_post_type_support( 'post', [ 'comments', 'trackbacks' ] );
	}

	public function test_comment_reply_script_is_deregistered_on_the_front_end(): void {
		do_action( 'wp_enqueue_scripts' );

		$this->assertFalse( wp_script_is( 'comment-reply', 'registered' ) );
	}
}
