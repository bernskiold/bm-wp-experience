<?php
/**
 * Users Tweaks
 **/

namespace Bernskiold\WP\Experience\Modules;

class Users extends Module {

    /**
     * On these domain names, agency users may be indexed.
     * Includes sub-domains.
     */
    protected const ALLOWLISTED_DOMAINS = [
        'bernskiold.com',
        'bernskiold.se',
    ];

    /**
     * Agency users are those with e-mails
     * in these domains (including sub-domains).
     */
    protected const EMAIL_DOMAINS = [
        'bernskiold.com',
        'bernskiold.se',
        'bernskioldmedia.com',
        'bernskioldmedia.se',
    ];

    public static function hooks(): void {
        add_action( 'wp', [ self::class, 'maybe_disable_author_archive' ] );

        // Block user enumeration via ?author=N scans. Runs before
        // redirect_canonical (priority 10) so the username is never leaked.
        add_action( 'template_redirect', [ self::class, 'block_author_enumeration' ], 0 );

        // Disable Gravatar phone-home unless explicitly enabled.
        if ( ! self::is_gravatar_enabled() ) {
            add_filter( 'pre_get_avatar_data', [ self::class, 'disable_gravatar' ] );
        }

        // Remove the color scheme picker from the admin.
        if ( true === apply_filters( 'bm_wpexp_remove_color_scheme_picker', true ) ) {
            remove_action( 'admin_color_scheme_picker', 'admin_color_scheme_picker' );
        }
    }

    /**
     * Block user enumeration via ?author=N scans.
     *
     * By default WordPress redirects /?author=1 to /author/username/,
     * leaking the login name. We intercept the numeric author query on the
     * front end and redirect to the home page instead.
     *
     * Return the bm_wpexp_block_user_enumeration filter as false to allow it.
     */
    public static function block_author_enumeration(): void {
        if ( is_admin() ) {
            return;
        }

        if ( false === apply_filters( 'bm_wpexp_block_user_enumeration', true ) ) {
            return;
        }

        if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
            wp_safe_redirect( home_url(), 301 );
            exit;
        }
    }

    /**
     * Replace the remote Gravatar URL with a local, inline placeholder so
     * that no request is ever made to gravatar.com.
     *
     * Setting the url short-circuits get_avatar_data() before it builds the
     * remote Gravatar URL.
     *
     * @param array $args The avatar data arguments.
     */
    public static function disable_gravatar( array $args ): array {
        $args['url'] = self::get_local_avatar_url();

        return $args;
    }

    /**
     * Whether Gravatar (remote avatars) should be enabled.
     *
     * Disabled by default to avoid phoning home to gravatar.com. Define
     * BM_WP_ENABLE_GRAVATAR as true, or return the bm_wpexp_enable_gravatar
     * filter as true, to restore native behavior.
     */
    protected static function is_gravatar_enabled(): bool {
        if ( defined( 'BM_WP_ENABLE_GRAVATAR' ) && BM_WP_ENABLE_GRAVATAR ) {
            return true;
        }

        return true === apply_filters( 'bm_wpexp_enable_gravatar', false );
    }

    /**
     * A neutral, inline SVG avatar used when Gravatar is disabled.
     *
     * Returned as a data URI so that rendering it never triggers an HTTP
     * request to an external service.
     */
    protected static function get_local_avatar_url(): string {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96"><rect width="96" height="96" fill="#e6e6e6"/><circle cx="48" cy="38" r="18" fill="#b3b3b3"/><path d="M16 88c0-17.7 14.3-32 32-32s32 14.3 32 32z" fill="#b3b3b3"/></svg>';

        return 'data:image/svg+xml;base64,' . base64_encode( $svg );
    }

    /**
     * We want to disable the author archive so that
     * agency users never get indexed on client sites.
     */
    public static function maybe_disable_author_archive(): void {
        if ( ! is_author() ) {
            return;
        }

        $is_author_disabled = false;
        $author             = get_queried_object();
        $current_domain     = parse_url( get_site_url(), PHP_URL_HOST );

        // Perform partial match on domains to catch subdomains or variation of domain name
        $filtered_domains = array_filter( self::get_allowlisted_domains(), fn ( $domain ) => false !== stripos( $current_domain, $domain ) );

        /*
         * The user in the query must have an email,
         * or if we allow indexing of BM users.
         */
        if ( ! empty( $filtered_domains ) || empty( $author->data->user_email ) || true === apply_filters( 'bm_wpexp_allow_bm_author_index', false ) ) {
            return;
        }

        foreach ( self::get_email_domains() as $domain ) {
            if ( false !== stripos( $author->data->user_email, $domain ) ) {
                $is_author_disabled = true;
            }
        }

        if ( true === $is_author_disabled ) {
            wp_safe_redirect( '/', 301 );
            exit();
        }
    }

    /**
     * Get Allowlisted Domains
     */
    public static function get_allowlisted_domains(): array {
        return apply_filters( 'bm_wpexp_authors_allowlisted_domains', self::ALLOWLISTED_DOMAINS );
    }

    /**
     * Get E-Mail Domains
     */
    public static function get_email_domains(): array {
        return apply_filters( 'bm_wpexp_authors_email_domains', self::EMAIL_DOMAINS );
    }

    public static function is_agency( $user ): bool {

        foreach ( self::get_email_domains() as $domain ) {
            if ( false !== stripos( $user->user_email, $domain ) ) {
                return true;
            }
        }

        return false;
    }
}
