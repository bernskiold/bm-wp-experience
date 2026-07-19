<?php

namespace BernskioldMedia\WP\Experience\Enums;

/**
 * The access roles supported by the Matomo API.
 *
 * The backing string values are the identifiers Matomo expects over the API.
 */
enum MatomoRole: string {
	case Admin    = 'admin';
	case View     = 'view';
	case NoAccess = 'noaccess';
}
