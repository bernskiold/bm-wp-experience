<?php

namespace Bernskiold\WP\Experience\Modules\Htaccess;

class ResponseHeaders extends HtaccessRuleset {

	protected array $rules = [
		'enabled'  => '/\#\s+BM HTTP Response Headers/si',
		'disabled' => '/\#\s+BM\s+HTTP\s+Response\s+Headers(.+?)\#\s+BM\s+HSTS\s+Response\s+Headers\s+END(\n)?/ims',
	];

	protected string $template = 'http-response.tpl';

}
