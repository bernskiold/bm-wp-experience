<?php

namespace Bernskiold\WP\Experience\Modules\Htaccess;

class XMLRPC_Protection extends HtaccessRuleset {

	protected array $rules = [
		'enabled'  => '/\#\s+BM Disable XMLRPC/si',
		'disabled' => '/\#\s+BM\s+Disable\s+XMLRPC(.+?)\#\s+BM\s+Disable\s+XMLRPC\s+END(\n)?/ims',
	];

	protected string $template = 'xmlrpc.tpl';

}
