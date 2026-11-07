<?php

namespace Bernskiold\WP\Experience\Tests;

class MediaTest extends TestCase {

	/**
	 * @dataProvider file_names
	 */
	public function test_uploaded_file_names_are_normalised( string $input, string $expected ): void {
		$this->assertSame( $expected, sanitize_file_name( $input ) );
	}

	public static function file_names(): array {
		return [
			'accents and spaces' => [ 'Hällo Wörld.JPG', 'hallo-world.jpg' ],
			'underscores'        => [ 'my_great_photo.png', 'my-great-photo.png' ],
			'extra dots'         => [ 'report.final.v2.pdf', 'reportfinal-v2.pdf' ],
			'repeated dashes'    => [ 'a -- b.gif', 'a-b.gif' ],
			'trailing dash'      => [ 'image-.png', 'image.png' ],
			'special characters' => [ 'Åsa & Örjan (1)!.jpeg', 'asa-orjan-1.jpeg' ],
		];
	}
}
