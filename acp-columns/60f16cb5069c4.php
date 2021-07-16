<?php

return [
	'version'  => '5.2',
	'title'    => __( 'Pages' ),
	'type'     => 'page',
	'id'       => '60f16cb5069c4',
	'updated'  => 1626435114,
	'columns'  => [
		'title'         => [
			'type'       => 'title',
			'label'      => __( 'Title' ),
			'width'      => '',
			'width_unit' => '%',
			'sort'       => 'on',
			'edit'       => 'off',
			'export'     => 'on',
			'search'     => 'on',
		],
		'60f16e2a2f01b' => [
			'type'          => 'date',
			'label'         => __( 'Published' ),
			'width'         => '',
			'width_unit'    => '%',
			'sort'          => 'on',
			'edit'          => 'off',
			'export'        => 'off',
			'search'        => 'on',
			'filter'        => 'on',
			'filter_label'  => __( 'Published' ),
			'filter_format' => 'range',
		],
		'author'        => [
			'type'       => 'author',
			'label'      => __( 'Author' ),
			'width'      => '',
			'width_unit' => '%',
			'sort'       => 'on',
			'edit'       => 'off',
			'export'     => 'on',
			'search'     => 'on',
		],
		'60f16e2a2f01e' => [
			'type'          => 'column-modified',
			'label'         => __( 'Last Updated', 'bm-wp-experience' ),
			'width'         => '10',
			'width_unit'    => '%',
			'date_format'   => 'j F Y',
			'sort'          => 'on',
			'edit'          => 'off',
			'export'        => 'on',
			'search'        => 'on',
			'filter'        => 'on',
			'filter_label'  => __( 'Last Updated', 'bm-wp-experience' ),
			'filter_format' => 'range',
		],
		'60f16e2a2f01f' => [
			'type'              => 'column-last_modified_author',
			'label'             => __( 'Last Updated By', 'bm-wp-experience' ),
			'width'             => '10',
			'width_unit'        => '%',
			'display_author_as' => 'display_name',
			'user_link_to'      => 'view_author',
			'sort'              => 'on',
			'export'            => 'on',
			'search'            => 'on',
			'filter'            => 'off',
			'filter_label'      => '',
		],
		'60f16e2a2f020' => [
			'type'       => 'column-word_count',
			'label'      => __( 'Words', 'bm-wp-experience' ),
			'width'      => '100',
			'width_unit' => 'px',
			'sort'       => 'on',
			'export'     => 'on',
		],
		'wpseo-score'   => [
			'type'       => 'wpseo-score',
			'label'      => __( 'SEO', 'bm-wp-experience' ),
			'width'      => '63',
			'width_unit' => 'px',
			'sort'       => 'on',
			'export'     => 'on',
		],
	],
	'settings' => [
		'hide_inline_edit'      => 'off',
		'hide_bulk_edit'        => 'off',
		'hide_filters'          => 'off',
		'hide_filter_post_date' => 'on',
		'hide_smart_filters'    => 'off',
		'hide_segments'         => 'off',
		'hide_export'           => 'off',
		'hide_new_inline'       => 'on',
		'hide_search'           => 'off',
		'hide_bulk_actions'     => 'off',
		'horizontal_scrolling'  => 'off',
		'sorting'               => '0',
		'sorting_order'         => 'asc',
	],
];
