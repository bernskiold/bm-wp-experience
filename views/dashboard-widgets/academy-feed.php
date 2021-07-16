<?php foreach ( $items as $item ) : ?>
<?php
	$string = wp_strip_all_tags( $item->get_description() );
	$string = ( strlen( $string ) > 120 ) ? substr( $string, 0, 123 ) . '...' : $string;
	?>
	<article class="bm-academy-feed-item">
		<a target="_blank" href="<?php echo esc_url($item->get_permalink()); ?>">
			<h3><?php echo esc_html( $item->get_title() ); ?> ›</h3>
			<p><?php echo esc_html( $string ); ?></p>
		</a>

	</article>
<?php endforeach; ?>
<p class="bm-academy-feed-more">
	<a href="#">More at the Academy ›</a>
</p>
