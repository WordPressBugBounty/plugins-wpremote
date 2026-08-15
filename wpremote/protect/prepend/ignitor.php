<?php
if (!defined('MCDATAPATH')) exit;

if (defined('MCCONFKEY')) {
	require_once dirname( __FILE__ ) . '/../protect.php';

	WPRProtect_V665::init(WPRProtect_V665::MODE_PREPEND);
}