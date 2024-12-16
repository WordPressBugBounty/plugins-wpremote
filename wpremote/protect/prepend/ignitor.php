<?php
if (!defined('MCDATAPATH')) exit;

if (defined('MCCONFKEY')) {
	require_once dirname( __FILE__ ) . '/../protect.php';

	WPRProtect_V588::init(WPRProtect_V588::MODE_PREPEND);
}