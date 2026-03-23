<?php
if (!defined('MCDATAPATH')) exit;

if (defined('MCCONFKEY')) {
	require_once dirname( __FILE__ ) . '/../protect.php';

	WPRProtect_V639::init(WPRProtect_V639::MODE_PREPEND);
}