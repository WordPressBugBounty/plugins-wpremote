<?php
if (!defined('MCDATAPATH')) exit;

if (defined('MCCONFKEY')) {
	require_once dirname( __FILE__ ) . '/../protect.php';

	WPRProtect_V591::init(WPRProtect_V591::MODE_PREPEND);
}