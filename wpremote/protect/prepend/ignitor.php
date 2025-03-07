<?php
if (!defined('MCDATAPATH')) exit;

if (defined('MCCONFKEY')) {
	require_once dirname( __FILE__ ) . '/../protect.php';

	WPRProtect_V592::init(WPRProtect_V592::MODE_PREPEND);
}