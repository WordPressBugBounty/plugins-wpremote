<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectLoggerFS_V585')) :
class WPRProtectLoggerFS_V585 {
	public $logFile;

	function __construct($filename) {
		$this->logFile = $filename;
	}

	public function log($data) {
		$_data = serialize($data);
		$str = "bvlogbvlogbvlog" . ":";
		$str .= strlen($_data) . ":" . $_data;
		error_log($str, 3, $this->logFile);
	}
}
endif;