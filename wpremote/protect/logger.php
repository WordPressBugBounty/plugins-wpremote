<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectLogger_V593')) :
require_once dirname( __FILE__ ) . '/logger/fs.php';
require_once dirname( __FILE__ ) . '/logger/db.php';

class WPRProtectLogger_V593 {
	private $log_destination;

	const TYPE_FS = 0;
	const TYPE_DB = 1;

	function __construct($name, $type = WPRProtectLogger_V593::TYPE_DB) {
		if ($type == WPRProtectLogger_V593::TYPE_FS) {
			$this->log_destination = new WPRProtectLoggerFS_V593($name);
		} else {
			$this->log_destination = new WPRProtectLoggerDB_V593($name);
		}
	}

	public function log($data) {
		$this->log_destination->log($data);
	}
}
endif;