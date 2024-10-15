<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectLoggerDB_V581')) :
class WPRProtectLoggerDB_V581 {
	private $tablename;
	private $bv_tablename;

	const MAXROWCOUNT = 100000;

	function __construct($tablename) {
		$this->tablename = $tablename;
		$this->bv_tablename = WPRProtect_V581::$db->getBVTable($tablename);
	}

	public function log($data) {
		if (is_array($data)) {
			if (WPRProtect_V581::$db->rowsCount($this->bv_tablename) > WPRProtectLoggerDB_V581::MAXROWCOUNT) {
				WPRProtect_V581::$db->deleteRowsFromtable($this->tablename, 1);
			}

			WPRProtect_V581::$db->replaceIntoBVTable($this->tablename, $data);
		}
	}
}
endif;