<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectLoggerDB_V636')) :
class WPRProtectLoggerDB_V636 {
	private $tablename;
	private $bv_tablename;

	const MAXROWCOUNT = 100000;

	function __construct($tablename) {
		$this->tablename = $tablename;
		$this->bv_tablename = WPRProtect_V636::$db->getBVTable($tablename);
	}

	public function log($data) {
		if (is_array($data)) {
			if (WPRProtect_V636::$db->rowsCount($this->bv_tablename) > WPRProtectLoggerDB_V636::MAXROWCOUNT) {
				WPRProtect_V636::$db->deleteRowsFromtable($this->tablename, 1);
			}

			WPRProtect_V636::$db->replaceIntoBVTable($this->tablename, $data);
		}
	}
}
endif;