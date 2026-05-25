<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectLoggerDB_V647')) :
class WPRProtectLoggerDB_V647 {
	private $tablename;
	private $bv_tablename;

	const MAXROWCOUNT = 100000;

	function __construct($tablename) {
		$this->tablename = $tablename;
		$this->bv_tablename = WPRProtect_V647::$db->getBVTable($tablename);
	}

	public function log($data) {
		if (is_array($data)) {
			if (WPRProtect_V647::$db->rowsCount($this->bv_tablename) > WPRProtectLoggerDB_V647::MAXROWCOUNT) {
				WPRProtect_V647::$db->deleteRowsFromtable($this->tablename, 1);
			}

			WPRProtect_V647::$db->replaceIntoBVTable($this->tablename, $data);
		}
	}
}
endif;