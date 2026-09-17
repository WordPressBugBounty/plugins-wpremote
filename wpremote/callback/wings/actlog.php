<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('WPRActLogCallback')) :
	
require_once dirname( __FILE__ ) . '/../../wp_actlog.php';

class WPRActLogCallback extends WPRCallbackBase {
	public $db;
	public $settings;

	const ACTLOG_WING_VERSION = 1.2;

	public function __construct($callback_handler) {
		$this->db = $callback_handler->db;
		$this->settings = $callback_handler->settings;
	}

	public function dropActLogTable() {
		return $this->db->dropBVTable(BVWPActLog::$actlog_table);
	}

	public function createActLogTable($usedbdelta = false) {
		$db = $this->db;
		$charset_collate = $db->getCharsetCollate();
		$table = $this->db->getBVTable(BVWPActLog::$actlog_table);
		$query = "CREATE TABLE $table (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			site_id int NOT NULL,
			user_id int DEFAULT 0,
			username text DEFAULT '',
			request_id text DEFAULT '',
			ip varchar(50) DEFAULT '',
			event_type varchar(60) NOT NULL DEFAULT '',
			event_data mediumtext NOT NULL,
			time int,
			PRIMARY KEY (id)
		) $charset_collate;";
		return $db->createTable($query, BVWPActLog::$actlog_table, $usedbdelta);
	}

	# The server confirms this migration before enabling the modern capture policy.
	public function alterActLogTable() {
		$table = $this->db->getBVTable(BVWPActLog::$actlog_table);
		$query = "ALTER TABLE $table MODIFY ip varchar(" . BVWPActLog::IP_MAX_LENGTH . ") DEFAULT '', " .
			"MODIFY event_type varchar(" . BVWPActLog::EVENT_TYPE_MAX_LENGTH . ") NOT NULL DEFAULT ''";
		return $this->db->alterBVTable($query, BVWPActLog::$actlog_table);
	}

	public function process($request) {
		$settings = $this->settings;
		$params = $request->params;
		switch ($request->method) {
		case "truncactlogtable":
			$resp = array("status" => $this->db->truncateBVTable(BVWPActLog::$actlog_table));
			break;
		case "dropactlogtable":
			$resp = array("status" => $this->dropActLogTable());
			break;
		case "createactlogtable":
			$usedbdelta = array_key_exists('usedbdelta', $params);
			$resp = array("status" => $this->createActLogTable($usedbdelta));
			break;
		case "alteractlogtable":
			$resp = array("status" => $this->alterActLogTable());
			break;
		default:
			$resp = false;
		}
		return $resp;
	}
}
endif;
