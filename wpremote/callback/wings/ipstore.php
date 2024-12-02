<?php
if (!defined('ABSPATH')) exit;

if (!class_exists('BVIPStoreCallback')) :
require_once dirname( __FILE__ ) . '/../../protect/ipstore.php';

class BVIPStoreCallback extends BVCallbackBase {
	public $db;

	const IPSTORE_WING_VERSION = 1.4;

	public function __construct($callback_handler) {
		$this->db = $callback_handler->db;
	}

	public function updateBVTableContent($table, $value, $filter) {
		$this->db->query("UPDATE $table SET $value $filter;");
	}

	public function insertBVTableContent($table, $fields, $value) {
		$this->db->query("INSERT INTO $table $fields values $value;");
	}

	public function deleteIPs($table, $rmfilters) {
		if (is_array($rmfilters)) {
			foreach ($rmfilters as $rmfilter) {
				$rmfilter = base64_decode($rmfilter);
				$this->db->deleteBVTableContent($table, $rmfilter);
			}
		}
	}

	public function insertIPs($table, $fields, $values) {
		if (is_array($values)) {
			foreach ($values as $value) {
				$value = base64_decode($value);
				$this->insertBVTableContent($table, $fields, $value);
			}
		}
	}

	public function updateIPs($table, $value, $filters) {
		if (is_array($filters)) {
			foreach ($filters as $filter) {
				$filter = base64_decode($filter);
				$this->updateBVTableContent($table, $value, $filter);
			}
		}
	}

	public function getIPs($table, $auto_increment_offset, $types, $category) {
		$query = "SELECT `start_ip_range` FROM %i WHERE id < %d AND `type` in (" . implode(',', array_fill(0, count($types), '%d')) . ") AND ";
		$query .= ($category == WPRProtectIpstoreDB_V585::CATEGORY_FW) ? "`is_fw` = true;" : "`is_lp` = true;";

		$args = array_merge(
			array($table, $auto_increment_offset),
			$types
		);

		return $this->db->getCol($query, $args);
	}

	public function getIPStoreOffset($table, $auto_increment_offset) {
		$query = "SELECT MAX(id) FROM %i WHERE id < %d";
		$args = array($table, $auto_increment_offset);
		return intval($this->db->getVar($query, $args));
	}

	public function getIPStoreInfo($table, $auto_increment_offset) {
		$db = $this->db;
		$info = array();

		$info['fw_blacklisted_ips'] = $this->getIPs($table, $auto_increment_offset,
			WPRProtectIpstoreDB_V585::blacklistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_FW);
		$info['lp_blacklisted_ips'] = $this->getIPs($table, $auto_increment_offset,
			WPRProtectIpstoreDB_V585::blacklistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_LP);
		$info['fw_whitelisted_ips'] = $this->getIPs($table, $auto_increment_offset,
			WPRProtectIpstoreDB_V585::whitelistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_FW);
		$info['lp_whitelisted_ips'] = $this->getIPs($table, $auto_increment_offset,
			WPRProtectIpstoreDB_V585::whitelistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_LP);
		$info['ip_store_offset'] = $this->getIPStoreOffset($table, $auto_increment_offset);
		$info['country_ips_size'] = intval($db->getVar("SELECT COUNT(id) FROM %i WHERE id >= %d", array($table, $auto_increment_offset)));

		return $info;
	}

	public function process($request) {
		$db = $this->db;
		$params = $request->params;
		$table = $params['table'];
		$bvTable = $db->getBVTable($table);
		$auto_increment_offset = $params['auto_increment_offset'];
		if (!$db->isTablePresent($bvTable)) {
			$resp = array("info" => false);
		} else {
			switch ($request->method) {
			case "ipstrinfo":
				$info = $this->getIPStoreInfo($bvTable, $auto_increment_offset);
				$resp = array("info" => $info);
				break;
			case "insrtips":
				$values = $params['values'];
				$fields = $params['fields'];
				if (array_key_exists('rmfilter', $params)) {
					$db->deleteBVTableContent($table, $params['rmfilter']);
				}
				$this->insertIPs($bvTable, $fields, $values);
				$resp = array("offset" => $this->getIPStoreOffset($bvTable, $auto_increment_offset));
				break;
			case "dltips":
				$rmfilters = $params['rmfilters'];
				$this->deleteIPs($table, $rmfilters);
				$resp = array("offset" => $this->getIPStoreOffset($bvTable, $auto_increment_offset));
				break;
			case "updtips":
				$value = $params['value'];
				$filters = $params['filters'];
				$this->updateIPs($bvTable, $value, $filters);
				$resp = array("offset" => $this->getIPStoreOffset($bvTable, $auto_increment_offset));
				break;
			default:
				$resp = false;
			}
			return $resp;
		}
	}
}
endif;