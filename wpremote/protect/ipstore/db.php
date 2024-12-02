<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectIpstoreDB_V585')) :
class WPRProtectIpstoreDB_V585 {
		const TABLE_NAME = 'ip_store';

		const CATEGORY_FW = 3;
		const CATEGORY_LP = 4;

		#XNOTE: check this. 
		public static function blacklistedTypes() {
			return WPRProtectRequest_V585::blacklistedCategories();
		}

		public static function whitelistedTypes() {
			return WPRProtectRequest_V585::whitelistedCategories();
		}

		public static function uninstall() {
			WPRProtect_V585::$db->dropBVTable(WPRProtectIpstoreDB_V585::TABLE_NAME);
		}

		public function isLPIPBlacklisted($ip) {
			return $this->checkIPPresent($ip, self::blacklistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_LP);
		}

		public function isLPIPWhitelisted($ip) {
			return $this->checkIPPresent($ip, self::whitelistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_LP);
		}

		public function getTypeIfBlacklistedIP($ip) {
			return $this->getIPType($ip, self::blacklistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_FW);
		}

		public function isFWIPBlacklisted($ip) {
			return $this->checkIPPresent($ip, self::blacklistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_FW);
		}

		public function isFWIPWhitelisted($ip) {
			return $this->checkIPPresent($ip, self::whitelistedTypes(), WPRProtectIpstoreDB_V585::CATEGORY_FW);
		}

		private function checkIPPresent($ip, $types, $category) {
			$ip_category = $this->getIPType($ip, $types, $category);

			return isset($ip_category) ? true : false;
		}

		#XNOTE: getIPCategory or getIPType?
		private function getIPType($ip, $types, $category) {
			$table = WPRProtect_V585::$db->getBVTable(WPRProtectIpstoreDB_V585::TABLE_NAME);

			if (WPRProtect_V585::$db->isTablePresent($table)) {
				$binIP = WPRProtectUtils_V585::bvInetPton($ip);
				$is_v6 = WPRProtectUtils_V585::isIPv6($ip);

				if ($binIP !== false) {
					$query_str = "SELECT * FROM %i WHERE %s >= `start_ip_range` AND %s <= `end_ip_range` AND ";
					if ($category == WPRProtectIpstoreDB_V585::CATEGORY_FW) {
						$query_str .= "`is_fw` = true";
					} else {
						$query_str .= "`is_lp` = true";
					}
					$query_str .= " AND `type` IN (" . implode(',', array_fill(0, count($types), '%d')) . ") AND `is_v6` = %d LIMIT 1;";

					$query_args = array_merge(
						array($table, $binIP, $binIP),
						$types,
						array($is_v6)
					);

					return WPRProtect_V585::$db->getVar($query_str, $query_args, 5);
				}
			}
		}
	}
endif;