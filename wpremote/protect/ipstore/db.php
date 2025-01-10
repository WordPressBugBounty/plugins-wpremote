<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectIpstoreDB_V591')) :
class WPRProtectIpstoreDB_V591 {
		const TABLE_NAME = 'ip_store';

		const CATEGORY_FW = 3;
		const CATEGORY_LP = 4;

		#XNOTE: check this. 
		public static function blacklistedTypes() {
			return WPRProtectRequest_V591::blacklistedCategories();
		}

		public static function whitelistedTypes() {
			return WPRProtectRequest_V591::whitelistedCategories();
		}

		public static function uninstall() {
			WPRProtect_V591::$db->dropBVTable(WPRProtectIpstoreDB_V591::TABLE_NAME);
		}

		public function isLPIPBlacklisted($ip) {
			return $this->checkIPPresent($ip, self::blacklistedTypes(), WPRProtectIpstoreDB_V591::CATEGORY_LP);
		}

		public function isLPIPWhitelisted($ip) {
			return $this->checkIPPresent($ip, self::whitelistedTypes(), WPRProtectIpstoreDB_V591::CATEGORY_LP);
		}

		public function getTypeIfBlacklistedIP($ip) {
			return $this->getIPType($ip, self::blacklistedTypes(), WPRProtectIpstoreDB_V591::CATEGORY_FW);
		}

		public function isFWIPBlacklisted($ip) {
			return $this->checkIPPresent($ip, self::blacklistedTypes(), WPRProtectIpstoreDB_V591::CATEGORY_FW);
		}

		public function isFWIPWhitelisted($ip) {
			return $this->checkIPPresent($ip, self::whitelistedTypes(), WPRProtectIpstoreDB_V591::CATEGORY_FW);
		}

		private function checkIPPresent($ip, $types, $category) {
			$ip_category = $this->getIPType($ip, $types, $category);

			return isset($ip_category) ? true : false;
		}

		#XNOTE: getIPCategory or getIPType?
		private function getIPType($ip, $types, $category) {
			$table = WPRProtect_V591::$db->getBVTable(WPRProtectIpstoreDB_V591::TABLE_NAME);

			if (WPRProtect_V591::$db->isTablePresent($table)) {
				$binIP = WPRProtectUtils_V591::bvInetPton($ip);
				$is_v6 = WPRProtectUtils_V591::isIPv6($ip);

				if ($binIP !== false) {
					$query_str = "SELECT * FROM $table WHERE %s >= `start_ip_range` && %s <= `end_ip_range` && ";
					if ($category == WPRProtectIpstoreDB_V591::CATEGORY_FW) {
						$query_str .= "`is_fw` = true";
					} else {
						$query_str .= "`is_lp` = true";
					}
					$query_str .= " && `type` in (" . implode(',', $types) . ") && `is_v6` = %d LIMIT 1;";

					$query = WPRProtect_V591::$db->prepare($query_str, array($binIP, $binIP, $is_v6));

					return WPRProtect_V591::$db->getVar($query, 5);
				}
			}
		}
	}
endif;