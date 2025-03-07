<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWPSiteInfo')) :

class WPRWPSiteInfo {
	public function wpurl() {
		if (function_exists('network_site_url'))
			return network_site_url();
		else
			return get_bloginfo('wpurl');
	}

	public function siteurl($path = '', $scheme = null) {
		if (function_exists('site_url')) {
			return site_url($path, $scheme);
		} else {
			return get_bloginfo('wpurl');
		}
	}

	public function homeurl() {
		if (function_exists('home_url')) {
			return home_url();
		} else {
			return get_bloginfo('url');
		}
	}

	public function isMultisite() {
		if (function_exists('is_multisite') && is_multisite())
			return true;
		return false;
	}

	public function isMainSite() {
		if (!function_exists('is_main_site' ) || !$this->isMultisite())
			return true;
		return is_main_site();
	}

	public function getMainSiteId() {
		if (!function_exists('get_main_site_id'))
			return 0;
		return get_main_site_id();
	}

	public function info() {
		$info = array();
		$this->basic($info);
		$info['dbsig'] = $this->dbsig(false);
		$info["serversig"] = $this->serversig(false);
		return $info;
	}

	public function basic(&$info) {
		$info['wpurl'] = $this->wpurl();
		$info['siteurl'] = $this->siteurl();
		$info['homeurl'] = $this->homeurl();
		if (array_key_exists('SERVER_ADDR', $_SERVER)) {
			$info['serverip'] = WPRHelper::getRawParam('SERVER', 'SERVER_ADDR');
		}

		$info['abspath'] = ABSPATH;
	}

	public function serversig($full = false) {
		$sig_param = ABSPATH;
		$server_addr = WPRHelper::getRawParam('SERVER', 'SERVER_ADDR');
		if (isset($server_addr)) {
			$sig_param = $server_addr . ABSPATH;
		}
		$sig = sha1($sig_param);
		if ($full)
			return $sig;
		else
			return substr($sig, 0, 6);
	}

	public function dbsig($full = false) {
		if (defined('DB_USER') && defined('DB_NAME') &&
			defined('DB_PASSWORD') && defined('DB_HOST')) {
			$sig = sha1(DB_USER.DB_NAME.DB_PASSWORD.DB_HOST);
		} else {
			$sig = "bvnone".WPRAccount::randString(34);
		}
		if ($full)
			return $sig;
		else
			return substr($sig, 0, 6);
	}

	public static function isWSKHosted() {
		$server_addr = WPRHelper::getRawParam('SERVER', 'SERVER_ADDR');
		if (isset($server_addr) && function_exists('gethostbyaddr')) {
			$hostFromIp = gethostbyaddr($server_addr);
			return preg_match('/webspacekit\.com/', $hostFromIp) === 1;
		}

		return false;
	}
}
endif;