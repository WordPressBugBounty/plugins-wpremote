<?php
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectIpstore_V593')) :
require_once dirname( __FILE__ ) . '/request.php';
require_once dirname( __FILE__ ) . '/ipstore/fs.php';
require_once dirname( __FILE__ ) . '/ipstore/db.php';

class WPRProtectIpstore_V593 {
	private $storage;
	private $storage_type;

	const STORAGE_TYPE_FS = 0;
	const STORAGE_TYPE_DB = 1;

	function __construct($storage_type = WPRProtectIpstore_V593::STORAGE_TYPE_DB) {
		$this->storage_type = $storage_type;
		if ($this->storage_type == WPRProtectIpstore_V593::STORAGE_TYPE_FS) {
			$this->storage = new WPRProtectIpstoreFS_V593();
		} else {
			$this->storage = new WPRProtectIpstoreDB_V593();
		}
	}

	public static function uninstall() {
		WPRProtectIpstoreDB_V593::uninstall();
	}

	public function isLPIPBlacklisted($ip) {
		if ($this->storage_type == WPRProtectIpstore_V593::STORAGE_TYPE_DB) {
			return $this->storage->isLPIPBlacklisted($ip);
		}
	}

	public function isLPIPWhitelisted($ip) {
		if ($this->storage_type == WPRProtectIpstore_V593::STORAGE_TYPE_DB) {
			return $this->storage->isLPIPWhitelisted($ip);
		}
	}

	public function getTypeIfBlacklistedIP($ip) {
		return $this->storage->getTypeIfBlacklistedIP($ip);
	}

	public function isFWIPBlacklisted($ip) {
		return $this->storage->isFWIPBlacklisted($ip);
	}

	public function isFWIPWhitelisted($ip) {
		return $this->storage->isFWIPWhitelisted($ip);
	}
}
endif;