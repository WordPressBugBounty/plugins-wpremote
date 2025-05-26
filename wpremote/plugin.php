<?php
/*
Plugin Name: WP Remote
Plugin URI: https://wpremote.com
Description: Manage your WordPress site with <a href="https://wpremote.com/">WP Remote</a>.
Author: WP Remote
Author URI: https://wpremote.com
Version: 6.02
Network: True
License: GPLv2 or later
License URI: [http://www.gnu.org/licenses/gpl-2.0.html](http://www.gnu.org/licenses/gpl-2.0.html)
 */

/*  Copyright 2017  WP Remote  (email : support@wpremote.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/* Global response array */

if (!defined('ABSPATH')) exit;
##OLDWPR##

require_once dirname( __FILE__ ) . '/wp_settings.php';
require_once dirname( __FILE__ ) . '/wp_site_info.php';
require_once dirname( __FILE__ ) . '/wp_db.php';
require_once dirname( __FILE__ ) . '/wp_api.php';
require_once dirname( __FILE__ ) . '/wp_actions.php';
require_once dirname( __FILE__ ) . '/info.php';
require_once dirname( __FILE__ ) . '/account.php';
require_once dirname( __FILE__ ) . '/helper.php';
require_once dirname( __FILE__ ) . '/wp_file_system.php';
require_once dirname( __FILE__ ) . '/wp_2fa/wp_2fa.php';

require_once dirname( __FILE__ ) . '/wp_login_whitelabel.php';

##WPCACHEMODULE##


$bvsettings = new WPRWPSettings();
$bvsiteinfo = new WPRWPSiteInfo();
$bvdb = new WPRWPDb();


$bvapi = new WPRWPAPI($bvsettings);
$bvinfo = new WPRInfo($bvsettings);
$wp_action = new WPRWPAction($bvsettings, $bvsiteinfo, $bvapi);

register_uninstall_hook(__FILE__, array('WPRWPAction', 'uninstall'));
register_activation_hook(__FILE__, array($wp_action, 'activate'));
register_deactivation_hook(__FILE__, array($wp_action, 'deactivate'));


add_action('wp_footer', array($wp_action, 'footerHandler'), 100);
add_action('wpr_clear_bv_services_config', array($wp_action, 'clear_bv_services_config'));

##SOADDUNINSTALLACTION##

##DISABLE_OTHER_OPTIMIZATION_PLUGINS##

##WPCLIMODULE##
if (is_admin()) {
	require_once dirname( __FILE__ ) . '/wp_admin.php';
	$wpadmin = new WPRWPAdmin($bvsettings, $bvsiteinfo);
	add_action('admin_init', array($wpadmin, 'initHandler'));
	add_filter('all_plugins', array($wpadmin, 'initWhitelabel'));
	add_filter('plugin_row_meta', array($wpadmin, 'hidePluginDetails'), 10, 2);
	add_filter('debug_information', array($wpadmin, 'handlePluginHealthInfo'), 10, 1);
	if ($bvsiteinfo->isMultisite()) {
		add_action('network_admin_menu', array($wpadmin, 'menu'));
	} else {
		add_action('admin_menu', array($wpadmin, 'menu'));
	}
	add_filter('plugin_action_links', array($wpadmin, 'settingsLink'), 10, 2);
	add_action('admin_head', array($wpadmin, 'removeAdminNotices'), 3);
	##POPUP_ON_DEACTIVATION##
	add_action('admin_notices', array($wpadmin, 'activateWarning'));
	add_action('admin_enqueue_scripts', array($wpadmin, 'wprsecAdminMenu'));
	##ALPURGECACHEFUNCTION##
	##ALADMINMENU##
}

if ((array_key_exists('bvreqmerge', $_POST)) || (array_key_exists('bvreqmerge', $_GET))) { // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
	$_REQUEST = array_merge($_GET, $_POST); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
}

#Service active check
if ($bvinfo->config != false) {
	add_action('wpr_remove_bv_preload_include', array($wp_action, 'removeBVPreload'));
}

require_once dirname( __FILE__ ) . '/php_error_monitoring/monitoring.php';
WPRWPPHPErrorMonitoring::init();

if ($bvinfo->hasValidDBVersion()) {
	if ($bvinfo->isServiceActive('activity_log')) {
		require_once dirname( __FILE__ ) . '/wp_actlog.php';
		$bvconfig = $bvinfo->config;
		$actlog = new BVWPActLog($bvdb, $bvsettings, $bvinfo, $bvconfig['activity_log']);
		$actlog->init();
	}

	##MAINTENANCEMODULE##
}

if (WPRHelper::getRawParam('REQUEST', 'bvplugname') == "wpremote") {
	require_once dirname( __FILE__ ) . '/callback/base.php';
	require_once dirname( __FILE__ ) . '/callback/response.php';
	require_once dirname( __FILE__ ) . '/callback/request.php';
	require_once dirname( __FILE__ ) . '/recover.php';

	$pubkey = WPRHelper::getRawParam('REQUEST', 'pubkey');
	$pubkey = isset($pubkey) ? WPRAccount::sanitizeKey($pubkey) : '';
	$rcvracc = WPRHelper::getRawParam('REQUEST', 'rcvracc');

	if (isset($rcvracc)) {
		$account = WPRRecover::find($bvsettings, $pubkey);
	} else {
		$account = WPRAccount::find($bvsettings, $pubkey);
	}

	$request = new BVCallbackRequest($account, $_REQUEST, $bvsettings); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$response = new BVCallbackResponse($request->bvb64cksize);

	if ($request->authenticate() === 1) {
		$bv_frm_tstng = WPRHelper::getRawParam('REQUEST', 'bv_frm_tstng');
		if (isset($bv_frm_tstng)) {
			require_once dirname(__FILE__) . '/form_testing/form_testing.php';
			$form_testing = new BVFormTesting($_REQUEST); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$form_testing->init();

		} else {
			define('WPRBASEPATH', plugin_dir_path(__FILE__));


			require_once dirname( __FILE__ ) . '/callback/handler.php';

			$params = $request->processParams($_REQUEST); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ($params === false) {
				$response->terminate($request->corruptedParamsResp());
			}
			$request->params = $params;
			$callback_handler = new BVCallbackHandler($bvdb, $bvsettings, $bvsiteinfo, $request, $account, $response);
			if ($request->is_afterload) {
				add_action('wp_loaded', array($callback_handler, 'execute'));
			} else if ($request->is_admin_ajax) {
				add_action('wp_ajax_bvadm', array($callback_handler, 'bvAdmExecuteWithUser'));
				add_action('wp_ajax_nopriv_bvadm', array($callback_handler, 'bvAdmExecuteWithoutUser'));
			} else {
				$callback_handler->execute();
			}
		}
	} else {
		$response->terminate($request->authFailedResp());
	}
} else {
	if ($bvinfo->hasValidDBVersion()) {
		if ($bvinfo->isProtectModuleEnabled()) {
			require_once dirname( __FILE__ ) . '/protect/protect.php';
			//For backward compatibility.
			WPRProtect_V602::$settings = new WPRWPSettings();
			WPRProtect_V602::$db = new WPRWPDb();
			WPRProtect_V602::$info = new WPRInfo(WPRProtect_V602::$settings);

			add_action('wpr_clear_pt_config', array('WPRProtect_V602', 'uninstall'));

			if ($bvinfo->isActivePlugin()) {
				WPRProtect_V602::init(WPRProtect_V602::MODE_WP);
			}
		}

		if ($bvinfo->isDynSyncModuleEnabled()) {
		require_once dirname( __FILE__ ) . '/wp_dynsync.php';
		$bvconfig = $bvinfo->config;
		$dynsync = new BVWPDynSync($bvdb, $bvsettings, $bvconfig['dynsync']);
		$dynsync->init();
	}

	}
	$bv_site_settings = $bvsettings->getOption('bv_site_settings');
	if (isset($bv_site_settings)) {
		if (isset($bv_site_settings['wp_auto_updates'])) {
			$wp_auto_updates = $bv_site_settings['wp_auto_updates'];
			if (array_key_exists('block_auto_update_core', $wp_auto_updates)) {
				add_filter('auto_update_core', '__return_false' );
			}
			if (array_key_exists('block_auto_update_theme', $wp_auto_updates)) {
				add_filter('auto_update_theme', '__return_false' );
				add_filter('themes_auto_update_enabled', '__return_false' );
			}
			if (array_key_exists('block_auto_update_plugin', $wp_auto_updates)) {
				add_filter('auto_update_plugin', '__return_false' );
				add_filter('plugins_auto_update_enabled', '__return_false' );
			}
			if (array_key_exists('block_auto_update_translation', $wp_auto_updates)) {
				add_filter('auto_update_translation', '__return_false' );
			}
		}
	}

	if (is_admin()) {
		add_filter('site_transient_update_plugins', array($wpadmin, 'hidePluginUpdate'));
	}

	##THIRDPARTYCACHINGMODULE##
}

if (WPRWP2FA::isEnabled($bvsettings)) {
	$wp_2fa = new WPRWP2FA();
	$wp_2fa->init();
}

if (!empty($bvinfo->getLPWhitelabelInfo())) {
	$wp_login_whitelabel = new WPRWPLoginWhitelabel();
	$wp_login_whitelabel->init();
}

add_action('wpr_clear_wp_2fa_config', array($wp_action, 'clear_wp_2fa_config'));