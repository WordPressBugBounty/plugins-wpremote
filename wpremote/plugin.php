<?php
/*
Plugin Name: WP Remote
Plugin URI: https://wpremote.com
Description: Manage your WordPress site with <a href="https://wpremote.com/">WP Remote</a>.
Author: WP Remote
Author URI: https://wpremote.com
Version: 5.85
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

	if ($bvinfo->isServiceActive('maintenance_mode')) {
		require_once dirname( __FILE__ ). '/maintenance/wp_maintenance.php';
		$bvconfig = $bvinfo->config;
		$maintenance = new BVWPMaintenance($bvconfig['maintenance_mode']);
		$maintenance->init();
	}

}

if ((array_key_exists('bvplugname', $_REQUEST)) && ($_REQUEST['bvplugname'] == "wpremote")) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	require_once dirname( __FILE__ ) . '/callback/base.php';
	require_once dirname( __FILE__ ) . '/callback/response.php';
	require_once dirname( __FILE__ ) . '/callback/request.php';
	require_once dirname( __FILE__ ) . '/recover.php';

	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Recommended
	$pubkey = isset($_REQUEST['pubkey']) ? WPRAccount::sanitizeKey(wp_unslash($_REQUEST['pubkey'])) : '';

	if (array_key_exists('rcvracc', $_REQUEST)) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$account = WPRRecover::find($bvsettings, $pubkey);
	} else {
		$account = WPRAccount::find($bvsettings, $pubkey);
	}

	$request = new BVCallbackRequest($account, $_REQUEST, $bvsettings); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$response = new BVCallbackResponse($request->bvb64cksize);

	if ($request->authenticate() === 1) {
		if (array_key_exists('bv_ignr_frm_cptch', $_REQUEST)) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			#handling of Contact Forms 7
			add_filter('wpcf7_skip_spam_check', '__return_true', PHP_INT_MAX, 2);

			#handling of Formidable plugin
			add_filter('frm_is_field_hidden', '__return_true', PHP_INT_MAX, 3);

			#handling of WP Forms plugin
			add_filter('wpforms_process_bypass_captcha', '__return_true', PHP_INT_MAX, 3);

			#handling of Forminator plugin
			if (defined('WP_PLUGIN_DIR')) {
				$abstractFrontActionFilePath = WP_PLUGIN_DIR . '/forminator/library/abstracts/abstract-class-front-action.php';
				$frontActionFilePath = WP_PLUGIN_DIR . '/forminator/library/modules/custom-forms/front/front-action.php';

				if (file_exists($abstractFrontActionFilePath) && file_exists($frontActionFilePath)) {
					require_once $abstractFrontActionFilePath;
					require_once $frontActionFilePath;
					if (class_exists('Forminator_CForm_Front_Action')) {
						Forminator_CForm_Front_Action::$hidden_fields[] = "bv-stripe-";
					}
				}
			}

			#handling of CleanTalk Antispam plugin
			add_action('init', function() {
				global $apbct;
				if (isset($apbct) && is_object($apbct)) {
					$apbct->settings['forms__contact_forms_test'] = 0;
				}
			});

			#handling of Akismet plugin
			add_filter('akismet_get_api_key', function($api_key) { return null; }, PHP_INT_MAX);

			#handling of Formidable Antispam
			add_filter('frm_validate_entry', function($errors, $values, $args) {
				unset($errors['spam']); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				return $errors;
			}, PHP_INT_MAX, 3);

			#handling of Gravity Form plugin
			if (isset($_REQUEST['form_id'])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$form_id = sanitize_text_field(wp_unslash($_REQUEST['form_id'])); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				add_filter('gform_pre_validation_' . $form_id, function($form) {
					foreach ($form['fields'] as &$field) {
						if ($field['type'] === 'captcha') {
							$field->visibility = 'hidden';
						}
					}
					return $form;
				}, PHP_INT_MAX, 1);
			}
		}

		if (array_key_exists('bv_ignr_eml', $_REQUEST)) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			#handling of Gravity Form's Email
			add_filter('gform_pre_send_email', function($email_data) {
				$email_data['abort_email'] = true;
				return $email_data;
			}, PHP_INT_MAX, 1);
		}

		if (!array_key_exists('bv_ignr_frm_cptch', $_REQUEST) && !array_key_exists('bv_ignr_eml', $_REQUEST)) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
			WPRProtect_V585::$settings = new WPRWPSettings();
			WPRProtect_V585::$db = new WPRWPDb();
			WPRProtect_V585::$info = new WPRInfo(WPRProtect_V585::$settings);

			add_action('wpr_clear_pt_config', array('WPRProtect_V585', 'uninstall'));

			if ($bvinfo->isActivePlugin()) {
				WPRProtect_V585::init(WPRProtect_V585::MODE_WP);
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