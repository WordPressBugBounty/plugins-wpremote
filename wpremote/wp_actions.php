<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWPAction')) :
	class WPRWPAction {
		public $settings;
		public $siteinfo;
		public $bvinfo;
		public $bvapi;

		public function __construct($settings, $siteinfo, $bvapi) {
			$this->settings = $settings;
			$this->siteinfo = $siteinfo;
			$this->bvapi = $bvapi;
			$this->bvinfo = new WPRInfo($settings);
		}
	
		public function activate() {
			if (!isset($_REQUEST['blogvaultkey'])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				##BVKEYSLOCATE##
			}
			if (WPRAccount::isConfigured($this->settings)) {
				/* This informs the server about the activation */
				$info = array();
				$this->siteinfo->basic($info);
				$this->bvapi->pingbv('/bvapi/activate', $info);
			} else {
				WPRAccount::setup($this->settings);
			}
		}

		public function deactivate() {
			$info = array();
			$this->siteinfo->basic($info);
			##DISABLECACHE##
			$this->process_deactivation_feedback($info);

			$this->bvapi->pingbv('/bvapi/deactivate', $info);
		}

		public static function uninstall() {
			do_action('wpr_clear_pt_config');
			do_action('wpr_clear_dynsync_config');
			##CLEARCACHECONFIG##
			do_action('wpr_clear_bv_services_config');
			do_action('wpr_clear_mu_plugin');
			do_action('wpr_clear_actlog_config');
			do_action('wpr_clear_wp_2fa_config');
			do_action('wpr_remove_bv_preload_include');
			do_action('wpr_clear_php_error_config');
		}

		public function clear_bv_services_config() {
			$this->settings->deleteOption($this->bvinfo->services_option_name);
		}

		public function clear_mu_plugin() {
			if (defined('WPMU_PLUGIN_DIR')) {
				$mu_plugin_file = WPMU_PLUGIN_DIR . '/0-wpremote-mu-plugin.php';
				if (file_exists($mu_plugin_file)) {
					@unlink($mu_plugin_file);
				}
			}
		}


		public function clear_wp_2fa_config() {
			$meta_keys = array('wpr_2fa_enabled', 'wpr_2fa_secret', 'wpr_2fa_method', 'wpr_2fa_email_challenge', 'wpr_2fa_email_rate', 'wpr_2fa_attempts');
			foreach ($meta_keys as $meta_key) {
					$this->settings->deleteMetaData('user', null, $meta_key, '', true);
			}

			$this->settings->deleteOption(WPRWP2FA::$wp_2fa_option);
		}


		##SOUNINSTALLFUNCTION##

		public function footerHandler() {
			$bvfooter = $this->settings->getOption($this->bvinfo->badgeinfo);
			if ($bvfooter) {
				echo '<div style="max-width:150px;min-height:70px;margin:0 auto;text-align:center;position:relative;">
					<a href='.esc_url($bvfooter['badgeurl']).' target="_blank" ><img src="'.esc_url(plugins_url($bvfooter['badgeimg'], __FILE__)).'" alt="'.esc_attr($bvfooter['badgealt']).'" /></a></div>';
			}
		}

		public function enqueueBrokenLinkHighlight() {
			// Read-only visual aid: this flag grants no access and executes no callback.
			if (!in_array('wpr', array('bv', 'mc', 'wpr'), true) ||
				WPRHelper::getRawParam('GET', 'bv-blc') !== '1' || is_admin() || is_feed() || (function_exists('is_embed') && is_embed())) {
				return;
			}

			// A cache that drops unknown query parameters from its key must not store this
			// page and serve the overlay to every visitor.
			if (!headers_sent()) {
				header('Cache-Control: no-store, max-age=0');
			}
			// The selection travels in the URL fragment, which browsers never send. This
			// request carries no input, so there is nothing here to read, decode or echo.
			// Share handles across plugin families so only one helper is loaded.
			wp_enqueue_style('blogvault-blc-highlight', plugins_url('broken_link_checker/highlight.css', __FILE__), array(), '1.3.1');
			wp_enqueue_script('blogvault-blc-highlight', plugins_url('broken_link_checker/highlight.js', __FILE__), array(), '1.3.1', true);
		}

		private function process_deactivation_feedback(&$info) {
			//phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			if (!isset($_GET['bv_deactivation_assets']) || !is_string($_GET['bv_deactivation_assets'])) {
				return;
			}

			$deactivation_assets = wp_unslash($_GET['bv_deactivation_assets']);
			$info['deactivation_feedback'] = base64_encode($deactivation_assets);
			//phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}

		public function removeBVPreload() {
			$pattern = "@include '" . rtrim(ABSPATH, DIRECTORY_SEPARATOR) . "/bv-preload.php" . "';";
			WPRHelper::removePatternFromWpConfig($pattern);
		}

	}
endif;
