<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWPAdmin')) :

class WPRWPAdmin {
	public $settings;
	public $siteinfo;
	public $bvinfo;
	public $bvapi;

	function __construct($settings, $siteinfo, $bvapi = null) {
		$this->settings = $settings;
		$this->siteinfo = $siteinfo;
		$this->bvapi = new WPRWPAPI($settings);
		$this->bvinfo = new WPRInfo($this->settings);
	}

	public function mainUrl($_params = '') {
		if (function_exists('network_admin_url')) {
			return network_admin_url('admin.php?page='.$this->bvinfo->plugname.$_params);
		} else {
			return admin_url('admin.php?page='.$this->bvinfo->plugname.$_params);
		}
	}

	function removeAdminNotices() {
		if (WPRHelper::getRawParam('REQUEST', 'page') === $this->bvinfo->plugname) {
			remove_all_actions('admin_notices');
			remove_all_actions('all_admin_notices');
		}
	}

	public function initHandler() {
		if (!current_user_can('activate_plugins'))
			return;
		$bvnonce = WPRHelper::getRawParam('REQUEST', 'bvnonce');
		$blogvaultkey = WPRHelper::getRawParam('REQUEST', 'blogvaultkey');
		$blogvaultkey = $blogvaultkey ? WPRAccount::sanitizeKey($blogvaultkey) : "";

		if ($bvnonce && wp_verify_nonce($bvnonce, "bvnonce") &&
				$blogvaultkey && strlen($blogvaultkey) == 64 &&
				(WPRHelper::getRawParam('REQUEST', 'page') === $this->bvinfo->plugname)) {
			$keys = str_split($blogvaultkey, 32);
			WPRAccount::addAccount($this->settings, $keys[0], $keys[1]);

			$location = WPRHelper::getStringParamSanitized('REQUEST', 'redirect', 'url');
			if ($location) {
				wp_redirect($this->bvinfo->appUrl()."/dash/redir?q=".urlencode($location));
				exit();
			}
		}

		if ($this->bvinfo->isActivateRedirectSet()) {
			$this->settings->updateOption($this->bvinfo->plug_redirect, 'no');
			##ACTIVATEREDIRECTCODE##
			if (!wp_doing_ajax()) {
				wp_redirect($this->mainUrl());
			}
		}
	}

	public function wprsecAdminMenu($hook) {
		if ($hook === 'toplevel_page_wpremote' || WPRHelper::safePregMatch("/wpr_add_account$/", $hook) || WPRHelper::safePregMatch("/wpr_account_details$/", $hook)) {
			wp_enqueue_style( 'bootstrap', plugins_url('css/bootstrap.min.css', __FILE__), array(), $this->bvinfo->version);
			wp_enqueue_style( 'bvplugin', plugins_url('css/bvplugin.min.css', __FILE__), array(), $this->bvinfo->version);
		}
	}

	public function menu() {
		$brand = $this->bvinfo->getPluginWhitelabelInfo();
		if (!array_key_exists('hide', $brand) && !array_key_exists('hide_from_menu', $brand)) {
			$bname = $this->bvinfo->getBrandName();
			$icon = $this->bvinfo->getBrandIcon();
			add_menu_page($bname, $bname, 'manage_options', $this->bvinfo->plugname,
					array($this, 'adminPage'), plugins_url($icon,  __FILE__ ));
		}
	}

	public function hidePluginUpdate($plugins) {
		if (!$this->bvinfo->canWhiteLabel()) {
			return $plugins;
		}
		$whitelabel_infos = $this->bvinfo->getPluginsWhitelabelInfos();
		foreach ($whitelabel_infos as $slug => $brand) {
			if ($this->bvinfo->canWhiteLabel($slug) && isset($plugins->response[$slug]) && is_array($brand)) {
				if (array_key_exists('hide_from_menu', $brand) || array_key_exists('hide', $brand)) {
					unset($plugins->response[$slug]);
				}
			}
		}
		return $plugins;
	}

	public function hidePluginDetails($plugin_metas, $slug) {
		if (!is_array($plugin_metas) || !$this->bvinfo->canWhiteLabel($slug)) {
			return $plugin_metas;
		}
		$whitelabel_info = $this->bvinfo->getPluginWhitelabelInfo($slug);
		if (array_key_exists('hide_plugin_details', $whitelabel_info)) {
			foreach ($plugin_metas as $pluginKey => $pluginValue) {
				// phpcs:ignore WordPress.WP.I18n.MissingArgDomain
				if (strpos($pluginValue, sprintf('>%s<', __('View details')))) {
					unset($plugin_metas[$pluginKey]);
					break;
				}
			}
		}
		return $plugin_metas;
	}

	public function handlePluginHealthInfo($plugins) {
		if (!isset($plugins["wp-plugins-active"]) ||
			!isset($plugins["wp-plugins-active"]["fields"]) || !$this->bvinfo->canWhiteLabel()) {
			return $plugins;
		}

		$whitelabel_infos_by_title = $this->bvinfo->getPluginsWhitelabelInfoByTitle();

		foreach ($whitelabel_infos_by_title as $title => $brand) {
			if (is_array($brand) && array_key_exists('slug', $brand) && $this->bvinfo->canWhiteLabel($brand["slug"])) {
				if (array_key_exists('hide', $brand)) {
					unset($plugins["wp-plugins-active"]["fields"][$title]);
				} else {
					$plugin = $plugins["wp-plugins-active"]["fields"][$title];
					$author = $brand['default_author'];
					if (array_key_exists('name', $brand)) {
						$plugin["label"] = $brand['name'];
					}
					if (array_key_exists('author', $brand)) {
						$plugin["value"] = str_replace($author, $brand['author'], $plugin["value"]);
					}
					if (array_key_exists('description', $brand)) {
						$plugin["debug"] = str_replace($author, $brand['author'], $plugin["debug"]);
					}
					$plugins["wp-plugins-active"]["fields"][$title] = $plugin;
				}
			}
		}
		return $plugins;
	}

	public function settingsLink($links, $file) {
		#XNOTE: Fix this
		if ( $file == plugin_basename( dirname(__FILE__).'/plugin.php' ) ) {
			$brand = $this->bvinfo->getPluginWhitelabelInfo();
			if (!array_key_exists('hide_plugin_details', $brand)) {
				// phpcs:ignore WordPress.WP.I18n.MissingArgDomain
				$links[] = '<a href="'.$this->mainUrl().'">'.__('Settings').'</a>';
			}
		}
		return $links;
	}

	public function getPluginLogo() {
		$brand = $this->bvinfo->getPluginWhitelabelInfo();
		if (array_key_exists('logo', $brand)) {
			return $brand['logo'];
		}
		return $this->bvinfo->logo;
	}

	public function getWebPage() {
		$brand = $this->bvinfo->getPluginWhitelabelInfo();
		if (array_key_exists('webpage', $brand)) {
			return $brand['webpage'];
		}
		return $this->bvinfo->webpage;
	}

	public function siteInfoTags() {
		require_once dirname( __FILE__ ) . '/recover.php';
		$bvnonce = wp_create_nonce("bvnonce");
		$public = WPRAccount::getApiPublicKey($this->settings);
		$secret = WPRRecover::defaultSecret($this->settings);
		$server_ip = WPRHelper::getStringParamEscaped('SERVER', 'SERVER_ADDR', 'attr');
		$tags = "<input type='hidden' name='url' value='".esc_attr($this->siteinfo->wpurl())."'/>\n".
				"<input type='hidden' name='homeurl' value='".esc_attr($this->siteinfo->homeurl())."'/>\n".
				"<input type='hidden' name='siteurl' value='".esc_attr($this->siteinfo->siteurl())."'/>\n".
				"<input type='hidden' name='dbsig' value='".esc_attr($this->siteinfo->dbsig(false))."'/>\n".
				"<input type='hidden' name='plug' value='".esc_attr($this->bvinfo->plugname)."'/>\n".
				"<input type='hidden' name='adminurl' value='".esc_attr($this->mainUrl())."'/>\n".
				"<input type='hidden' name='bvversion' value='".esc_attr($this->bvinfo->version)."'/>\n".
				"<input type='hidden' name='serverip' value='".$server_ip."'/>\n".
				"<input type='hidden' name='abspath' value='".esc_attr(ABSPATH)."'/>\n".
				"<input type='hidden' name='secret' value='".esc_attr($secret)."'/>\n".
				"<input type='hidden' name='public' value='".esc_attr($public)."'/>\n".
				"<input type='hidden' name='bvnonce' value='".esc_attr($bvnonce)."'/>\n";
		return $tags;
	}

	public function activateWarning() {
		global $hook_suffix;
		if (!WPRAccount::isConfigured($this->settings) && $hook_suffix == 'index.php' ) {
?>
			<div id="message" class="updated" style="padding: 8px; font-size: 16px; background-color: #dff0d8">
						<a class="button-primary" href="<?php echo esc_url($this->mainUrl()); ?>">Activate WPRemote</a>
						&nbsp;&nbsp;&nbsp;<b>Almost Done:</b> Activate your WPRemote account to backup & secure your site.
			</div>
<?php
		}
	}

	public function showAddAccountPage() {
		require_once dirname( __FILE__ ) . "/admin/add_new_account.php";
	}

	public function showAccountDetailsPage() {
		require_once dirname( __FILE__ ) . "/admin/account_details.php";
	}

	public function adminPage() {
		$bvnonce = WPRHelper::getRawParam('REQUEST', 'bvnonce');
		if ($bvnonce && wp_verify_nonce($bvnonce, 'bvnonce')) {
			$info = array();
			$this->siteinfo->basic($info);

			$pubkey = WPRHelper::getRawParam('REQUEST', 'pubkey');

			if (!empty($pubkey)) {
				$pubkey = WPRAccount::sanitizeKey($pubkey);
				$this->bvapi->pingbv('/bvapi/disconnect', $info, $pubkey);
				WPRAccount::remove($this->settings, $pubkey);
			}
		}
		if (WPRAccount::isConfigured($this->settings)) {
			if (!isset($_REQUEST['add_account'])) {
				$this->showAccountDetailsPage();
			} else {
				$this->showAddAccountPage();
			}
		} else {
			$this->showAddAccountPage();
		}
	}

	public function initWhitelabel($plugins) {
		if (!is_array($plugins) || !$this->bvinfo->canWhiteLabel()) {
			return $plugins;
		}
		$whitelabel_infos = $this->bvinfo->getPluginsWhitelabelInfos();
		foreach ($whitelabel_infos as $slug => $brand) {
			if (!isset($slug) || !$this->bvinfo->canWhiteLabel($slug) || !array_key_exists($slug, $plugins) || !is_array($brand)) {
				continue;
			}
			if (array_key_exists('hide', $brand)) {
				unset($plugins[$slug]);
			} else {
				if (array_key_exists('name', $brand)) {
					$plugins[$slug]['Name'] = $brand['name'];
				}
				if (array_key_exists('title', $brand)) {
					$plugins[$slug]['Title'] = $brand['title'];
				}
				if (array_key_exists('description', $brand)) {
					$plugins[$slug]['Description'] = $brand['description'];
				}
				if (array_key_exists('authoruri', $brand)) {
					$plugins[$slug]['AuthorURI'] = $brand['authoruri'];
				}
				if (array_key_exists('author', $brand)) {
					$plugins[$slug]['Author'] = $brand['author'];
				}
				if (array_key_exists('authorname', $brand)) {
					$plugins[$slug]['AuthorName'] = $brand['authorname'];
				}
				if (array_key_exists('pluginuri', $brand)) {
					$plugins[$slug]['PluginURI'] = $brand['pluginuri'];
				}
			}
		}
		return $plugins;
	}
}
endif;