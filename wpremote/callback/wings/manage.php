<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVManageCallback')) :
class BVManageCallback extends BVCallbackBase {
	public $settings;
	public $skin;
	public $bvinfo;

	const MANAGE_WING_VERSION = 1.7;

	public function __construct($callback_handler) {
		$this->settings = $callback_handler->settings;
		$this->bvinfo = new WPRInfo($this->settings);
	}

	function getError($err) {
		return $this->objectToArray($err);
	}	

	function is_pantheon() {
		return (!empty($_ENV['PANTHEON_ENVIRONMENT']) && $_ENV['PANTHEON_ENVIRONMENT'] !== 'dev');
	}

	function isServerWritable() {
		if ($this->is_pantheon()) {
			return false;
		}

		if ((!defined('FTP_HOST') || !defined('FTP_USER')) && (get_filesystem_method(array(), false) != 'direct')) {
			return false;
		} else {
			return true;
		}
	}

	function include_files() {
		@include_once ABSPATH.'wp-admin/includes/file.php';
		@include_once ABSPATH.'wp-admin/includes/plugin.php';
		@include_once ABSPATH.'wp-admin/includes/theme.php';
		@include_once ABSPATH.'wp-admin/includes/misc.php';
		@include_once ABSPATH.'wp-admin/includes/template.php';
		@include_once ABSPATH.'wp-includes/pluggable.php';
		@include_once ABSPATH.'wp-admin/includes/class-wp-upgrader.php';
		@include_once ABSPATH.'wp-admin/includes/class-theme-upgrader.php';
		@include_once ABSPATH.'wp-admin/includes/class-plugin-upgrader.php';
		@include_once ABSPATH.'wp-admin/includes/user.php';
		@include_once ABSPATH.'wp-admin/includes/upgrade.php';
		@include_once ABSPATH.'wp-admin/includes/update.php';
		@require_once ABSPATH.'wp-admin/includes/update-core.php';
	}

	function edit($args) {
		$result = array();
		if ($args['type'] == 'plugins') {
			$result['plugins'] = $this->editPlugins($args);
		} elseif ($args['type'] == 'themes') {
			$result['themes'] = $this->editThemes($args);
		} elseif ($args['type'] == 'users') {
			$result['users'] = $this->editWpusers($args);
		}
		return $result;
	}

	function editPlugins($args) {
		$result = array();
		$plugins = $args['items'];
		foreach ($plugins as $plugin) {
			if (array_key_exists('network', $plugin)) {
				$networkwide = $plugin['network'];
			} else {
				$networkwide = false;
			}
			switch ($args['action']) {
			case 'activate':
				$res = activate_plugin($plugin['file'], '', $networkwide);
				break;
			case 'deactivate':
				$res = deactivate_plugins(array($plugin['file']), false, $networkwide);
				break;
			case 'delete':
				$res = delete_plugins(array($plugin['file']));
				break;
			case 'deactivate_delete':
				$res = deactivate_plugins(array($plugin['file']), false, $networkwide);
				if ($res || is_wp_error($res))
					break;
				$res = delete_plugins(array($plugin['file']));
			default:
				break;
			}
			if (is_wp_error($res)) {
				$res = array('status' => "Error", 'message' => $res->get_error_message());
			} elseif ($res === false) {
				$res = array('status' => "Error", 'message' => "Failed to perform action.");
			} else {
				$res = array('status' => "Done");
			}
			$result[$plugin['file']] = $res;
		}
		return $result;
	}

	function editThemes($args) {
		$result = array();
		$themes = $args['items'];
		foreach ($themes as $theme) {
			switch ($args['action']) {
			case 'activate':
				$res = switch_theme($theme['template'], $theme['stylesheet']);
				break;
			case 'delete':
				$res = delete_theme($theme['stylesheet']);
				break;
			default:
				break;
			}

			if (is_wp_error($res)) {
				$res = array('status' => "Error", 'message' => $res->get_error_message());
			} elseif ($res === false) {
				$res = array('status' => "Error", 'message' => "Failed to perform action.");
			} else {
				$res = array( 'status' => "Done");
			}
			$result[$theme['template']] = $res;
		}
		return $result;
	}

	function editWpusers($args) {
		$result = array();
		$items = $args['items'];
		foreach ($items as $item) {
			$res = array();
			$user = get_user_by('id', $item['id']);
			if ($user) {
				switch ($args['action']) {
				case 'changerole':
					$data = array();
					$data['role'] = $item['newrole'];
					$data['ID'] = $user->ID;
					$res = wp_update_user($data);
					break;
				case 'changepass':
						$data	= array();
						$data['user_pass'] = $item['newpass'];
						$data['ID']	= $user->ID;
						$res	= wp_update_user($data);
					break;
				case 'delete':
					if (array_key_exists('reassign', $args)) {
						$user_to = get_user_by('id', $args['reassign']);
						if ($user_to != false) {
							$res = wp_delete_user($user->ID, $user_to->ID);
						} else {
							$res = array('status' => "Error", 'message' => 'Reassigned user doesnot exists');
						}
					} else {
						$res = wp_delete_user($user->ID);
					}
					break;
				}
				if (is_wp_error($res)) {
					$res = array('status' => "Error", 'message' => $res->get_error_message());
				} else {
					$res = array( 'status' => "Done");
				}
			} else {
				$res = array('status' => "Error", 'message' => "Unable to find user");
			}
			$result[$item['id']] = $res;
		}
		return $result;
	}

	function addUser($args) {
		if (username_exists($args['user_login'])) {
			return array('status' => "Error", 'message' => "Username already exists");
		}
		if (email_exists($args['user_email'])) {
			return array('status' => "Error", 'message' => "Email already exists");
		}
		$result = wp_insert_user($args);
		if ( !is_wp_error( $result ) ) {
			return array('status' => "Done", 'user_id' => $result);
		} else {
			return array('status' => "Error", 'message' => $this->getError($result));
		}
	}

	function upgrade($params = null, $has_bv_skin = false, $bv_bulk_upgrade = false) {
		$result = array();
		$premium_upgrades = array();
		if (array_key_exists('clear_filters', $params)) {
			$filters = $params['clear_filters'];
			foreach ($filters as $filter)
				remove_all_filters($filter);
		}
		if (array_key_exists('core', $params) && !empty($params['core'])) {
			$result['core'] = $this->upgradeCore($params['core']);
		}
		if (array_key_exists('translations', $params) && !empty($params['translations'])) {
			$result['translations'] = $this->upgradeTranslations($params['translations'], $has_bv_skin);
		}
		if (array_key_exists('plugins', $params) && !empty($params['plugins'])) {
			$result['plugins'] = $this->upgradePlugins($params['plugins'], $has_bv_skin, $bv_bulk_upgrade);
		}
		if (array_key_exists('themes', $params) && !empty($params['themes'])) {
			$result['themes'] = $this->upgradeThemes($params['themes'], $has_bv_skin, $bv_bulk_upgrade);
		}
		return $result;
	}

	function get_translation_updates() {
		$updates = array();
		$transients = array( 'update_core' => 'core', 'update_plugins' => 'plugin', 'update_themes' => 'theme' );
		foreach ( $transients as $transient => $type ) {
			$transient = $this->settings->getTransient( $transient );
			if ( empty( $transient->translations ) )
				continue;

			foreach ( $transient->translations as $translation ) {
				$updates[] = (object) $translation;
			}
		}
		return $updates;
	}

	function upgradeTranslations($translations, $has_bv_skin = false) {
		$language_updates = $this->get_translation_updates();
		$valid_updates = array();
		$result = array();
		if (!empty($language_updates)) {
			foreach($language_updates as $update) {
				if ($update && in_array($update->package, $translations)) {
					$valid_updates[] = $update;
				}
			}
		}
		if (!empty($valid_updates)) {
			if (class_exists('Language_Pack_Upgrader')) {
				if ($has_bv_skin) {
					require_once( "bv_upgrader_skin.php" );
					$skin = new BVUpgraderSkin("upgrade_translations");
					$this->skin = $skin;
				} else {
					$skin = new Language_Pack_Upgrader_Skin(array());
				}
				$upgrader = new Language_Pack_Upgrader($skin);
				$result = $upgrader->bulk_upgrade($valid_updates);
				if (is_array($result) && !empty($result)) {
					foreach ($result as $translate_tmp => $translate_info) {
						if (is_wp_error($translate_info) || empty($translate_info)) {
							$error = (!empty($translate_info)) ? is_wp_error($translate_info) : "Upgrade failed";
							return array('status' => "Error", 'message' => $error);
						}
					}
				}
				return array('status' => "Done");
			}
		}
		return array('status' => "Error", 'message' => "Upgrade failed");
	}

	function upgradeCore($args) {
		global $wp_filesystem, $wp_version;
		$core = $this->settings->getTransient('update_core');
		$core_update_index = intval($args['coreupdateindex']);
		if (isset($core->updates) && !empty($core->updates)) {
			$to_update = $core->updates[$core_update_index];
		} else {
			return array('status' => "Error", "message" => "Updates not available");
		}
		$resp = array("Core_Upgrader", class_exists('Core_Upgrader'));
		if (version_compare($wp_version, '3.1.9', '>')) {
			$core   = new Core_Upgrader();
			$result = $core->upgrade($to_update);
			if (is_wp_error($result)) {
				return array('status' => "Error", "message" => $this->getError($result));
			} else {
				return array('status' => 'Done');
			}
		} else {
			$resp = array("WP_Upgrader", class_exists('WP_Upgrader'));
			if (class_exists('WP_Upgrader')) {
				$upgrader = new WP_Upgrader();

				$res = $upgrader->fs_connect(
					array(
						ABSPATH,
						WP_CONTENT_DIR,
					)
				);
				if (is_wp_error($res)) {
					return array('status' => "Error", "message" => $this->getError($res));
				}

				$wp_dir = trailingslashit($wp_filesystem->abspath());

				$core_package = false;
				if (isset($to_update->package) && !empty($to_update->package)) {
					$core_package = $to_update->package;
				} elseif (isset($to_update->packages->full) && !empty($to_update->packages->full)) {
					$core_package = $to_update->packages->full;
				}

				$download = $upgrader->download_package($core_package);
				if (is_wp_error($download)) {
					return array('status' => "Error", "message" => $this->getError($download));
				}
				$working_dir = $upgrader->unpack_package($download);
				if (is_wp_error($working_dir)) {
					return array('status' => "Error", "message" => $this->getError($working_dir));
				}

				if (!$wp_filesystem->copy($working_dir.'/wordpress/wp-admin/includes/update-core.php', $wp_dir.'wp-admin/includes/update-core.php', true)) {
					$wp_filesystem->delete($working_dir, true);
					return array('status' => "Error", "message" => "Unable to move files.");
				}

				$wp_filesystem->chmod($wp_dir.'wp-admin/includes/update-core.php', FS_CHMOD_FILE);

				$result = update_core($working_dir, $wp_dir);

				if (is_wp_error($result)) {
					return array('status' => "Error", "message" => $this->getError($result));
				}
				return array('status' => 'Done');
			}
		}
	}

	function bv_plugin_bulk_upgrade($upgrader, $_plugins) {
		global $wp_version;
		$plugins = array_keys($_plugins);
		$args = array();
		$defaults = array(
			'clear_update_cache' => true,
		);
		$parsed_args = wp_parse_args($args, $defaults);
		$upgrader->init();
		$upgrader->bulk = true;
		$upgrader->upgrade_strings();
		add_filter('upgrader_clear_destination', array($upgrader, 'delete_old_plugin'), 10, 4);
		$upgrader->skin->header();
		$res = $upgrader->fs_connect(array(WP_CONTENT_DIR, WP_PLUGIN_DIR));
		if (!$res) {
			$upgrader->skin->footer();
			return false;
		}
		$upgrader->skin->bulk_header();
		$maintenance = (is_multisite() && ! empty($plugins));
		foreach ($plugins as $plugin) {
			$maintenance = $maintenance || (is_plugin_active($plugin));
		}
		if ($maintenance) {
			$upgrader->maintenance_mode(true);
		}
		$results = array();
		$upgrader->update_count = count($plugins);
		$upgrader->update_current = 0;
		foreach($plugins as $plugin) {
			$upgrader->update_current++;
			$upgrader->skin->plugin_info = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, true);
			$upgrader->skin->plugin_active = is_plugin_active($plugin);
			if ( isset( $_plugins[$plugin]['requires'] ) && function_exists('is_wp_version_compatible') && !is_wp_version_compatible( $_plugins[$plugin]['requires'] ) ) {
				$result = new WP_Error(
					'incompatible_wp_required_version',
					sprintf(
						__( 'Your WordPress version is %1$s, however the new plugin version requires %2$s.' ),
						$wp_version,
						$_plugins[$plugin]['requires']
					)
				);

				$upgrader->skin->before( $result );
				$upgrader->skin->error( $result );
				$upgrader->skin->after();
			} elseif ( isset( $_plugins[$plugin]['requires_php'] ) && function_exists('is_php_version_compatible') && !is_php_version_compatible( $_plugins[$plugin]['requires_php'] ) ) {

				$result = new WP_Error(
					'incompatible_php_required_version',
					sprintf(
						__( 'The PHP version on your server is %1$s, however the new plugin version requires %2$s.' ),
						PHP_VERSION,
						$_plugins[$plugin]['requires_php']
					)
				);

				$upgrader->skin->before( $result );
				$upgrader->skin->error( $result );
				$upgrader->skin->after();
			} else {
				add_filter('upgrader_source_selection', array($upgrader, 'check_package'));
				$result = $upgrader->run(
					array(
						'package'           => $_plugins[$plugin]['package'],
						'destination'       => WP_PLUGIN_DIR,
						'clear_destination' => true,
						'clear_working'     => true,
						'is_multi'          => true,
						'hook_extra'        => array(
							'plugin' => $plugin,
						),
					)
				);
				remove_filter('upgrader_source_selection', array($upgrader, 'check_package'));
			}
			$results[$plugin] = $result;
			if (false === $result) {
				break;
			}
		}
		$upgrader->maintenance_mode(false);
		wp_clean_plugins_cache($parsed_args['clear_update_cache']);
		do_action(
			'upgrader_process_complete',
			$upgrader,
			array(
				'action' => 'update',
				'type' => 'plugin',
				'bulk' => true,
				'plugins' => $plugins,
			)
		);
		$upgrader->skin->bulk_footer();
		$upgrader->skin->footer();
		remove_filter('upgrader_clear_destination', array($upgrader, 'delete_old_plugin'));
		$past_failure_emails = get_option('auto_plugin_theme_update_emails', array());
		foreach ($results as $plugin => $result) {
			if (!$result || is_wp_error($result) || !isset($past_failure_emails[$plugin])) {
				continue;
			}
			unset($past_failure_emails[$plugin]);
		}
		update_option('auto_plugin_theme_update_emails', $past_failure_emails);
		return $results;
	}

	function upgradePlugins($plugins, $has_bv_skin = false, $bv_bulk_upgrade = false) {
		$result = array();
		$_plugins = array();
		$plugins_by_name = array();
		foreach ($plugins as $plugin) {
			$_plugins[$plugin['file']] = [
				'package' => $plugin['package']
			];
			if (isset($plugin['requires'])) {
				$_plugins[$plugin['file']]['requires'] = $plugin['requires'];
			}

			if (isset($plugin['requires_php'])) {
				$_plugins[$plugin['file']]['requires_php'] = $plugin['requires_php'];
			}
			$plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin['file'], false, true);
			$plugins_by_name[$plugin_data['Name']] = $plugin['file'];
		}
		if (empty(array_keys($_plugins))) {
			return $result;
		}
		if (class_exists('Plugin_Upgrader')) {
			if ($has_bv_skin) {
				require_once( "bv_upgrader_skin.php" );
				$skin = new BVUpgraderSkin("plugin_upgrade", $plugins_by_name);
				$this->skin = $skin;
			} else {
				$skin = new Bulk_Plugin_Upgrader_Skin();
			}
			$upgrader = new Plugin_Upgrader($skin);

			if ($bv_bulk_upgrade) {
				$result = $this->bv_plugin_bulk_upgrade($upgrader, $_plugins);
			} else {
				$result = $upgrader->bulk_upgrade(array_keys($_plugins));
			}
			if (!is_array($result)) {
				return array('status' => "Error", 'message' =>'result is not an array');
			}
			foreach (array_keys($_plugins) as $file) {
				if (!array_key_exists($file, $result)) {
					$result[$file] = array('status' => "Error");
				} else {
					$res = $result[$file];
					if (!$res || is_wp_error($res)) {
						$result[$file] = array('status' => "Error");
					} else {
						$result[$file] = array('status' => "Done");
					}
				}
			}
		}
		return $result;
	}

	function bv_theme_bulk_upgrade($upgrader, $_themes) {
		global $wp_version;
		$themes = array_keys($_themes);
		$args = array();
		$defaults = array(
			'clear_update_cache' => true,
		);
		$parsed_args = wp_parse_args($args, $defaults);
		$upgrader->init();
		$upgrader->bulk = true;
		$upgrader->upgrade_strings();
		add_filter('upgrader_pre_install', array($upgrader, 'current_before'), 10, 2);
		add_filter('upgrader_post_install', array( $upgrader, 'current_after'), 10, 2);
		add_filter('upgrader_clear_destination', array($upgrader, 'delete_old_theme'), 10, 4);
		$upgrader->skin->header();
		$res = $upgrader->fs_connect(array(WP_CONTENT_DIR));
		if (!$res) {
			$upgrader->skin->footer();
			return false;
		}
		$upgrader->skin->bulk_header();
		$maintenance = (is_multisite() && !empty($themes));
		foreach ($themes as $theme) {
			$maintenance = $maintenance || get_stylesheet() === $theme || get_template() === $theme;
		}
		if ($maintenance) {
			$upgrader->maintenance_mode(true);
		}
		$results = array();
		$upgrader->update_count = count($themes);
		$upgrader->update_current = 0;
		foreach ($themes as $theme) {
			$upgrader->update_current++;
			$upgrader->skin->theme_info = $upgrader->theme_info($theme);
			if ( isset( $_themes[$theme]['requires'] ) && function_exists('is_wp_version_compatible') && !is_wp_version_compatible( $_themes[$theme]['requires'] ) ) {
				$result = new WP_Error(
					'incompatible_wp_required_version',
					sprintf(
						__( 'Your WordPress version is %1$s, however the new theme version requires %2$s.' ),
						$wp_version,
						$_themes[$theme]['requires']
					)
				);

				$upgrader->skin->before( $result );
				$upgrader->skin->error( $result );
				$upgrader->skin->after();
			} elseif ( isset( $_themes[$theme]['requires_php'] ) && function_exists('is_php_version_compatible') && !is_php_version_compatible( $_themes[$theme]['requires_php'] ) ) {
				$result = new WP_Error(
					'incompatible_php_required_version',
					sprintf(
						__( 'The PHP version on your server is %1$s, however the new theme version requires %2$s.' ),
						PHP_VERSION,
						$_themes[$theme]['requires_php']
					)
				);

				$upgrader->skin->before( $result );
				$upgrader->skin->error( $result );
				$upgrader->skin->after();
			} else {
				add_filter('upgrader_source_selection', array($upgrader, 'check_package'));
				$result = $upgrader->run(
					array(
						'package'           => $_themes[$theme]['package'],
						'destination'       => get_theme_root($theme),
						'clear_destination' => true,
						'clear_working'     => true,
						'is_multi'          => true,
						'hook_extra'        => array(
							'theme' => $theme,
						),
					)
				);
				remove_filter('upgrader_source_selection', array($upgrader, 'check_package'));
			}
			$results[$theme] = $result;
			if (false === $result) {
				break;
			}
		}
		$upgrader->maintenance_mode(false);
		wp_clean_themes_cache($parsed_args['clear_update_cache']);
		do_action(
			'upgrader_process_complete',
			$upgrader,
			array(
				'action' => 'update',
				'type'   => 'theme',
				'bulk'   => true,
				'themes' => $themes,
			)
		);
		$upgrader->skin->bulk_footer();
		$upgrader->skin->footer();
		remove_filter('upgrader_pre_install', array($upgrader, 'current_before'));
		remove_filter('upgrader_post_install', array($upgrader, 'current_after'));
		remove_filter('upgrader_clear_destination', array($upgrader, 'delete_old_theme'));
		$past_failure_emails = get_option('auto_plugin_theme_update_emails', array());
		foreach ($results as $theme => $result) {
			if (!$result || is_wp_error($result) || !isset($past_failure_emails[$theme])) {
				continue;
			}
			unset($past_failure_emails[$theme]);
		}
		update_option('auto_plugin_theme_update_emails', $past_failure_emails);
		return $results;
	}

	function upgradeThemes($themes, $has_bv_skin = false, $bv_bulk_upgrade = false) {
		$result  = array();
		$_themes = array();
		foreach ($themes as $theme) {
			$_themes[$theme['stylesheet']] = [
				'package' => $theme['package']
			];
			if (isset($theme['requires'])) {
				$_themes[$theme['stylesheet']]['requires'] = $theme['requires'];
			}
			if (isset($theme['requires_php'])) {
				$_themes[$theme['stylesheet']]['requires_php'] = $theme['requires_php'];
			}
		}
		if (empty(array_keys($_themes))) {
			return $result;
		}
		if (class_exists('Theme_Upgrader')) {
			if ($has_bv_skin) {
				require_once( "bv_upgrader_skin.php" );
				$skin = new BVUpgraderSkin("theme_upgrade");
				$this->skin = $skin;
			} else {
				$skin = new Bulk_Theme_Upgrader_Skin();
			}
			$upgrader = new Theme_Upgrader($skin);
			if ($bv_bulk_upgrade) {
				$result = $this->bv_theme_bulk_upgrade($upgrader, $_themes);
			} else {
				$result = $upgrader->bulk_upgrade(array_keys($_themes));
			}
			if (!is_array($result)) {
				return array('status' => "Error", 'message' =>'result is not an array');
			}
			foreach (array_keys($_themes) as $stylesheet) {
				if (!array_key_exists($stylesheet, $result)) {
					$result[$stylesheet] = array('status' => "Error");
				} else {
					$res = $result[$stylesheet];
					if (!$res || is_wp_error($res)) {
						$result[$stylesheet] = array('status' => "Error");
					} else {
						$result[$stylesheet] = array('status' => "Done");
					}
				}
			}
		}
		return $result;
	}

	function install($params, $has_bv_skin = false) {
		$result = array();
		if (isset($params['plugins'])) {
			foreach ($params['plugins'] as $plugin) {
				if (!array_key_exists('plugins', $result))
					$result["plugins"] = array();
				$plugin['dest'] = WP_PLUGIN_DIR;
				$res = $this->installPackage("plugin", $plugin, $has_bv_skin);
				$pluginName = $plugin['package'];
				$result["plugins"][$pluginName] = $res;
			}
		}
		if (isset($params['themes'])) {
			foreach ($params['themes'] as $theme) {
				if (!array_key_exists('themes', $result))
					$result["themes"] = array();
				$theme['dest'] = WP_CONTENT_DIR.'/themes';
				$res = $this->installPackage("theme", $theme, $has_bv_skin);
				$themeName = $theme['package'];
				$result["themes"][$themeName] = $res;
			}
		}
		return $result;
	}

	function installPackage($type, $params, $has_bv_skin = false) {
		global $wp_filesystem;

		if (!isset($params['package']) || empty($params['package'])) {
			return array('status' => "Error", 'message' => "No package is sent");
		}
		$valid_domain_regex = "/^(http|https):\/\/[\-\w]*\.(blogvault\.net|w\.org|wp\.org|wordpress\.org)\//";
		if (WPRHelper::safePregMatch($valid_domain_regex, $params['package']) !== 1) {
			return array('status' => "Error", 'message' => "Invalid package domain");
		}
		if ($has_bv_skin) {
			require_once( "bv_upgrader_skin.php" );
			$skin = new BVUpgraderSkin("installer", array(), $params['package']);
			$this->skin = $skin;
		} else {
			$skin = new WP_Upgrader_Skin();
		}	
		if ("plugin" === $type) {
			$upgrader = new Plugin_Upgrader($skin);
		} elseif ("theme" === $type) {
			$upgrader = new Theme_Upgrader($skin);
		} else {
			$upgrader = new WP_Upgrader($skin);
		}
		$upgrader->init();
		$destination = $params['dest'];
		$clear_destination = isset($params['cleardest']) ? $params['cleardest'] : false;
		$package_url = $params['package'];
		$key = basename($package_url);
		add_filter('upgrader_source_selection', array($upgrader, 'check_package'));
		$res = $upgrader->run(
			array(
				'package' => $package_url,
				'destination' => $destination,
				'clear_destination' => $clear_destination,
				'clear_working' => true,
				'hook_extra' => array(
					"type" => $type,
					"action" => "install"
				),
			)
		);
		remove_filter('upgrader_source_selection', array($upgrader, 'check_package'));
		if (is_wp_error($res)) {
			$res = array('status' => "Error", 'message' => $this->getError($res));
		} else {
			$res = array( 'status' => "Done");
		}
		return $res;
	}

	function getPremiumUpdates() {
		return apply_filters( 'mwp_premium_update_notification', array() );
	}

	function getPremiumUpgradesInfo() {
		return apply_filters( 'mwp_premium_perform_update', array() );
	}

	function autoLogin($username, $isHttps) {
		$user = get_user_by('login', $username);
		if ($user != FALSE) {
			wp_set_current_user( $user->ID );
			if ($isHttps) {
				wp_set_auth_cookie( $user->ID, false, true );
			} else {
				# As we are not sure about wp-cofig.php settings for sure login
				wp_set_auth_cookie( $user->ID, false, true );
				wp_set_auth_cookie( $user->ID, false, false );
			}
			$redirect_to = get_admin_url();
			wp_safe_redirect( $redirect_to );
			exit;
		}
	}

	public function refreshPluginUpdates() {
		global $wp_current_filter;
		$wp_current_filter[] = 'load-update-core.php';

		wp_update_plugins();

		array_pop($wp_current_filter);

		wp_update_plugins();

		return true;
	}

	public function refreshThemeUpdates() {
		global $wp_current_filter;
		$wp_current_filter[] = 'load-update-core.php';

		wp_update_themes();

		array_pop($wp_current_filter);

		wp_update_themes();

		return true;
	}

	function upgradeElementorDB($file) {
		try {
			$managerClass = $file === "elementor/elementor.php" ? '\Elementor\Core\Upgrade\Manager' : '\ElementorPro\Core\Upgrade\Manager';

			if (!class_exists($managerClass)) {
				return array('status' => 'Error', 'error' => 'Elementor plugin not found or disabled', 'source' => 'BV');
			}

			$manager = new $managerClass();
			$required_methods = array('get_task_runner', 'should_upgrade', 'on_runner_complete',
					'get_current_version', 'get_new_version');
			foreach ($required_methods as $method) {
				if (!method_exists($manager, $method)) {
					return array('status' => 'Error', 'error' => 'Required methods are missing', 'source' => 'BV');
				}
			}

			$updateInfo = array(
				'from' => $manager->get_current_version(),
				'to' => $manager->get_new_version(),
			);

			if ($manager->should_upgrade()) {
				$callbacks = $manager->get_upgrade_callbacks();

				if (!empty($callbacks)) {
					$manager->get_task_runner()->handle_immediately($callbacks);
					$manager->on_runner_complete(true);
				}
			} else {
				return array('status' => 'Error', 'error' => 'Database Update is not available currently',
						'update_info' => $updateInfo, 'source' => 'BV');
			}

			return array('status' => 'Done', 'update_info' => $updateInfo);
		} catch (Exception $e) {
			return array('status' => 'Error', 'error' => $e->getMessage());
		}
	}

	function upgradeWoocommerceDb() {
		try {
			if (!defined('WC_ABSPATH')) {
				return array('status' => 'Error', 'error' => 'WC not found', 'source' => 'BV');
			}

			if (file_exists(WC_ABSPATH . 'includes/class-wc-install.php')) {
				include_once WC_ABSPATH . 'includes/class-wc-install.php';
			}

			if (file_exists(WC_ABSPATH . 'includes/wc-update-functions.php')) {
				include_once WC_ABSPATH . 'includes/wc-update-functions.php';
			}

			if (!class_exists('WC_Install') || !method_exists('WC_Install', 'needs_db_update') ||
					!method_exists('WC_Install', 'get_db_update_callbacks')) {
				return array('status' => 'Error', 'error' => 'WC files missing or corrupted', 'source' => 'BV');
			}

			$current_db_version = $this->settings->getOption('woocommerce_db_version');
			if (!$current_db_version) {
				return array('status' => 'Error', 'error' => 'Current WC DB version not available', 'source' => 'BV');
			}

			$latest_db_version = $this->bvinfo->getLatestWooCommerceDBVersion();
			if ($current_db_version >= $latest_db_version) {
				return array('status' => 'Error', 'error' => 'WC DB update not available', 'source' => 'BV');
			}

			$db_update_callbacks = WC_Install::get_db_update_callbacks();

			$loop = 0;
			foreach ($db_update_callbacks as $version => $update_callbacks) {
				if (version_compare($current_db_version, $version, '<')) {
					foreach ($update_callbacks as $update_callback) {
						WC()->queue()->schedule_single(
							time() + $loop,
							'woocommerce_run_update_callback',
							array('update_callback' => $update_callback),
							'woocommerce-db-updates'
						);
						$loop++;
					}
				}
			}

			$current_wc_version = WC()->version;
			if (version_compare($current_db_version, $current_wc_version, '<') &&
					!WC()->queue()->get_next('woocommerce_update_db_to_current_version')) {
				WC()->queue()->schedule_single(
					time() + $loop,
					'woocommerce_update_db_to_current_version',
					array('version' => $current_wc_version),
					'woocommerce-db-updates'
				);
			}

			return array('status' => 'Done');
		} catch (Exception $e) {
			return array('status' => 'Error', 'error' => $e->getMessage());
		}
	}

	function upgrade_db(){
		if (function_exists('wp_upgrade')) {
			wp_upgrade();
			return "Done";
		} else {
			return "NOUPGRADERFUNCTION";
		}
	}

	function process($request) {
		global $wp_filesystem;
		$this->include_files();

		if (!$this->is_pantheon() && !$wp_filesystem) {
			WP_Filesystem();
		}

		$params = $request->params;
		$resp = array();
		switch ($request->method) {
		case "adusr":
			$resp = array("adduser" => $this->addUser($params['args']));
			break;
		case "upgrde":
			$has_bv_skin = array_key_exists('bvskin', $params);
			$bv_bulk_upgrade = array_key_exists('bv_bulk_update', $params['args']);
			$resp = array("upgrades" => $this->upgrade($params['args'], $has_bv_skin, $bv_bulk_upgrade));
			break;
		case "cmbneupgrde":
			$args = $params['args'];
			$has_bv_skin = array_key_exists('bvskin', $args);
			$bv_bulk_upgrade = array_key_exists('bv_bulk_update', $args);

			$resp['upgrades'] = $this->upgrade($args['upgrades'], $has_bv_skin, $bv_bulk_upgrade);

			if (isset($args['delete_transient'])) {
				$resp['delete_transient'] = $this->settings->deleteTransient($args['delete_transient']);
			}
			if (isset($args['wp_update_plugins'])) {
				$resp['wp_update_plugins'] = $this->refreshPluginUpdates();
			}
			if (isset($args['wp_update_themes'])) {
				$resp['wp_update_themes'] = $this->refreshThemeUpdates();
			}
			break;
		case "edt":
			$resp = array("edit" => $this->edit($params['args']));
			break;
		case "instl":
			$has_bv_skin = array_key_exists('bvskin', $params); 
			$resp = array("install" => $this->install($params['args'], $has_bv_skin));
			break;
		case "getpremiumupdates":
			$resp = array("premiumupdates" => $this->getPremiumUpdates());
			break;
		case "getpremiumupgradesinfo":
			$resp = array("premiumupgradesinfo" => $this->getPremiumUpgradesInfo());
			break;
		case "wrteble":
			$resp = array("writeable" => $this->isServerWritable());
			break;
		case "atolgn":
			$isHttps = false;
			if (array_key_exists('https', $params))
				$isHttps = true;
			$resp = array("autologin" => $this->autoLogin($params['username'], $isHttps));
			break;
		case "updatedb":
			$resp = array("status" => $this->upgrade_db());
			break;
		case "updateplgndb":
			$resp = array();
			$files = $params['files'];

			foreach ($files as $file) {
				switch ($file) {
					case "woocommerce/woocommerce.php":
						$resp[$file] = $this->upgradeWoocommerceDb();
						break;
					case "elementor/elementor.php":
					case "elementor-pro/elementor-pro.php":
						$resp[$file] = $this->upgradeElementorDB($file);
						break;
				}
			}

			break;
		default:
			$resp = false;
		}
		if ($this->skin && is_array($resp)) {
			$resp = array_merge($resp, $this->skin->status);
		}
		return $resp;
	}
}
endif;