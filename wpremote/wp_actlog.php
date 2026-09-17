<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVWPActLog')) :

	/*
	 * A sensor, not an interpreter. The server decides which hooks and keys are
	 * watched; each handler records what WordPress handed it and nothing more.
	 * Meaning (created, published, which setting changed) is assigned on the server.
	 */
	class BVWPActLog {

		public static $actlog_table = 'activities_store';
		# Post content and comment bodies larger than this are omitted from the row.
		const CONTENT_MAX_BYTES = 16384;
		# A serialized row larger than this is stored without content, or not at all.
		# The server refuses rows above 4 MiB and ships up to 1000 rows per request.
		const EVENT_DATA_MAX_BYTES = 32768;
		# Column widths for tables created by actlog wing 1.1+ and for tables
		# widened through the alteractlogtable callback.
		const IP_MAX_LENGTH = 50;
		const EVENT_TYPE_MAX_LENGTH = 60;

		# hook => array(handler, accepted args, priority). The server sends the hooks
		# to register; only hooks named here can ever be bound.
		public static $hooks = array(
			'wp_after_insert_post' => array('post_saved_handler', 4),
			'deleted_post' => array('post_deleted_handler', 2),
			'post_stuck' => array('post_handler'),
			'post_unstuck' => array('post_handler'),
			'wp_insert_comment' => array('comment_handler', 2),
			'edit_comment' => array('comment_handler'),
			'transition_comment_status' => array('comment_status_handler', 3),
			'created_term' => array('term_handler'),
			'edited_term' => array('term_handler'),
			'delete_term' => array('term_deleted_handler', 4),
			'user_register' => array('user_handler'),
			'profile_update' => array('user_updated_handler', 2),
			'deleted_user' => array('user_deleted_handler', 3),
			'set_user_role' => array('role_handler', 3),
			'add_user_role' => array('role_handler', 2),
			'remove_user_role' => array('role_handler', 2),
			'activated_plugin' => array('plugin_handler'),
			'deactivated_plugin' => array('plugin_handler'),
			'deleted_plugin' => array('plugin_deleted_handler', 2),
			'switch_theme' => array('theme_handler'),
			'deleted_theme' => array('theme_deleted_handler', 2),
			'wp_insert_site' => array('site_handler'),
			'wp_delete_site' => array('site_handler'),
			'wp_update_site' => array('site_updated_handler', 2),
			'wp_login' => array('login_handler', 2),
			'wp_logout' => array('logout_handler'),
			'after_password_reset' => array('password_reset_handler'),
			'upgrader_install_package_result' => array('package_result_handler', 2, PHP_INT_MAX),
			'upgrader_process_complete' => array('upgrade_handler', 2),
			'automatic_updates_complete' => array('automatic_updates_handler'),
			'_core_updated_successfully' => array('core_upgrade_handler'),
			'added_post_meta' => array('post_meta_handler', 4),
			'updated_post_meta' => array('post_meta_handler', 4),
			'deleted_post_meta' => array('post_meta_handler', 4),
			'added_user_meta' => array('user_meta_handler', 4),
			'updated_user_meta' => array('user_meta_handler', 4),
			'deleted_user_meta' => array('user_meta_handler', 4),
			'added_option' => array('option_handler', 3),
			'updated_option' => array('option_handler', 3),
			'deleted_option' => array('option_handler', 3),
			# Multisite network options (sitemeta).
			'add_site_option' => array('option_handler', 3),
			'update_site_option' => array('option_handler', 3),
			'delete_site_option' => array('option_handler', 3),
			'woocommerce_before_product_object_save' => array('product_before_save_handler'),
			'woocommerce_after_product_object_save' => array('product_saved_handler'),
			'woocommerce_new_order' => array('order_handler', 2),
			'woocommerce_before_order_object_save' => array('order_before_save_handler'),
			'woocommerce_after_order_object_save' => array('order_saved_handler'),
			'woocommerce_order_status_changed' => array('order_status_handler', 4),
			'woocommerce_trash_order' => array('order_handler'),
			'woocommerce_delete_order' => array('order_deleted_handler'),
			'trashed_post' => array('order_post_handler'),
			'untrashed_post' => array('order_post_handler'),
			'woocommerce_attribute_added' => array('attribute_handler', 2),
			'woocommerce_attribute_updated' => array('attribute_updated_handler', 3),
			'woocommerce_attribute_deleted' => array('attribute_deleted_handler', 3),
			'woocommerce_tax_rate_added' => array('tax_rate_handler', 2),
			'woocommerce_tax_rate_updated' => array('tax_rate_handler', 2),
			'woocommerce_tax_rate_deleted' => array('tax_rate_deleted_handler'),
			'woocommerce_shipping_zone_method_added' => array('shipping_method_handler', 3),
			'woocommerce_shipping_zone_method_status_toggled' => array('shipping_method_handler', 4),
			'woocommerce_shipping_zone_method_deleted' => array('shipping_method_handler', 3),
			'woocommerce_grant_product_download_access' => array('download_granted_handler'),
			'woocommerce_ajax_revoke_access_to_product_download' => array('download_revoked_handler', 4)
		);

		public $db;
		public $settings;
		public $bvinfo;
		public $request_id;
		public $config;
		public $pending_changes = array();
		public $installed_packages = array();

		public function __construct($db, $settings, $info, $config) {
			$this->db = $db;
			$this->settings = $settings;
			$this->bvinfo = $info;
			$this->request_id = WPRInfo::getRequestID();
			$this->config = is_array($config) ? $config : array();
		}

		function init() {
			add_action('wpr_clear_actlog_config', array($this, 'clearConfig'));
			foreach ($this->option('hooks') as $hook) {
				if (!is_string($hook) || !isset(self::$hooks[$hook])) continue;
				$binding = self::$hooks[$hook];
				$this->listen($hook, $binding[0], isset($binding[1]) ? $binding[1] : 1, isset($binding[2]) ? $binding[2] : 10);
			}
		}

		# Fired from the plugin's uninstall hook; this module owns its own table.
		public function clearConfig() {
			$this->db->dropBVTable(BVWPActLog::$actlog_table);
		}

		function option($key) {
			return isset($this->config[$key]) && is_array($this->config[$key]) ? $this->config[$key] : array();
		}

		function watching($hook) {
			return in_array($hook, $this->option('hooks'), true);
		}

		# Everything captured by name (post types, comment types, setting keys) is
		# selected from one server list of the same shape: allow mode captures only
		# the listed names, deny mode everything except them.
		function selected($list, $name) {
			$list = $this->option($list);
			$listed = $this->listed($list, $name);
			return isset($list['mode']) && $list['mode'] === 'deny' ? !$listed : $listed;
		}

		function listed($list, $name) {
			if (!is_string($name)) return false;
			if (isset($list['names']) && in_array($name, (array) $list['names'], true)) return true;
			foreach (isset($list['patterns']) ? (array) $list['patterns'] : array() as $pattern) {
				if (is_string($pattern) && WPRHelper::safePregMatch($pattern, $name)) return true;
			}
			return false;
		}

		/*
		 * Every hook goes through this wrapper so that a WordPress or plugin API change
		 * that breaks one handler can never break the site. Filters get their first
		 * argument back untouched when the handler fails or the event is ignored.
		 */
		function listen($hook, $handler, $accepted_args = 1, $priority = 10) {
			$self = $this;
			add_filter($hook, function() use ($self, $handler) {
				$args = func_get_args();
				$passthrough = isset($args[0]) ? $args[0] : null;
				try {
					$result = call_user_func_array(array($self, $handler), $args);
					return is_null($result) ? $passthrough : $result;
				} catch (Throwable $e) {
					return $passthrough;
				} catch (Exception $e) {
					# PHP 5 does not define Throwable, so keep the legacy exception path safe.
					return $passthrough;
				}
			}, $priority, $accepted_args);
		}

		/* ---------- snapshots ---------- */

		function get_post($post_id, $post = null, $with_details = null) {
			$post = is_null($post) ? get_post($post_id) : $post;
			$with_details = is_null($with_details) ? !empty($this->config['capture_details']) : $with_details;
			$data = array('id' => $post_id);
			if (empty($post))
				return $data;
			$data['title'] = $post->post_title;
			$data['status'] = $post->post_status;
			$data['type'] = $post->post_type;
			$data['parent_id'] = intval($post->post_parent);
			$data['url'] = get_permalink($post);
			$data['date'] = $post->post_date;
			# The reason describes site policy, not this call: identity-only snapshots
			# (comment context, settings, deletions) carry no reason on a site with details on.
			if (!in_array($post->post_type, array('post', 'page'), true)) {
				$data['detail_omission_reason'] = 'unsupported';
			} elseif (empty($this->config['capture_details'])) {
				$data['detail_omission_reason'] = 'disabled';
			} elseif ($with_details) {
				$data['slug'] = $post->post_name;
				$data['author_id'] = intval($post->post_author);
				$data['modified_date'] = $post->post_modified;
				$data['excerpt'] = $post->post_excerpt;
				$this->add_content($data, 'content', $post->post_content);
			}
			return $data;
		}

		function add_content(&$data, $key, $value) {
			$value = is_scalar($value) ? (string) $value : '';
			if (strlen($value) < self::CONTENT_MAX_BYTES)
				$data[$key] = $value;
			else
				$data[$key . '_omission_reason'] = 'too_large';
		}

		function get_comment($comment) {
			$data = array('id' => intval($comment->comment_ID), 'author' => $comment->comment_author, 'post_id' => $comment->comment_post_ID);
			if (!empty($this->config['capture_details']))
				$this->add_content($data, 'body', $comment->comment_content);
			return $data;
		}

		function get_term($term_id) {
			$term = get_term($term_id);
			$data = array('id' => $term_id);
			if (!empty($term) && !is_wp_error($term)) {
				$data['name'] = $term->name;
				$data['slug'] = $term->slug;
				$data['taxonomy'] = $term->taxonomy;
			}
			return $data;
		}

		function get_user($user, $user_id = 0) {
			$user = is_object($user) ? $user : get_userdata($user);
			$data = array('id' => !empty($user) && isset($user->ID) ? $user->ID : $user_id);
			if (!empty($user)) {
				$data['username'] = $user->user_login;
				$data['email'] = $user->user_email;
				$data['role'] = isset($user->roles) ? $user->roles : array();
			}
			return $data;
		}

		function get_order($id, $order) {
			$data = array('id' => $id);
			if (is_object($order)) {
				$data['title'] = 'Order #' . $order->get_order_number();
				$data['status'] = $order->get_status('edit');
			}
			return $data;
		}

		function get_ip($ipHeader) {
			$ip = '127.0.0.1';
			if ($ipHeader && is_array($ipHeader)) {
				if (array_key_exists($ipHeader['hdr'], $_SERVER)) {
					$_ips = preg_split("/(,| |\t)/", WPRHelper::getRawParam('SERVER', $ipHeader['hdr']));
					if (array_key_exists(intval($ipHeader['pos']), $_ips)) {
						$ip = $_ips[intval($ipHeader['pos'])];
					}
				}
			} else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
				$ip = WPRHelper::getRawParam('SERVER', 'REMOTE_ADDR');
			}

			$ip = trim($ip);
			if (WPRHelper::safePregMatch('/^\[([0-9a-fA-F:]+)\](:[0-9]+)$/', $ip, $matches)) {
				$ip = $matches[1];
			} elseif (WPRHelper::safePregMatch('/^([0-9.]+)(:[0-9]+)$/', $ip, $matches)) {
				$ip = $matches[1];
			}

			return $ip;
		}

		/* ---------- storage ---------- */

		function add_activity($event_data, $user = null) {
			$event_data['schema_version'] = 2;
			$event_data['hook'] = current_filter();
			$serialized = $this->fit($event_data);
			if ($serialized === false)
				return false;
			if (!function_exists('wp_get_current_user')) {
				@include_once(ABSPATH . "wp-includes/pluggable.php");
			}

			$user = $user ? $user : wp_get_current_user();
			$values = array();
			if (!empty($user)) {
				$values["user_id"] = $user->ID;
				$values["username"] = $user->user_login;
			}
			$values["request_id"] = $this->request_id;
			$values["site_id"] = get_current_blog_id();
			$ip_header = isset($this->config['ip_header']) ? $this->config['ip_header'] : false;
			$values["ip"] = substr($this->get_ip($ip_header), 0, self::IP_MAX_LENGTH);
			$values["event_type"] = 'bv_activity';
			$values["event_data"] = $serialized;
			$values["time"] = time();
			return $this->db->replaceIntoBVTable(BVWPActLog::$actlog_table, $values) !== false;
		}

		# Content is dropped whole, never truncated, when the row would exceed the cap.
		# Returns the serialized row, or false when even identity alone does not fit.
		function fit($event_data) {
			$serialized = maybe_serialize($event_data);
			if (strlen($serialized) <= self::EVENT_DATA_MAX_BYTES)
				return $serialized;
			foreach ($event_data as $entity => $snapshot) {
				if (!is_array($snapshot)) continue;
				foreach (array('content', 'excerpt', 'body') as $key) {
					if (!isset($snapshot[$key])) continue;
					unset($snapshot[$key]);
					$snapshot[$key . '_omission_reason'] = 'too_large';
				}
				$event_data[$entity] = $snapshot;
			}
			$serialized = maybe_serialize($event_data);
			return strlen($serialized) <= self::EVENT_DATA_MAX_BYTES ? $serialized : false;
		}

		/* ---------- posts ---------- */

		function skip_post($post) {
			return !$post || $post->post_status === 'auto-draft' || !$this->selected('post_types', $post->post_type);
		}

		# Names of the standard fields that differ are recorded as evidence; the
		# snapshots omit content the server must not see, so they cannot show it.
		const POST_FIELDS = array('post_title', 'post_content', 'post_excerpt', 'post_status', 'post_name', 'post_author',
			'post_parent', 'post_password', 'menu_order', 'comment_status', 'ping_status', 'post_date');

		function post_saved_handler($id, $post, $update, $before) {
			if ($this->skip_post($post)) return;
			$data = array('post' => $this->get_post($id, $post), 'updated' => (bool) $update);
			if ($before) {
				$data['before'] = $this->get_post($id, $before);
				$data['changed_fields'] = array();
				foreach (self::POST_FIELDS as $field) {
					if ((isset($before->$field) ? $before->$field : null) != (isset($post->$field) ? $post->$field : null)) $data['changed_fields'][] = $field;
				}
				if ($update && empty($data['changed_fields'])) return;
			}
			$this->add_activity($data);
		}

		function post_handler($post_id) {
			$post = get_post($post_id);
			if (!$this->skip_post($post)) $this->add_activity(array('post' => $this->get_post($post_id, $post, false)));
		}

		function post_deleted_handler($id, $post) {
			if ($this->watching('woocommerce_delete_order') && $this->is_stored_as_post($post)) return $this->order_post_handler($id, $post);
			if ($this->skip_post($post)) return;
			$this->add_activity(array('post' => $this->get_post($id, $post, false)));
		}

		/* ---------- comments ---------- */

		function skip_comment($comment) {
			return !$comment || !$this->selected('comment_types', $comment->comment_type);
		}

		function comment_handler($comment_id, $comment = null) {
			$comment = $comment ? $comment : get_comment($comment_id);
			if ($this->skip_comment($comment)) return;
			$this->add_activity(array(
				'comment' => $this->get_comment($comment),
				'post' => $this->get_post($comment->comment_post_ID, null, false)
			));
		}

		function comment_status_handler($new_status, $old_status, $comment) {
			if ($new_status === $old_status || $old_status === 'new' || $this->skip_comment($comment)) return;
			$this->add_activity(array(
				'comment' => $this->get_comment($comment),
				'post' => $this->get_post($comment->comment_post_ID, null, false),
				'old_status' => $old_status,
				'new_status' => $new_status
			));
		}

		/* ---------- terms, users, roles ---------- */

		function term_handler($term_id) {
			$this->add_activity(array('term' => $this->get_term($term_id)));
		}

		function term_deleted_handler($id, $tt_id, $taxonomy, $term) {
			$this->add_activity(array('term' => array('id' => $id, 'name' => $term->name, 'slug' => $term->slug, 'taxonomy' => $taxonomy)));
		}

		function user_handler($user_id) {
			$this->add_activity(array('user' => $this->get_user($user_id)));
		}

		function user_updated_handler($user_id, $old_userdata) {
			$this->add_activity(array('old_user' => $this->get_user($old_userdata, $user_id), 'user' => $this->get_user($user_id)));
		}

		function user_deleted_handler($id, $reassign, $user) {
			$this->add_activity(array('user' => $this->get_user($user, $id)));
		}

		function role_handler($id, $role, $old_roles = null) {
			$this->add_activity(array('user' => $this->get_user($id), 'role' => $role, 'old_roles' => $old_roles));
		}

		/* ---------- sessions ---------- */

		# Login and logout use the hook's subject as the actor: WordPress has already
		# cleared the current user when the logout hook fires.
		function login_handler($user_login, $user) {
			$this->add_activity(array('user' => $this->get_user($user)), $user);
		}

		function logout_handler($user_id = 0) {
			$user = get_userdata($user_id);
			$this->add_activity(array('user' => $this->get_user($user, $user_id)), $user);
		}

		function password_reset_handler($user) {
			if (!empty($user)) $this->add_activity(array('user' => $this->get_user($user)));
		}

		/* ---------- plugins, themes, sites ---------- */

		function plugin_handler($plugin) {
			$this->add_activity(array('plugin' => $plugin));
		}

		function plugin_deleted_handler($plugin, $deleted) {
			if ($deleted) $this->add_activity(array('plugin' => $plugin));
		}

		function theme_handler($theme_name) {
			$this->add_activity(array('theme' => $theme_name));
		}

		function theme_deleted_handler($stylesheet, $deleted) {
			if ($deleted) $this->add_activity(array('theme' => $stylesheet));
		}

		function get_site($site) {
			$data = array('id' => intval($site->blog_id), 'domain' => $site->domain, 'path' => $site->path, 'url' => 'https://' . $site->domain . $site->path);
			foreach (array('public', 'archived', 'spam', 'deleted') as $flag)
				$data[$flag] = isset($site->$flag) ? (bool) intval($site->$flag) : null;
			if (isset($site->blogname)) $data['name'] = $site->blogname;
			return $data;
		}

		function site_handler($site) {
			$this->add_activity(array('blog' => $this->get_site($site)));
		}

		function site_updated_handler($site, $before) {
			$data = array('blog' => $this->get_site($site), 'before' => $this->get_site($before));
			if ($data['blog'] != $data['before']) $this->add_activity($data);
		}

		/* ---------- settings: values ride along, bounded ---------- */

		# Like content, an oversized value is omitted whole and the omission recorded.
		function add_value(&$data, $key, $value) {
			if (is_null($value)) return;
			if (strlen(is_scalar($value) ? (string) $value : maybe_serialize($value)) < self::CONTENT_MAX_BYTES)
				$data[$key] = $value;
			else
				$data[$key . '_omission_reason'] = 'too_large';
		}

		function post_meta_handler($meta_ids, $post_id, $key, $value = null) {
			if (!$this->selected('post_meta', $key)) return;
			$post = get_post($post_id);
			if ($this->skip_post($post)) return;
			$data = array('key' => $key, 'post' => $this->get_post($post_id, $post, false));
			$this->add_value($data, current_filter() === 'deleted_post_meta' ? 'old_value' : 'new_value', $value);
			$this->add_activity($data);
		}

		function user_meta_handler($meta_ids, $user_id, $key, $value = null) {
			if (!$this->selected('user_meta', $key)) return;
			$data = array('key' => $key, 'user' => $this->get_user($user_id));
			$this->add_value($data, current_filter() === 'deleted_user_meta' ? 'old_value' : 'new_value', $value);
			$this->add_activity($data);
		}

		# Options and multisite network options (sitemeta). Transients are cache,
		# never activity, whatever the server selected. updated_option passes
		# (key, old, new) but update_site_option (key, new, old); the add hooks pass
		# only the new value and the delete hooks none.
		function option_handler($key, $first = null, $second = null) {
			if (strpos($key, '_transient_') === 0 || strpos($key, '_site_transient_') === 0) return;
			if (!$this->selected('option', $key)) return;
			$old = $new = null;
			switch (current_filter()) {
				case 'updated_option': list($old, $new) = array($first, $second); break;
				case 'update_site_option': list($new, $old) = array($first, $second); break;
				case 'added_option': case 'add_site_option': $new = $first; break;
			}
			$data = array('key' => $key);
			$this->add_value($data, 'old_value', $old);
			$this->add_value($data, 'new_value', $new);
			$this->add_activity($data);
		}

		/* ---------- upgrades ---------- */

		function is_relative_package_path($file) {
			return is_string($file) && $file !== '' && $file[0] !== '/' && strpos($file, '..') === false;
		}

		# Remember successful installs only. Automatic updates can still roll back
		# after this hook, so the activity is emitted at final completion.
		function package_result_handler($result, $extra) {
			if (!is_array($extra)) return $result;
			foreach (array('plugin', 'theme') as $type) {
				if (!isset($extra[$type]) || !$this->is_relative_package_path($extra[$type])) continue;
				if (is_array($result)) $this->installed_packages[$type][$extra[$type]] = true;
				else unset($this->installed_packages[$type][$extra[$type]]);
			}
			return $result;
		}

		function completed_package($type, $file) {
			if (!isset($this->installed_packages[$type][$file])) return;
			unset($this->installed_packages[$type][$file]);
			$item = $type === 'plugin' ? $this->get_plugin_data($file) : $this->get_theme_data($file);
			$this->add_activity(array('action' => 'update', 'type' => $type, $type . 's' => array($item)));
		}

		function upgrade_handler($upgrader, $data) {
			if (!is_array($data) || !isset($data['action'], $data['type']) || !in_array($data['type'], array('plugin', 'theme'), true))
				return;
			$type = $data['type'];
			if ($data['action'] === 'update') {
				if (isset($upgrader->skin) && $upgrader->skin instanceof Automatic_Upgrader_Skin) return;
				$files = isset($data[$type]) ? array($data[$type]) : (isset($data[$type . 's']) ? (array) $data[$type . 's'] : array());
				foreach ($files as $file) {
					if ($this->is_relative_package_path($file)) $this->completed_package($type, $file);
				}
			} elseif ($data['action'] === 'install' && isset($upgrader->result) && is_array($upgrader->result)) {
				$headers = $type === 'plugin' ? (isset($upgrader->new_plugin_data) ? $upgrader->new_plugin_data : array()) : (isset($upgrader->new_theme_data) ? $upgrader->new_theme_data : array());
				$this->add_activity(array('action' => 'install', 'type' => $type, $type . 's' => array($this->title_and_version($headers))));
			}
		}

		function automatic_updates_handler($results) {
			foreach (array('plugin', 'theme') as $type) {
				foreach (isset($results[$type]) ? $results[$type] : array() as $result) {
					$file = isset($result->item->$type) ? $result->item->$type : null;
					if (!$this->is_relative_package_path($file)) continue;
					if ($result->result && !is_wp_error($result->result)) $this->completed_package($type, $file);
					unset($this->installed_packages[$type][$file]);
				}
			}
		}

		function core_upgrade_handler($new_wp_version) {
			global $wp_version;
			$this->add_activity(array('type' => 'core', 'wp_core' => array('prev_version' => $wp_version, 'new_version' => $new_wp_version)));
		}

		function title_and_version($headers) {
			return array(
				'title' => isset($headers['Name']) ? $headers['Name'] : '',
				'version' => isset($headers['Version']) ? $headers['Version'] : ''
			);
		}

		function get_plugin_data($file) {
			if (!function_exists('get_plugin_data'))
				@include_once(ABSPATH . 'wp-admin/includes/plugin.php');
			$headers = defined('WP_PLUGIN_DIR') && function_exists('get_plugin_data') ? get_plugin_data(WP_PLUGIN_DIR . '/' . $file, false, false) : array();
			$item = $this->title_and_version($headers);
			$item['file'] = $file;
			$item['slug'] = strpos($file, '/') !== false ? dirname($file) : preg_replace('/\.php$/', '', $file);
			return $item;
		}

		function get_theme_data($stylesheet) {
			# Read installed headers without depending on the theme object cache.
			$headers = get_file_data(get_theme_root($stylesheet) . '/' . $stylesheet . '/style.css', array('Name' => 'Theme Name', 'Version' => 'Version'));
			$item = $this->title_and_version($headers);
			$item['stylesheet'] = $stylesheet;
			return $item;
		}

		/* ---------- WooCommerce products and orders ---------- */

		# Woo exposes pending changes only before save, so the change set is held
		# until the matching after-save hook confirms the write.
		function remember_changes($object, $allowed) {
			$fields = array_values(array_intersect(array_keys($object->get_changes()), $allowed));
			$this->pending_changes[spl_object_hash($object)] = array('new' => !$object->get_id(), 'fields' => $fields);
		}

		function take_changes($object) {
			$key = spl_object_hash($object);
			$changes = isset($this->pending_changes[$key]) ? $this->pending_changes[$key] : null;
			unset($this->pending_changes[$key]);
			return $changes && $object->get_id() ? $changes : null;
		}

		function product_before_save_handler($product) {
			$this->remember_changes($product, $this->option('product_fields'));
		}

		function product_saved_handler($product) {
			$changes = $this->take_changes($product);
			if (!$changes || (!$changes['new'] && empty($changes['fields']))) return;
			$post = array(
				'id' => $product->get_id(), 'title' => $product->get_name('edit'), 'status' => $product->get_status('edit'),
				'type' => $product->is_type('variation') ? 'product_variation' : 'product', 'parent_id' => $product->get_parent_id('edit')
			);
			$this->add_activity(array('post' => $post, 'updated' => !$changes['new'], 'changed_fields' => $changes['fields']));
		}

		function order_before_save_handler($order) {
			$this->remember_changes($order, $this->option('order_fields'));
		}

		function order_saved_handler($order) {
			$changes = $this->take_changes($order);
			if (!$changes || $changes['new'] || empty($changes['fields'])) return;
			$this->add_activity(array('order' => $this->get_order($order->get_id(), $order), 'changed_fields' => $changes['fields']));
		}

		function order_handler($id, $order = null) {
			$order = $order ? $order : (function_exists('wc_get_order') ? wc_get_order($id) : null);
			$this->add_activity(array('order' => $this->get_order($id, $order)));
		}

		function order_deleted_handler($id) {
			$this->add_activity(array('order' => array('id' => $id)));
		}

		function order_status_handler($id, $from, $to, $order) {
			$this->add_activity(array('order' => $this->get_order($id, $order), 'old_status' => $from, 'new_status' => $to));
		}

		# Orders kept in the posts table are observed through WordPress trash,
		# restore and delete, only while the order hooks are watched. With HPOS
		# these posts are only synchronization copies.
		function is_stored_as_post($post) {
			return $post && $post->post_type === 'shop_order' &&
				class_exists('\Automattic\WooCommerce\Utilities\OrderUtil') &&
				!\Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled();
		}

		function order_post_handler($id, $post = null) {
			$post = is_object($post) ? $post : get_post($id);
			if (!$this->is_stored_as_post($post)) return;
			$this->add_activity(array('order' => array('id' => $id, 'title' => 'Order #' . $id, 'status' => preg_replace('/^wc-/', '', $post->post_status))));
		}

		/* ---------- WooCommerce configuration ---------- */

		function get_attribute($attribute_id, $attribute_data) {
			$data = array('id' => $attribute_id);
			if (is_array($attribute_data)) {
				$data['name'] = isset($attribute_data['attribute_label']) ? $attribute_data['attribute_label'] : '';
				$data['slug'] = isset($attribute_data['attribute_name']) ? $attribute_data['attribute_name'] : '';
			}
			return $data;
		}

		function attribute_handler($attribute_id, $attribute_data) {
			$this->add_activity(array('attribute' => $this->get_attribute($attribute_id, $attribute_data)));
		}

		function attribute_updated_handler($attribute_id, $attribute_data, $old_slug = null) {
			$attribute = $this->get_attribute($attribute_id, $attribute_data);
			if (is_string($old_slug)) $attribute['old_slug'] = $old_slug;
			$this->add_activity(array('attribute' => $attribute));
		}

		function attribute_deleted_handler($attribute_id, $name = null, $taxonomy = null) {
			$attribute = array('id' => $attribute_id);
			if (is_string($name)) $attribute['name'] = $name;
			if (is_string($taxonomy)) $attribute['slug'] = preg_replace('/^pa_/', '', $taxonomy);
			$this->add_activity(array('attribute' => $attribute));
		}

		function tax_rate_handler($tax_rate_id, $tax_rate) {
			$data = array('id' => $tax_rate_id);
			if (is_array($tax_rate)) {
				$data['name'] = isset($tax_rate['tax_rate_name']) ? $tax_rate['tax_rate_name'] : '';
				$data['country'] = isset($tax_rate['tax_rate_country']) ? $tax_rate['tax_rate_country'] : '';
				$data['rate'] = isset($tax_rate['tax_rate']) ? $tax_rate['tax_rate'] : '';
			}
			$this->add_activity(array('tax_rate' => $data));
		}

		function tax_rate_deleted_handler($tax_rate_id) {
			$this->add_activity(array('tax_rate' => array('id' => $tax_rate_id)));
		}

		function shipping_method_handler($instance_id, $method_id, $zone_id, $enabled = null) {
			$data = array('instance_id' => absint($instance_id), 'method_id' => $method_id, 'zone_id' => $zone_id);
			if (!is_null($enabled)) $data['enabled'] = (bool) $enabled;
			$this->add_activity($data);
		}

		function download_granted_handler($data) {
			if (!is_array($data)) return;
			$event_data = array();
			foreach (array('download_id', 'user_id', 'order_id', 'product_id') as $key)
				$event_data[$key] = isset($data[$key]) ? $data[$key] : '';
			$this->add_activity($event_data);
		}

		function download_revoked_handler($download_id, $product_id, $order_id, $permission_id = null) {
			$this->add_activity(array('download_id' => $download_id, 'product_id' => $product_id, 'order_id' => $order_id, 'permission_id' => $permission_id));
		}
	}
endif;
