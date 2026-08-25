<?php
if (!defined('ABSPATH')) exit;
if (!class_exists('WPRSecurityCallback')) :
	class WPRSecurityCallback extends WPRCallbackBase {
		private $settings;

		public function __construct() {
			$this->settings = new WPRWPSettings();
		}

		// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fread
		// Here we need fread as we are using popen which returns a handler
		function getCrontab() {
			$resp = array();

			if (function_exists('exec')) {
				$output = array();
				$retval = -1;
				$execRes = exec('crontab -l', $output, $retval);
				if ($execRes !== false && $execRes !== null) {
					$resp["content"] = implode("\n", $output);
					$resp["status"] = "success";
					$resp["code"] = $retval;
				}
			}
			if (empty($resp) && function_exists('popen')) {
				$handle = popen('crontab -l', 'rb');
				if ($handle) {
					$output = '';
					while (!feof($handle)) {
						$output .= fread($handle, 8192);
					}
					$resp["content"] = $output;
					$resp["status"] = "success";
					pclose($handle);
				} else {
					$resp["status"] = "failed";
				}
			}

			return $resp;
		}
		// phpcs:enable WordPress.WP.AlternativeFunctions.file_system_operations_fread

		public function setupWP2FA($secrets_by_uids, $to_encrypt, $cipher_algo, $enabled) {
			if (!is_array($secrets_by_uids) || !is_bool($to_encrypt) ||
					(!is_null($cipher_algo) && !is_string($cipher_algo)) ||
					(!is_null($enabled) && !is_bool($enabled))) {
				return array("status" => false, "message" => "Invalid parameters.");
			}
			if (count($secrets_by_uids) < 1) {
				return array("status" => false, "message" => "Invalid parameters.");
			}
			foreach ($secrets_by_uids as $user_id => $secret) {
				if (!$this->isValidUserId($user_id) || !is_string($secret)) {
					return array("status" => false, "message" => "Invalid parameters.");
				}
			}

			$result = array();
			$status = true;
			foreach ($secrets_by_uids as $user_id => $secret) {
				if ($to_encrypt === true) {
					if (empty($cipher_algo)) {
						$cipher_algo = WPRWP2FA::$cipher_algo;
					}

					if (defined('SECURE_AUTH_KEY')) {
						$encryption_result = WPRHelper::opensslEncrypt($secret, $cipher_algo, SECURE_AUTH_KEY);
						if ($encryption_result[0] === false) {
							return array("status" => false, "message" => $encryption_result[1]);
						}
						$secret = $encryption_result[1];
					} else {
						return array("status" => false, "message" => "Encryption key not found.");
					}
				}

				$secret_info = array(
					"secret" => base64_encode($secret),
					"is_encrypted" => $to_encrypt
				);

				$email_state_cleared = WPRWP2FAEmailOTP::revoke($user_id);
				$attempt_state_cleared = WPRWP2FATimeOTPLogin::clearState($user_id);
				$result[$user_id][WPRWP2FA::EMAIL_CHALLENGE_META_KEY] = $email_state_cleared;
				if (!$email_state_cleared || !$attempt_state_cleared) {
					$status = false;
					continue;
				}

				update_user_meta($user_id, WPRWP2FA::SECRET_META_KEY, $secret_info);
				$secret_saved = get_user_meta($user_id, WPRWP2FA::SECRET_META_KEY, true) === $secret_info;
				$result[$user_id][WPRWP2FA::SECRET_META_KEY] = $secret_saved;
				if (!$secret_saved) {
					$status = false;
					continue;
				}

				update_user_meta($user_id, WPRWP2FA::METHOD_META_KEY, 'totp');
				$method_saved = get_user_meta($user_id, WPRWP2FA::METHOD_META_KEY, true) === 'totp';
				$result[$user_id][WPRWP2FA::METHOD_META_KEY] = $method_saved;
				if (!$method_saved) {
					$status = false;
					continue;
				}

				update_user_meta($user_id, WPRWP2FA::FLAG_META_KEY, true);
				$flag_saved = get_user_meta($user_id, WPRWP2FA::FLAG_META_KEY, true) === '1';
				$result[$user_id][WPRWP2FA::FLAG_META_KEY] = $flag_saved;
				if (!$flag_saved) {
					$status = false;
				}
			}

			if (is_bool($enabled)) {
				$config = array("enabled" => $enabled);
				$this->settings->updateOption(WPRWP2FA::$wp_2fa_option, $config);
				$option_saved = WPRWP2FA::isEnabled($this->settings) === $enabled;
				$result[WPRWP2FA::$wp_2fa_option] = $option_saved;
				if (!$option_saved) {
					$status = false;
				}
			}

			return array("status" => $status, "result" => $result);
		}

		public function verifyWP2FACode($user_id, $code, $cipher_algo = null) {
			$encoded_secret_info = get_user_meta($user_id, WPRWP2FA::SECRET_META_KEY, true);

			$secret_info = WPRWP2FAUtils::getSecretInfo($encoded_secret_info);
			$secret = $secret_info['secret'];
			$is_secret_encrypted = $secret_info['is_encrypted'];

			if (is_null($secret) || is_null($is_secret_encrypted)) {
				return array("status" => false, "message" => "Secret and encryption status not found.");
			}

			if ($is_secret_encrypted === true) {
				if (empty($cipher_algo)) {
					$cipher_algo = WPRWP2FA::$cipher_algo;
				}

				if (defined('SECURE_AUTH_KEY')) {
					$decryption_result = WPRHelper::opensslDecrypt($secret, $cipher_algo, SECURE_AUTH_KEY);
					if ($decryption_result[0] === false) {
						return array("status" => false, "message" => $decryption_result[1]);
					}
					$secret = $decryption_result[1];
				} else {
					return array("status" => false, "message" => "Decryption key not found.");
				}
			}

			return array("status" => WPRWP2FATimeOTP::verifyCode($secret, $code, 2));
		}

		public function readWP2FAKeys($user_id) {
			$secret = get_user_meta($user_id, WPRWP2FA::SECRET_META_KEY, true);
			$enabled = get_user_meta($user_id, WPRWP2FA::FLAG_META_KEY, true);
			return array(
				"secret" => $secret,
				"enabled" => $enabled
			);
		}

		public function deleteWP2FAKeys($user_ids, $is_disable = false) {
			$result = array();
			$status = true;

			foreach ($user_ids as $user_id) {
				$secret_deleted = $this->deleteUserMetaState($user_id, WPRWP2FA::SECRET_META_KEY);
				$flag_deleted = $this->deleteUserMetaState($user_id, WPRWP2FA::FLAG_META_KEY);
				$method_deleted = $this->deleteUserMetaState($user_id, WPRWP2FA::METHOD_META_KEY);
				$email_state_deleted = WPRWP2FAEmailOTP::revoke($user_id);
				$totp_state_deleted = WPRWP2FATimeOTPLogin::clearState($user_id);
				$status = $status && $secret_deleted && $flag_deleted && $method_deleted &&
						$email_state_deleted && $totp_state_deleted;
				$result[$user_id] = array(
					WPRWP2FA::SECRET_META_KEY => $secret_deleted,
					WPRWP2FA::FLAG_META_KEY => $flag_deleted,
					WPRWP2FA::METHOD_META_KEY => $method_deleted,
					WPRWP2FA::EMAIL_CHALLENGE_META_KEY => $email_state_deleted
				);
			}

			if ($is_disable === true) {
				$this->settings->deleteOption(WPRWP2FA::$wp_2fa_option);
				$option_deleted = $this->settings->getOption(WPRWP2FA::$wp_2fa_option) === false;
				$result[WPRWP2FA::$wp_2fa_option] = $option_deleted;
				$status = $status && $option_deleted;
			}

			return array("status" => $status, "result" => $result);
		}

		private function deleteUserMetaState($user_id, $key) {
			delete_user_meta($user_id, $key);
			return !metadata_exists('user', $user_id, $key);
		}

		private function restoreEmailWP2FAMeta($user_id, $key, $value) {
			if ($value === '') {
				delete_user_meta($user_id, $key);
				if (get_user_meta($user_id, $key, true) !== '') update_user_meta($user_id, $key, '');
			} else {
				update_user_meta($user_id, $key, $value);
			}
			return get_user_meta($user_id, $key, true) === $value;
		}

		private function restoreEmailWP2FAUserState($user_id, $method, $flag) {
			$method_restored = $this->restoreEmailWP2FAMeta($user_id, WPRWP2FA::METHOD_META_KEY, $method);
			$flag_restored = $this->restoreEmailWP2FAMeta($user_id, WPRWP2FA::FLAG_META_KEY, $flag);
			return $method_restored && $flag_restored;
		}

		private function clearAuthenticatorState($user_id) {
			$secret_deleted = $this->deleteUserMetaState($user_id, WPRWP2FA::SECRET_META_KEY);
			$attempt_state_deleted = WPRWP2FATimeOTPLogin::clearState($user_id);
			return $secret_deleted && $attempt_state_deleted;
		}

		private function isValidUserId($user_id) {
			$is_integer = is_int($user_id);
			$is_integer_string = is_string($user_id) && ctype_digit($user_id);
			return ($is_integer || $is_integer_string) && intval($user_id) > 0;
		}

		public function setupEmailWP2FA($capability_version, $enabled, $targets) {
			if (!is_int($capability_version) || $capability_version !== 1 || $enabled !== true || !is_array($targets) || count($targets) < 1 || count($targets) > 100) return array('status' => false, 'outcomes' => array());
			$seen_user_ids = array();
			foreach ($targets as $target) {
				if (!is_array($target) || !isset($target['user_id']) || !is_int($target['user_id']) || $target['user_id'] < 1 || !array_key_exists('replace_existing', $target) || !is_bool($target['replace_existing']) || isset($seen_user_ids[$target['user_id']])) return array('status' => false, 'outcomes' => array());
				$seen_user_ids[$target['user_id']] = true;
			}
			if (!WPRWP2FAEmailOTP::hasSiteSecret()) {
				$outcomes = array();
				foreach ($targets as $target) {
					$outcomes[] = array('user_id' => $target['user_id'], 'status' => 'rejected', 'reason' => 'secure_secret_unavailable');
				}
				return array('status' => true, 'outcomes' => $outcomes);
			}
			$config = $this->settings->getOption(WPRWP2FA::$wp_2fa_option);
			if (!is_array($config)) $config = array();
			$config['enabled'] = true;
			$this->settings->updateOption(WPRWP2FA::$wp_2fa_option, $config);
			if (!WPRWP2FA::isEnabled($this->settings)) return array('status' => false, 'outcomes' => array());
			$outcomes = array();
			foreach ($targets as $target) {
				$user_id = isset($target['user_id']) ? $target['user_id'] : null;
				$replace = isset($target['replace_existing']) && $target['replace_existing'] === true;
				if (!is_int($user_id) || $user_id < 1) continue;
				$user = get_userdata($user_id);
				if (!$user) { $outcomes[] = array('user_id' => $user_id, 'status' => 'rejected', 'reason' => 'not_found'); continue; }
				if (!is_email($user->user_email)) { $outcomes[] = array('user_id' => $user_id, 'status' => 'rejected', 'reason' => 'invalid_email'); continue; }
				$current = get_user_meta($user_id, WPRWP2FA::METHOD_META_KEY, true);
				$has_2fa = get_user_meta($user_id, WPRWP2FA::FLAG_META_KEY, true) === '1';
				$current = ($has_2fa && $current === '') ? 'totp' : $current;
				if ($has_2fa && $current === 'email_otp') {
					$authenticator_state_cleared = $this->clearAuthenticatorState($user_id);
					$outcomes[] = array(
						'user_id' => $user_id,
						'status' => $authenticator_state_cleared ? 'already_configured' : 'rejected',
						'reason' => $authenticator_state_cleared ? null : 'persistence_failed'
					);
					continue;
				}
				if ($has_2fa && !$replace) { $outcomes[] = array('user_id' => $user_id, 'status' => 'rejected', 'reason' => 'replacement_required'); continue; }
				$previous_method = get_user_meta($user_id, WPRWP2FA::METHOD_META_KEY, true);
				$previous_flag = get_user_meta($user_id, WPRWP2FA::FLAG_META_KEY, true);
				if (!WPRWP2FAEmailOTP::revoke($user_id)) {
					$outcomes[] = array('user_id' => $user_id, 'status' => 'rejected', 'reason' => 'persistence_failed');
					continue;
				}
				update_user_meta($user_id, WPRWP2FA::METHOD_META_KEY, 'email_otp');
				update_user_meta($user_id, WPRWP2FA::FLAG_META_KEY, true);
				$method_persisted = get_user_meta($user_id, WPRWP2FA::METHOD_META_KEY, true) === 'email_otp';
				$flag_persisted = get_user_meta($user_id, WPRWP2FA::FLAG_META_KEY, true) === '1';
				if (!$method_persisted || !$flag_persisted) {
					$rollback_restored = $this->restoreEmailWP2FAUserState($user_id, $previous_method, $previous_flag);
					$reason = $rollback_restored ? 'persistence_failed' : 'rollback_failed';
					$outcomes[] = array('user_id' => $user_id, 'status' => 'rejected', 'reason' => $reason);
					continue;
				}
				# Dropped only once the switch has stuck, so the rollback above still has it.
				if (!$this->clearAuthenticatorState($user_id)) {
					$outcomes[] = array('user_id' => $user_id, 'status' => 'rejected', 'reason' => 'persistence_failed');
					continue;
				}
				$outcomes[] = array('user_id' => $user_id, 'status' => 'configured', 'reason' => null);
			}
			return array('status' => true, 'outcomes' => $outcomes);
		}

		public function process($request) {
			$params = isset($request->params) && is_array($request->params) ? $request->params : array();
			$invalid_params = array('status' => false, 'message' => 'Invalid parameters.');

			switch ($request->method) {
			case "gtcrntb":
				$resp = $this->getCrontab();
				break;
			case "stupwp2fa":
				$secrets_by_uids = array_key_exists('secrets_by_uids', $params) ? $params['secrets_by_uids'] : null;
				$to_encrypt = array_key_exists('to_encrypt', $params) ? $params['to_encrypt'] : null;
				$cipher_algo = array_key_exists('cipher_algo', $params) ? $params['cipher_algo'] : null;
				$enable_wp_2fa = array_key_exists('enable_wp_2fa', $params) ? $params['enable_wp_2fa'] : null;
				if (!is_array($secrets_by_uids) || !is_bool($to_encrypt) ||
						(!is_null($cipher_algo) && !is_string($cipher_algo)) ||
						(!is_null($enable_wp_2fa) && !is_bool($enable_wp_2fa))) {
					$resp = $invalid_params;
					break;
				}
				$resp = $this->setupWP2FA($secrets_by_uids, $to_encrypt, $cipher_algo, $enable_wp_2fa);
				break;
			case "stupemail2fa":
				$capability_version = array_key_exists('capability_version', $params) ? $params['capability_version'] : null;
				$enable_wp_2fa = array_key_exists('enable_wp_2fa', $params) ? $params['enable_wp_2fa'] : null;
				$targets = array_key_exists('targets', $params) ? $params['targets'] : null;
				$resp = $this->setupEmailWP2FA($capability_version, $enable_wp_2fa, $targets);
				break;
			case "vrfywp2fa":
				$user_id = array_key_exists('user_id', $params) ? $params['user_id'] : null;
				$code = array_key_exists('code', $params) ? $params['code'] : null;
				$cipher_algo = array_key_exists('cipher_algo', $params) ? $params['cipher_algo'] : null;
				if (!$this->isValidUserId($user_id) || !is_string($code) ||
						(!is_null($cipher_algo) && !is_string($cipher_algo))) {
					$resp = $invalid_params;
					break;
				}
				$resp = $this->verifyWP2FACode($user_id, $code, $cipher_algo);
				break;
			case "rdwp2fa":
				$user_id = array_key_exists('user_id', $params) ? $params['user_id'] : null;
				$resp = $this->isValidUserId($user_id) ? $this->readWP2FAKeys($user_id) : $invalid_params;
				break;
			case "dltewp2fa":
				$user_ids = array_key_exists('user_ids', $params) ? $params['user_ids'] : null;
				$is_disable = array_key_exists('is_disable', $params) ? $params['is_disable'] : null;
				$valid_user_ids = is_array($user_ids);
				if ($valid_user_ids) {
					foreach ($user_ids as $user_id) {
						if (!$this->isValidUserId($user_id)) {
							$valid_user_ids = false;
							break;
						}
					}
				}
				$resp = ($valid_user_ids && is_bool($is_disable)) ?
					$this->deleteWP2FAKeys($user_ids, $is_disable) : $invalid_params;
				break;
			default:
				$resp = false;
			}

			return $resp;
		}
	}
endif;
