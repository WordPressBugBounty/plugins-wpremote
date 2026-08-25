<?php
if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWP2FA')) :

require_once dirname(__FILE__) . '/utils.php';
require_once dirname(__FILE__) . '/time_otp.php';
require_once dirname(__FILE__) . '/time_otp_login.php';
require_once dirname(__FILE__) . '/email_otp.php';
require_once dirname(__FILE__) . '/email_otp_sender.php';
require_once dirname(__FILE__) . '/email_otp_login.php';

class WPRWP2FA {
	const FLAG_META_KEY = 'wpr_2fa_enabled';
	const SECRET_META_KEY = 'wpr_2fa_secret';
	const METHOD_META_KEY = 'wpr_2fa_method';
	const EMAIL_CHALLENGE_META_KEY = 'wpr_2fa_email_challenge';
	const EMAIL_RATE_META_KEY = 'wpr_2fa_email_rate';
	const ATTEMPTS_META_KEY = 'wpr_2fa_attempts';
	const INVALID_CODE_MESSAGE = 'The 2FA code you entered is incorrect.';
	const TOOLTIP_MESSAGE = 'Please contact your administrator if you need assistance.';
	const CONTEXT_MESSAGE = 'Two-factor authentication is required in the standard sign-in page.';
	const CONFIG_MESSAGE = 'Please contact your administrator to login.';

	public static $cipher_algo = 'aes-256-cbc';
	public static $wp_2fa_option = 'wprWp2faConf';
	
	private static $whitelabel = null;

	public static function whitelabelMessage($key, $default) {
		if (self::$whitelabel === null) {
			$info = new WPRInfo(new WPRWPSettings());
			$values = $info->getLPWhitelabelInfo();
			self::$whitelabel = is_array($values) ? $values : array();
		}

		return (isset(self::$whitelabel[$key]) && is_string(self::$whitelabel[$key])) ? self::$whitelabel[$key] : $default;
	}

	# Sent as a JSON failure rather than returned as a WP_Error. These are system
	# states, not wrong credentials, and a WP_Error would be recorded as a failed
	# login against the firewall's lockout counter.
	public static function sendFailure($message, $data = array()) {
		wp_send_json_error(array_merge($data, array('message' => $message)));
		exit;
	}

	public static function humanWait($seconds) {
		if ($seconds < 90) {
			return sprintf('%d seconds', max(1, intval($seconds)));
		}

		return sprintf('%d minutes', intval(ceil($seconds / MINUTE_IN_SECONDS)));
	}

	public static function isEnabled($settings) {
		$config = $settings->getOption(self::$wp_2fa_option);

		return (is_array($config) && array_key_exists('enabled', $config) &&
				$config['enabled'] === true);
	}

	public function init() {
		add_filter('authenticate', array($this, 'authenticate'), 25, 3);
		add_action('login_form', array($this, 'custom_login_form'));
		add_action('login_enqueue_scripts', array($this, 'enqueue_login_assets'));
	}

	public function enqueue_login_assets() {
		wp_enqueue_style('WPR-wp-2fa-login', plugin_dir_url(__FILE__) . 'css/login.css', array(), '1.4');
		wp_enqueue_script('WPR-wp-2fa-login', plugin_dir_url(__FILE__) . 'js/login.js', array(), '1.4', true);
	}

	public function authenticate($user, $username, $password) {
		if (!($user instanceof WP_User)) {
			return $user;
		}

		if ('1' !== get_user_meta($user->ID, self::FLAG_META_KEY, true)) {
			return $user;
		}

		if (!self::isInteractiveLogin()) {
			return new WP_Error('twofa_context', self::CONTEXT_MESSAGE);
		}

		$method = get_user_meta($user->ID, self::METHOD_META_KEY, true);
		if ($method === 'email_otp') {
			return WPRWP2FAEmailOTPLogin::authenticate($user);
		}
		if ($method !== '' && $method !== 'totp') {
			self::sendFailure(self::CONFIG_MESSAGE);
		}

		return WPRWP2FATimeOTPLogin::authenticate($user);
	}

	private static function isInteractiveLogin() {
		global $pagenow;

		if ((defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) ||
				(defined('REST_REQUEST') && REST_REQUEST) ||
				(defined('WP_CLI') && WP_CLI)) {
			return false;
		}

		return $pagenow === 'wp-login.php';
	}

	function custom_login_form() {
		$tooltip_message = self::whitelabelMessage('2fa_tooltip', self::TOOLTIP_MESSAGE);
		$is_url = filter_var($tooltip_message, FILTER_VALIDATE_URL);
		$allowed_tooltip_html = array(
			'a' => array(
				'class' => true,
				'href' => true,
				'rel' => true,
				'target' => true
			),
			'span' => array(
				'class' => true,
				'id' => true,
				'title' => true
			)
		);

		$icon_html = '<span
					id="twofa-help-icon"
					class="dashicons dashicons-editor-help"></span>';

		if ($is_url) {
			$tooltip_html = '<a
						href="' . esc_url($tooltip_message) . '"
						target="_blank"
						rel="noopener noreferrer"
						class="twofa-help-link">' . $icon_html . '</a>';
		} else {
			$tooltip_html = '<span
						id="twofa-help-icon"
						class="dashicons dashicons-editor-help"
						title="' . esc_attr($tooltip_message) . '"></span>';
		}
?>
		<div class="wp2fa-progress-bar">
			<div class="progress-bar-inner"></div>
		</div>
		<template id="twofa-field-template">
			<p id="twofa-code-field">
				<label for="twofa-code">
					2FA Code
					<?php echo wp_kses($tooltip_html, $allowed_tooltip_html); ?>
				</label>
				<input type="text" required name="twofa_code" id="twofa-code" class="input" value="" maxlength="6" minlength="6" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code">
				<span id="twofa-destination" role="status" aria-live="polite"></span>
				<button type="button" id="twofa-resend" class="button-link">Send a new code</button>
				<span id="twofa-resend-status" role="status" aria-live="polite"></span>
			</p>
		</template>
<?php
	}
}
endif;
