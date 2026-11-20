<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVMailPoetFormHandler')) :

// MailPoet subscription forms: CAPTCHA and email bypasses for the tested form in a signed test request.
class BVMailPoetFormHandler {
	const SETTINGS_CLASS = 'MailPoet\\Settings\\SettingsController';
	const CONTAINER_CLASS = 'MailPoet\\DI\\ContainerWrapper';
	const MAILER_FACTORY_CLASS = 'MailPoet\\Mailer\\MailerFactory';
	const MAILER_CLASS = 'MailPoet\\Mailer\\Mailer';
	const MAILER_METHOD_INTERFACE = 'MailPoet\\Mailer\\Methods\\MailerMethod';

	private static $integration_hooks = array('mailpoet_segment_subscribed', 'mailpoet_subscriber_tag_added');

	private $form_id;
	private $bypass_params = array();
	private $bypass_captcha = false;
	private $bypass_email = false;

	public function __construct($form_id, $bypass_params) {
		$this->form_id = absint($form_id);
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if ($this->form_id <= 0) {
			return;
		}

		$this->bypass_captcha = array_key_exists('should_bypass_captcha', $this->bypass_params);
		$this->bypass_email = array_key_exists('should_bypass_email', $this->bypass_params);

		add_action('mailpoet_api_setup', array($this, 'prepareSubmission'), PHP_INT_MIN, 1);
	}

	/** Whether this request subscribes through the tested form (the API reads $_POST when api_version is posted). */
	private function isTestedSubmission() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if (!isset($_POST['api_version'], $_POST['endpoint'], $_POST['data']) || !is_array($_POST['data'])) {
			return false;
		}
		$method = isset($_POST['mailpoet_method']) ? $_POST['mailpoet_method'] : (isset($_POST['method']) ? $_POST['method'] : '');
		$form_id = isset($_POST['data']['form_id']) ? $_POST['data']['form_id'] : null;
		return $_POST['endpoint'] === 'subscribers' && $method === 'subscribe' && is_scalar($form_id) && absint($form_id) === $this->form_id;
		// phpcs:enable
	}

	/** Sets up the bypasses before MailPoet reads the request (mailpoet_api_setup runs first in setupAjax). */
	public function prepareSubmission() {
		if (!$this->isTestedSubmission()) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token = isset($_POST['token']) && is_string($_POST['token']) ? trim(wp_unslash($_POST['token'])) : '';
		if ($token === '' || wp_verify_nonce($token, 'mailpoet_token') === false) {
			$_POST['token'] = wp_create_nonce('mailpoet_token');
		}

		if ($this->bypass_captcha) {
			$this->overrideSettings(array('captcha' => array('type' => null)));
			add_filter('mailpoet_behavioral_signals_looks_human', array($this, 'looksHuman'), PHP_INT_MAX, 3);
		}

		add_filter('mailpoet_subscription_limit_enabled', '__return_false', PHP_INT_MAX);
		add_filter('query', array($this, 'ignoreDuplicateThrottleRecord'), PHP_INT_MAX);
		add_action('mailpoet_subscription_before_subscribe', array($this, 'forgetThrottleRecord'), PHP_INT_MAX, 3);

		$this->replaceMailer();

		foreach (self::$integration_hooks as $hook) {
			remove_all_actions($hook);
		}
	}

	public function looksHuman($result, $signals = null, $data = array()) {
		return (is_array($data) && isset($data['form_id']) && absint($data['form_id']) === $this->form_id) ? true : $result;
	}

	/** Sets values in MailPoet's in-memory settings for this request only (nothing is saved). */
	private function overrideSettings($overrides) {
		if (!class_exists(self::SETTINGS_CLASS) || !method_exists(self::SETTINGS_CLASS, 'getInstance')) {
			return false;
		}
		$settings = call_user_func(array(self::SETTINGS_CLASS, 'getInstance'));
		if (!is_object($settings)) {
			return false;
		}
		$apply = Closure::bind(function ($overrides) {
			if (!property_exists($this, 'settings') || !method_exists($this, 'ensureLoaded')) {
				return false;
			}
			$this->ensureLoaded();
			foreach ($overrides as $key => $values) {
				$current = (isset($this->settings[$key]) && is_array($this->settings[$key])) ? $this->settings[$key] : array();
				$this->settings[$key] = array_merge($current, $values);
			}
			return true;
		}, $settings, get_class($settings));
		return $apply ? $apply($overrides) : false;
	}

	/**
	 * Throttling::throttle() inserts (ip, created_at) after a check for an existing row. Two tests from the same
	 * IP in the same second (two monitored MailPoet forms) both pass the check and the second insert hits the
	 * primary key, which MailPoet reports as "An unknown error occurred". Make that insert an INSERT IGNORE.
	 */
	public function ignoreDuplicateThrottleRecord($query) {
		global $wpdb;
		if (!is_string($query) || !is_object($wpdb)) {
			return $query;
		}
		$table = $wpdb->prefix . 'mailpoet_subscriber_ips';
		return preg_replace('/^\s*INSERT\s+INTO\s+`?' . preg_quote($table, '/') . '`?/i', 'INSERT IGNORE INTO ' . $table, $query, 1);
	}

	/** Removes the IP row Throttling::throttle() just stored for this subscription. */
	public function forgetThrottleRecord($data = array(), $segment_ids = array(), $form = null) {
		global $wpdb;
		if (!is_object($form) || !method_exists($form, 'getId') || absint($form->getId()) !== $this->form_id || !is_object($wpdb)) {
			return;
		}
		$ip = (isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
		$since = isset($_SERVER['REQUEST_TIME']) ? (int) $_SERVER['REQUEST_TIME'] : time();
		if ($ip === '') {
			return;
		}
		$table = $wpdb->prefix . 'mailpoet_subscriber_ips';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE ip = %s AND created_at >= %s", $ip, gmdate('Y-m-d H:i:s', $since - 1)));
	}

	/** Puts a mailer that records (wp_mail with capture on) or drops MailPoet's direct emails for this request. */
	private function replaceMailer() {
		if (!class_exists(self::CONTAINER_CLASS) || !class_exists(self::MAILER_FACTORY_CLASS) || !class_exists(self::MAILER_CLASS) ||
				!interface_exists(self::MAILER_METHOD_INTERFACE)) {
			return false;
		}
		try {
			$factory = call_user_func(array(self::CONTAINER_CLASS, 'getInstance'))->get(self::MAILER_FACTORY_CLASS);
		} catch (Throwable $e) {
			return false;
		}
		if (!is_object($factory) || !property_exists($factory, 'defaultMailer')) {
			return false;
		}
		$class = self::MAILER_CLASS;
		$mailer = new $class(self::testMailerMethod(!$this->bypass_email));
		$set = Closure::bind(function ($mailer) {
			$this->defaultMailer = $mailer;
		}, $factory, get_class($factory));
		if ($set) {
			$set($mailer);
		}
		return true;
	}

	/**
	 * A MailPoet mailer method (anonymous class: MailPoet's MailerMethod interface only exists once MailPoet is
	 * loaded) that hands each email to wp_mail() when $to_wp_mail, else drops it, and reports it as sent.
	 */
	private static function testMailerMethod($to_wp_mail) {
		return new class($to_wp_mail) implements \MailPoet\Mailer\Methods\MailerMethod {
			private $to_wp_mail;

			public function __construct($to_wp_mail) {
				$this->to_wp_mail = $to_wp_mail;
			}

			public function send($newsletter, $subscriber, $extraParams = array()): array {
				if ($this->to_wp_mail && function_exists('wp_mail')) {
					$to = is_array($subscriber) ? (isset($subscriber['email']) ? $subscriber['email'] : '') : (string) $subscriber;
					$subject = (is_array($newsletter) && isset($newsletter['subject'])) ? (string) $newsletter['subject'] : '';
					$body = '';
					if (is_array($newsletter) && isset($newsletter['body']) && is_array($newsletter['body'])) {
						$body = isset($newsletter['body']['html']) ? (string) $newsletter['body']['html'] : (isset($newsletter['body']['text']) ? (string) $newsletter['body']['text'] : '');
					}
					wp_mail($to, $subject, $body, array('Content-Type: text/html; charset=UTF-8'));
				}
				return array('response' => true);
			}
		};
	}
}

endif;
