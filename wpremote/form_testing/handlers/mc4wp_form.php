<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVMc4wpFormHandler')) :

// Mailchimp for WordPress (MC4WP) sign-up forms: CAPTCHA bypass and stubbed Mailchimp calls for the tested form in a
// signed test request.
class BVMc4wpFormHandler {
	const API_HOST = 'api.mailchimp.com';
	const BOT_USER_AGENT = '/bot|crawl|spider|seo|lighthouse|facebookexternalhit|preview/i';
	const TEST_USER_AGENT = 'Mozilla/5.0 (compatible; WPRemote form test)';

	private static $captcha_errors = array('procaptcha_required');
	private static $recorder = null;
	private static $form_id_seen = '';

	private $form_id;
	private $bypass_params = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = $form_id;
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if (!self::isTestedSubmission($this->form_id)) {
			return;
		}

		self::$form_id_seen = self::postedFormId();
		$this->passAntiSpamChecks();

		add_filter('pre_http_request', array($this, 'answerMailchimpApi'), 10, 3);
		add_filter('mc4wp_form_redirect_url', array($this, 'noRedirect'), PHP_INT_MAX);
		add_action('mc4wp_form_subscribed', array($this, 'removePremiumLogging'), 0);

		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			add_filter('mc4wp_form_errors', array($this, 'removeCaptchaErrors'), PHP_INT_MAX, 1);
		}

		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			add_filter('pre_wp_mail', array($this, 'skipMail'), PHP_INT_MAX);
		}
	}

	/** The request is the MC4WP submission of the tested form (any form when no id is given). */
	public static function isTestedSubmission($form_id) {
		$posted = self::postedFormId();
		if ($posted === '') {
			return false;
		}

		return $form_id === null || $form_id === '' || (string) $form_id === $posted;
	}

	private static function postedFormId() {
		if (!isset($_POST['_mc4wp_form_id']) || !is_scalar($_POST['_mc4wp_form_id'])) {
			return '';
		}
		$id = absint($_POST['_mc4wp_form_id']);

		return $id > 0 ? (string) $id : '';
	}

	private function passAntiSpamChecks() {
		$now = time();
		$timestamp = isset($_POST['_mc4wp_timestamp']) && is_scalar($_POST['_mc4wp_timestamp']) ? intval($_POST['_mc4wp_timestamp']) : 0;
		if ($timestamp > ($now - 3) || $timestamp < ($now - 89 * DAY_IN_SECONDS)) {
			$_POST['_mc4wp_timestamp'] = (string) ($now - 5);
		}
		$_POST['_mc4wp_honeypot'] = '';

		$agent = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		if ($agent === '' || preg_match(self::BOT_USER_AGENT, $agent)) {
			$_SERVER['HTTP_USER_AGENT'] = self::TEST_USER_AGENT;
		}
	}

	/** pre_http_request: answers calls to the Mailchimp API (see the class comment). */
	public function answerMailchimpApi($preempt, $args, $url) {
		if ($preempt !== false) {
			return $preempt;
		}

		$parts = BVFormTestRecorder::parseUrl((string) $url);
		$host = (is_array($parts) && isset($parts['host'])) ? strtolower($parts['host']) : '';
		if ($host !== self::API_HOST && substr($host, -strlen('.' . self::API_HOST)) !== '.' . self::API_HOST) {
			return $preempt;
		}

		$method = (is_array($args) && isset($args['method'])) ? strtoupper((string) $args['method']) : 'GET';
		$path = isset($parts['path']) ? trim(preg_replace('#^/3\.0#', '', (string) $parts['path']), '/') : '';
		$body = (is_array($args) && isset($args['body']) && is_string($args['body'])) ? json_decode($args['body'], true) : null;
		$body = is_array($body) ? $body : array();

		if ($method === 'POST' && preg_match('#^lists/([^/]+)/members$#', $path, $match)) {
			self::addEvent('api_subscribe');
			return self::response(200, self::member($match[1], $body));
		}
		if (($method === 'PUT' || $method === 'PATCH') && preg_match('#^lists/([^/]+)/members/[^/]+$#', $path, $match)) {
			self::addEvent('api_update');
			return self::response(200, self::member($match[1], $body));
		}
		if ($method === 'POST' && preg_match('#^lists/[^/]+/members/[^/]+/tags$#', $path)) {
			return self::response(204, null);
		}

		return self::response(404, array('type' => 'https://mailchimp.com/developer/marketing/docs/errors/',
			'title' => 'Resource Not Found', 'status' => 404, 'detail' => 'Answered by the form test.'));
	}

	private static function member($list_id, $body) {
		$email = isset($body['email_address']) && is_string($body['email_address']) ? $body['email_address'] : '';
		$status = isset($body['status']) && is_string($body['status']) ? $body['status'] : 'pending';

		return array(
			'id' => md5(strtolower($email)),
			'email_address' => $email,
			'status' => $status,
			'list_id' => (string) $list_id,
			'merge_fields' => isset($body['merge_fields']) ? $body['merge_fields'] : new stdClass(),
			'interests' => isset($body['interests']) ? $body['interests'] : new stdClass(),
			'tags' => array()
		);
	}

	private static function response($code, $data) {
		$messages = array(200 => 'OK', 204 => 'No Content', 404 => 'Not Found');

		return array(
			'headers' => array('content-type' => 'application/json; charset=utf-8'),
			'body' => $data === null ? '' : BVFormTestRecorder::jsonEncode($data),
			'response' => array('code' => $code, 'message' => isset($messages[$code]) ? $messages[$code] : ''),
			'cookies' => array(),
			'filename' => null
		);
	}

	public function noRedirect($url) {
		return '';
	}

	public function removeCaptchaErrors($errors) {
		if (!is_array($errors)) {
			return $errors;
		}

		return array_values(array_filter($errors, function ($error) {
			return !in_array($error, BVMc4wpFormHandler::captchaErrors(), true);
		}));
	}

	public static function captchaErrors() {
		return self::$captcha_errors;
	}

	public function skipMail($return) {
		return $return === null ? true : $return;
	}

	/** MC4WP Premium logs every form subscription (MC4WP_Logger::log_form_request); not for a test. */
	public function removePremiumLogging() {
		global $wp_filter;

		if (!isset($wp_filter['mc4wp_form_subscribed']) || !is_object($wp_filter['mc4wp_form_subscribed']) ||
				!isset($wp_filter['mc4wp_form_subscribed']->callbacks) || !is_array($wp_filter['mc4wp_form_subscribed']->callbacks)) {
			return;
		}

		foreach ($wp_filter['mc4wp_form_subscribed']->callbacks as $priority => $callbacks) {
			foreach ((array) $callbacks as $callback) {
				$function = isset($callback['function']) ? $callback['function'] : null;
				if (is_array($function) && isset($function[0], $function[1]) && is_object($function[0]) &&
						get_class($function[0]) === 'MC4WP_Logger' && $function[1] === 'log_form_request') {
					remove_action('mc4wp_form_subscribed', $function, $priority);
				}
			}
		}
	}

	private static function addEvent($name) {
		if (self::$recorder !== null) {
			self::$recorder->addEvent('mc4wp', $name, self::$form_id_seen !== '' ? self::$form_id_seen : self::postedFormId());
		}
	}

	/** Watches for the handled submission (called by BVFormTesting when a run is recorded). */
	public static function watch($recorder) {
		self::$recorder = $recorder;

		add_action('mc4wp_form_subscribed', function () {
			self::addEvent('subscribed');
		}, PHP_INT_MAX, 0);
		add_action('mc4wp_form_error', function ($form) {
			if (is_object($form) && isset($form->ID) && (string) $form->ID === self::postedFormId()) {
				self::addEvent('form_error');
			}
		}, PHP_INT_MAX, 1);
	}
}

endif;
