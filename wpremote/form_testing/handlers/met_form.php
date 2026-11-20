<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVMetFormHandler')) :

// MetForm (and MetForm Pro): CAPTCHA and email bypasses for the tested form in a signed test request.
class BVMetFormHandler {
	const ROUTE_PATTERN = '#^/metform/v1/entries/insert/(\d+)/?$#';
	const FORM_SETTINGS_KEY = 'metform_form__form_setting';
	const GLOBAL_SETTINGS_OPTION = 'metform_option__settings';
	const CAPTCHA_INPUT = 'mf-captcha-challenge';

	private static $recaptcha_settings = array('mf_recaptcha_site_key', 'mf_recaptcha_site_key_v3');
	private static $email_settings = array('enable_admin_notification', 'enable_user_notification', 'email_verification_enable');
	private static $integration_settings = array('mf_mail_chimp', 'mf_get_response', 'mf_automizy', 'mf_rest_api', 'mf_zapier',
		'mf_slack', 'mf_fluent', 'mf_active_campaign', 'mf_convert_kit', 'mf_mail_aweber', 'mf_mail_poet', 'mf_mailerlite',
		'mf_mailster', 'mf_google_sheet', 'mf_google_drive', 'mf_dropbox', 'mf_sms_status', 'mf_form_to_post', 'mf_hubspot',
		'mf_hubspot_forms', 'mf_helpscout', 'mf_fluent_crm', 'mf_registration', 'mf_login');
	private static $integration_hooks = array('metform/entries/submit/integrations', 'metform_after_store_form_data');
	private static $email_hooks = array('metform/entries/submit/notify_user');

	private $form_id;
	private $bypass_params = array();
	private $disabled_settings = array();
	private $reading_settings = false;

	public function __construct($form_id, $bypass_params) {
		$this->form_id = absint($form_id);
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if ($this->form_id <= 0) {
			return;
		}

		$bypass_captcha = array_key_exists('should_bypass_captcha', $this->bypass_params);
		$bypass_email = array_key_exists('should_bypass_email', $this->bypass_params);

		$this->disabled_settings = self::$integration_settings;
		if ($bypass_captcha) {
			$this->disabled_settings = array_merge($this->disabled_settings, self::$recaptcha_settings);
		}
		if ($bypass_email) {
			$this->disabled_settings = array_merge($this->disabled_settings, self::$email_settings);
		}

		add_filter('get_post_metadata', array($this, 'filterFormSettings'), PHP_INT_MAX, 4);
		add_filter('option_' . self::GLOBAL_SETTINGS_OPTION, array($this, 'filterSettings'), PHP_INT_MAX);

		$handler = $this;
		add_filter('rest_pre_dispatch', function ($result, $server, $request) use ($handler, $bypass_captcha, $bypass_email) {
			if ($handler->isTestedSubmission($request)) {
				$hooks = self::$integration_hooks;
				if ($bypass_email) {
					$hooks = array_merge($hooks, self::$email_hooks);
				}
				foreach ($hooks as $hook) {
					remove_all_actions($hook);
				}
				if ($bypass_captcha) {
					$handler->seedSimpleCaptcha($request);
				}
			}
			return $result;
		}, PHP_INT_MAX, 3);
	}

	/** Whether the REST request is the MetForm submission of the tested form. */
	public function isTestedSubmission($request) {
		if (!is_object($request) || !method_exists($request, 'get_route') || !method_exists($request, 'get_method')) {
			return false;
		}
		if ($request->get_method() !== 'POST' || !preg_match(self::ROUTE_PATTERN, (string) $request->get_route(), $matches)) {
			return false;
		}
		return absint($matches[1]) === $this->form_id;
	}

	/** The tested form's settings postmeta, with the bypassed switches removed. */
	public function filterFormSettings($value, $object_id, $meta_key, $single) {
		if ($meta_key !== self::FORM_SETTINGS_KEY || absint($object_id) !== $this->form_id || $this->reading_settings) {
			return $value;
		}

		$this->reading_settings = true;
		$settings = get_post_meta($object_id, self::FORM_SETTINGS_KEY, true);
		$this->reading_settings = false;

		if (!is_array($settings)) {
			return $value;
		}
		return array($this->filterSettings($settings));
	}

	public function filterSettings($settings) {
		if (!is_array($settings)) {
			return $settings;
		}
		foreach ($this->disabled_settings as $key) {
			unset($settings[$key]);
		}
		return $settings;
	}

	/**
	 * MetForm compares the posted simple-captcha answer with $_SESSION['mf_captcha_text'] (set when the captcha
	 * image is served) and calls session_start() itself: store the posted answer in a session it will resume.
	 */
	public function seedSimpleCaptcha($request) {
		$answer = $request->get_param(self::CAPTCHA_INPUT);
		if (!is_string($answer) || $answer === '' || !function_exists('session_status')) {
			return;
		}

		if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
			@session_start();
		}
		if (session_status() !== PHP_SESSION_ACTIVE) {
			return;
		}

		$_SESSION['mf_captcha_text'] = $answer;
		$_SESSION['LAST_ACTIVITY'] = time();
		session_write_close();
	}
}

endif;
