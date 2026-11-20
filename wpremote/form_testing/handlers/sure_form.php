<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVSureFormHandler')) :

// SureForms (and SureForms Pro): CAPTCHA and email bypasses for the tested form in a signed test request.
class BVSureFormHandler {
	const ROUTE = '/sureforms/v1/submit-form';
	const TOKEN_HEADER = 'X-WP-Submit-Token';
	const TOKEN_FIELD = 'bv_srfm_submit_token';
	const HONEYPOT_FIELD = 'srfm-honeypot-field';
	const CAPTCHA_META = '_srfm_captcha_security_type';
	const TOKEN_CLASS = 'SRFM\\Inc\\Submit_Token';

	private static $integration_hooks = array('srfm_form_submit', 'srfm_after_submission_process');

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

		add_filter('rest_pre_dispatch', array($this, 'prepareSubmission'), PHP_INT_MIN, 3);
	}

	/** Whether the REST request submits the tested form. */
	private function isTestedSubmission($request) {
		if (!is_object($request) || !method_exists($request, 'get_route') || !method_exists($request, 'get_param')) {
			return false;
		}
		$posted = $request->get_param('form-id');
		return untrailingslashit((string) $request->get_route()) === self::ROUTE && is_scalar($posted) && absint($posted) === $this->form_id;
	}

	/** Sets up the bypasses once the tested submission is being dispatched (before its permission check). */
	public function prepareSubmission($result, $server, $request) {
		if (!$this->isTestedSubmission($request)) {
			return $result;
		}

		$this->setSubmitToken($request);

		if ($this->bypass_captcha) {
			add_filter('get_post_metadata', array($this, 'filterCaptchaType'), PHP_INT_MAX, 4);
			if ($request->get_param(self::HONEYPOT_FIELD) === null) {
				$request->set_param(self::HONEYPOT_FIELD, '');
			}
		}

		if ($this->bypass_email) {
			add_filter('srfm_email_notification_should_send', array($this, 'dropNotifications'), PHP_INT_MAX, 1);
			add_filter('srfm_should_send_email', array($this, 'dontSendEmail'), PHP_INT_MAX, 4);
		}

		foreach (self::$integration_hooks as $hook) {
			remove_all_actions($hook);
		}
		add_filter('srfm_before_entry_data', array($this, 'markProcessed'), PHP_INT_MAX, 1);
		self::setUploadTypes();

		return $result;
	}

	private function setSubmitToken($request) {
		$header = $request->get_header(self::TOKEN_HEADER);
		if (is_string($header) && $header !== '') {
			return;
		}

		$token = $request->get_param(self::TOKEN_FIELD);
		if (!is_string($token) || $token === '') {
			$token = $this->currentToken();
		}
		if (is_string($token) && $token !== '') {
			$request->set_header(self::TOKEN_HEADER, sanitize_text_field($token));
		}
	}

	/** The submit token SureForms renders for the form now (Submit_Token::generate), or null. */
	private function currentToken() {
		if (!class_exists(self::TOKEN_CLASS) || !method_exists(self::TOKEN_CLASS, 'generate')) {
			return null;
		}
		try {
			return call_user_func(array(self::TOKEN_CLASS, 'generate'), $this->form_id);
		} catch (Throwable $e) {
			return null;
		}
	}

	/** The tested form's security type reads as "none". */
	public function filterCaptchaType($value, $object_id, $meta_key, $single) {
		if ($meta_key === self::CAPTCHA_META && absint($object_id) === $this->form_id) {
			return array('none');
		}
		return $value;
	}

	public function dropNotifications($notifications) {
		return array();
	}

	public function dontSendEmail($send, $notification_id = 0, $form_id = 0, $form_data = array()) {
		return absint($form_id) === $this->form_id ? false : $send;
	}

	/**
	 * SureForms Pro's upload field checks each file's client-declared type ($_FILES[..]['type']) against the field's
	 * allowed formats. A browser declares the file's real type; the test and monitor clients declare
	 * application/octet-stream. For those files only, use the type WordPress detects from the file (as a browser would
	 * declare it); a file it can't identify keeps its declared type and is checked as before.
	 */
	private static function setUploadTypes() {
		foreach ($_FILES as $field => $file) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if (strpos((string) $field, 'srfm-upload-') !== 0 || !is_array($file) || !isset($file['type'], $file['name'], $file['tmp_name'])) {
				continue;
			}
			foreach ((array) $file['type'] as $index => $type) {
				$name = is_array($file['name']) ? (isset($file['name'][$index]) ? $file['name'][$index] : '') : $file['name'];
				$tmp = is_array($file['tmp_name']) ? (isset($file['tmp_name'][$index]) ? $file['tmp_name'][$index] : '') : $file['tmp_name'];
				if (($type !== '' && $type !== 'application/octet-stream') || !is_string($name) || !is_string($tmp) || $tmp === '' || !is_uploaded_file($tmp)) {
					continue;
				}
				$checked = wp_check_filetype_and_ext($tmp, $name);
				if (!empty($checked['type'])) {
					if (is_array($file['type'])) {
						$_FILES[$field]['type'][$index] = $checked['type'];
					} else {
						$_FILES[$field]['type'] = $checked['type'];
					}
				}
			}
		}
	}

	/** Stores the entry as already through the after-submission process (Background_Process::claim_submission). */
	public function markProcessed($entries_data) {
		if (!is_array($entries_data) || !isset($entries_data['form_id']) || absint($entries_data['form_id']) !== $this->form_id) {
			return $entries_data;
		}
		$extras = (isset($entries_data['extras']) && is_array($entries_data['extras'])) ? $entries_data['extras'] : array();
		$extras['is_after_submission_process_triggered'] = true;
		$entries_data['extras'] = $extras;
		return $entries_data;
	}
}

endif;
