<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVDiviFormHandler')) :

// Divi contact form module: CAPTCHA and email bypasses for the tested form in a signed test request.
class BVDiviFormHandler {
	const SUBMIT_PREFIX = 'et_pb_contactform_submit_';
	const NONCE_PREFIX = '_wpnonce-et-pb-contact-form-submitted-';
	const CAPTCHA_PREFIX = 'et_pb_contact_captcha_';
	const RECAPTCHA_VERIFY_URLS = array(
		'https://www.google.com/recaptcha/api/siteverify',
		'https://www.recaptcha.net/recaptcha/api/siteverify'
	);

	private $form_id;
	private $bypass_params = array();
	private $skip_next_mail = false;

	public function __construct($form_id, $bypass_params) {
		$this->form_id = $form_id;
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		$suffixes = self::submittedSuffixes();
		if (empty($suffixes)) {
			return;
		}

		$handler = $this;
		// Nonces depend on the current user, which is set by init.
		add_action('init', function () use ($handler, $suffixes) {
			$handler->addMissingNonces($suffixes);
		}, PHP_INT_MAX);

		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			$this->answerMathsCaptcha($suffixes);
			if (!isset($_POST['token']) || !is_string($_POST['token']) || $_POST['token'] === '') {
				$_POST['token'] = 'bv-form-test';
			}
			add_filter('pre_http_request', array($this, 'stubCaptchaVerification'), PHP_INT_MAX - 1, 3);
		}

		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			add_filter('et_contact_page_headers', array($this, 'markFormMail'), PHP_INT_MAX);
			add_filter('pre_wp_mail', array($this, 'skipFormMail'), PHP_INT_MAX);
		}
	}

	/** Suffixes <s> of the Divi contact forms submitted in this request. */
	public static function submittedSuffixes() {
		$suffixes = array();
		foreach (array_keys($_POST) as $key) {
			if (is_string($key) && strpos($key, self::SUBMIT_PREFIX) === 0) {
				$suffix = substr($key, strlen(self::SUBMIT_PREFIX));
				if ($suffix !== '' && preg_match('/^[A-Za-z0-9_-]+$/', $suffix) === 1) {
					$suffixes[] = $suffix;
				}
			}
		}
		return $suffixes;
	}

	public function addMissingNonces($suffixes) {
		if (!function_exists('wp_create_nonce')) {
			return;
		}
		foreach ($suffixes as $suffix) {
			$key = self::NONCE_PREFIX . $suffix;
			if (isset($_POST[$key]) && is_string($_POST[$key]) && $_POST[$key] !== '') {
				continue;
			}
			// Divi 4 numbers forms by render order; Divi 5 uses the module's unique id (a UUID or md5).
			$action = preg_match('/^\d+$/', $suffix) === 1 ?'et-pb-contact-form-submit' : 'et-pb-contact-form-submit-' . $suffix;
			$_POST[$key] = wp_create_nonce($action);
		}
	}

	private function answerMathsCaptcha($suffixes) {
		foreach ($suffixes as $suffix) {
			$key = self::CAPTCHA_PREFIX . $suffix;
			$first = self::CAPTCHA_PREFIX . 'first_digit_' . $suffix;
			$second = self::CAPTCHA_PREFIX . 'second_digit_' . $suffix;
			if (isset($_POST[$first], $_POST[$second]) && is_numeric($_POST[$first]) && is_numeric($_POST[$second])) {
				$_POST[$key] = (string) (intval($_POST[$first]) + intval($_POST[$second]));
			} elseif (!isset($_POST[$key]) || !is_string($_POST[$key]) || $_POST[$key] === '') {
				// Not answered, or not posted at all (a test that never saw the page's numbers).
				$_POST[$key] = '1';
			}
		}
	}

	public function stubCaptchaVerification($preempt, $args, $url) {
		if ($preempt !== false || !is_string($url)) {
			return $preempt;
		}
		$url = strtok($url, '?');
		if (!in_array($url, self::RECAPTCHA_VERIFY_URLS, true)) {
			return $preempt;
		}

		$verdict = array('success' => true, 'score' => 1.0, 'hostname' => BVFormTestRecorder::parseUrl(home_url(), PHP_URL_HOST));
		return array(
			'headers' => array(),
			'body' => BVFormTestRecorder::jsonEncode($verdict),
			'response' => array('code' => 200, 'message' => 'OK'),
			'cookies' => array(),
			'filename' => null
		);
	}

	public function markFormMail($headers) {
		$this->skip_next_mail = true;
		return $headers;
	}

	public function skipFormMail($return) {
		if ($this->skip_next_mail !== true || $return !== null) {
			return $return;
		}
		$this->skip_next_mail = false;
		return true;
	}

	/** Watches for the handled submission (called by BVFormTesting when a run is recorded). */
	public static function watch($recorder) {
		add_action('et_pb_contact_form_submit', function ($processed_fields_values, $et_contact_error = false, $contact_form_info = array()) use ($recorder) {
			$form_id = '';
			if (is_array($contact_form_info)) {
				if (!empty($contact_form_info['contact_form_unique_id'])) {
					$form_id = $contact_form_info['contact_form_unique_id'];
				} elseif (isset($contact_form_info['post_id'], $contact_form_info['contact_form_number'])) {
					// Divi 4 forms saved before 4.13.1 have no unique id.
					$form_id = $contact_form_info['post_id'] . ':' . $contact_form_info['contact_form_number'];
				}
			}
			$recorder->addEvent('divi', $et_contact_error ? 'submit_error' : 'submit', $form_id);
		}, PHP_INT_MAX, 3);
	}
}

endif;
