<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVJetFormBuilderFormHandler')) :

// JetFormBuilder: CAPTCHA, email and post-submit action bypasses for the tested form in a signed test request.
class BVJetFormBuilderFormHandler {
	const FORM_ID_FIELD = '_jet_engine_booking_form_id';
	const CAPTCHA_META = '_jf_recaptcha';
	const ARGS_META = '_jf_args';
	const ACTIONS_META = '_jf_actions';
	const CSRF_FIELD = '_jfb_csrf_token';

	private static $kept_actions = array('send_email', 'save_record', 'redirect_to_page');

	private $form_id;
	private $bypass_params = array();
	private $bypass_captcha = false;
	private $bypass_email = false;
	private $reading_meta = false;

	public function __construct($form_id, $bypass_params) {
		$this->form_id = absint($form_id);
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if ($this->form_id <= 0 || !$this->isTestedSubmission()) {
			return;
		}

		$this->bypass_captcha = array_key_exists('should_bypass_captcha', $this->bypass_params);
		$this->bypass_email = array_key_exists('should_bypass_email', $this->bypass_params);

		add_filter('get_post_metadata', array($this, 'filterFormMeta'), PHP_INT_MAX, 4);

		if ($this->bypass_captcha) {
			add_filter('jet-form-builder/request-handler/request', array($this, 'refreshCsrfToken'), PHP_INT_MIN);
		}
	}

	/** Whether this request submits the tested form. */
	private function isTestedSubmission() {
		// phpcs:ignore WordPress.Security.NonceVerification
		$posted = isset($_REQUEST[self::FORM_ID_FIELD]) ? $_REQUEST[self::FORM_ID_FIELD] : null;
		return is_scalar($posted) && absint($posted) === $this->form_id;
	}

	/** The tested form's captcha settings (empty) and actions (side-effect actions switched off). */
	public function filterFormMeta($value, $object_id, $meta_key, $single) {
		if (absint($object_id) !== $this->form_id || $this->reading_meta) {
			return $value;
		}

		if ($meta_key === self::CAPTCHA_META && $this->bypass_captcha) {
			return array('{}');
		}

		// The honeypot inputs are named like real fields (name, email, phone, company): a test may fill them.
		if ($meta_key === self::ARGS_META && $this->bypass_captcha) {
			$this->reading_meta = true;
			$raw = get_post_meta($object_id, self::ARGS_META, true);
			$this->reading_meta = false;
			$args = is_string($raw) ? json_decode($raw, true) : $raw;
			if (is_array($args) && !empty($args['use_honeypot'])) {
				$args['use_honeypot'] = false;
				return array(BVFormTestRecorder::jsonEncode($args));
			}
			return $value;
		}

		if ($meta_key !== self::ACTIONS_META) {
			return $value;
		}

		$this->reading_meta = true;
		$raw = get_post_meta($object_id, self::ACTIONS_META, true);
		$this->reading_meta = false;

		$actions = is_string($raw) ? json_decode($raw, true) : $raw;
		if (!is_array($actions)) {
			return $value;
		}

		foreach ($actions as $index => $action) {
			if (!is_array($action)) {
				continue;
			}
			$type = isset($action['type']) ? (string) $action['type'] : '';
			$keep = in_array($type, self::$kept_actions, true) && !($type === 'send_email' && $this->bypass_email);
			if (!$keep) {
				$actions[$index]['is_execute'] = false;
			}
		}

		return array(BVFormTestRecorder::jsonEncode($actions));
	}

	/** Swaps the posted CSRF token for the one JFB holds for this client (Csrf_Tools::add returns it or adds one). */
	public function refreshCsrfToken($request) {
		$tools = 'JFB_Modules\\Security\\Csrf\\Csrf_Tools';
		if (!is_array($request) || !array_key_exists(self::CSRF_FIELD, $request) || !class_exists($tools) ||
				!method_exists($tools, 'add') || !method_exists($tools, 'client_id') || !method_exists($tools, 'generate')) {
			return $request;
		}

		try {
			$token = call_user_func(array($tools, 'add'), call_user_func(array($tools, 'generate')),
				call_user_func(array($tools, 'client_id'), $this->form_id));
		} catch (Throwable $e) {
			return $request;
		}
		if (is_string($token) && $token !== '') {
			$request[self::CSRF_FIELD] = $token;
		}
		return $request;
	}
}

endif;
