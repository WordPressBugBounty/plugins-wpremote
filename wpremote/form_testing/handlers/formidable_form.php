<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVFormidableFormHandler')) :

class BVFormidableFormHandler {
	private $form_id;
	private $bypass_params = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = $form_id;
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		// Report spam as an error instead of silently saving a spam entry behind a success message.
		add_filter('frm_save_spam_entry', '__return_false', PHP_INT_MAX);

		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			$this->bypassCaptcha();
		}

		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			$this->bypassEmail();
		}
	}

	public function bypassCaptcha() {
		// Only the captcha field: Formidable Pro also uses this filter for conditional logic on every field.
		add_filter('frm_is_field_hidden', array($this, 'hideCaptchaField'), PHP_INT_MAX, 2);
		// Anti-spam a direct test POST can't pass: the JavaScript token and the honeypot.
		add_filter('frm_run_antispam', '__return_false', PHP_INT_MAX);
		add_filter('frm_run_honeypot', '__return_false', PHP_INT_MAX);
	}

	public function hideCaptchaField($is_hidden, $field) {
		$type = is_array($field) ? (isset($field['type']) ? $field['type'] : '') : (isset($field->type) ? $field->type : '');
		return ($type === 'captcha') ? true : $is_hidden;
	}

	public function bypassEmail() {
		add_filter('frm_send_email', '__return_false', PHP_INT_MAX);
	}
}

endif;