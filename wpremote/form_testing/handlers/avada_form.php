<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVAvadaFormHandler')) :

// Avada Forms (Avada Builder): CAPTCHA, email and third-party action bypasses for the tested form in a signed test request.
class BVAvadaFormHandler {
	const AJAX_ACTION = 'fusion_form_submit_ajax';
	const NONCE_ACTION = 'fusion_form_nonce';
	const NONCE_FIELD = 'fusion_form_nonce';

	private static $captcha_inputs = array('g-recaptcha-response', 'fusion-form-recaptcha-response');
	// Actions that only store the entry or act in the visitor's browser.
	private static $kept_actions = array('database', 'off-canvas');
	private static $integration_keys = array('mailchimp_action', 'hubspot_action');

	private $form_id;
	private $bypass_params = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = absint($form_id);
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if ($this->form_id <= 0 || !$this->isTestedSubmission()) {
			return;
		}

		$handler = $this;
		// Nonces depend on the current user, which is set by init.
		add_action('init', function () use ($handler) {
			$handler->addMissingNonce();
		}, PHP_INT_MAX);

		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			foreach (self::$captcha_inputs as $key) {
				unset($_POST[$key], $_REQUEST[$key]);
			}
		}

		add_filter('fusion_get_all_meta', array($this, 'filterFormMeta'), PHP_INT_MAX, 2);
	}

	/** Whether this request is the Avada Forms submission of the tested form. */
	public function isTestedSubmission() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if (!isset($_POST['action'], $_POST['form_id']) || !is_string($_POST['action']) || $_POST['action'] !== self::AJAX_ACTION) {
			return false;
		}
		return is_scalar($_POST['form_id']) && absint($_POST['form_id']) === $this->form_id;
		// phpcs:enable
	}

	public function addMissingNonce() {
		if (!function_exists('wp_create_nonce')) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if (isset($_POST[self::NONCE_FIELD]) && is_string($_POST[self::NONCE_FIELD]) && $_POST[self::NONCE_FIELD] !== '') {
			return;
		}
		$nonce = wp_create_nonce(self::NONCE_ACTION);
		$_POST[self::NONCE_FIELD] = $nonce;
		$_REQUEST[self::NONCE_FIELD] = $nonce;
	}

	/** The tested form's settings without its third-party actions (and, with email suppression, its emails). */
	public function filterFormMeta($meta, $post_id = 0) {
		if (!is_array($meta) || absint($post_id) !== $this->form_id) {
			return $meta;
		}

		$kept = self::$kept_actions;
		if (!array_key_exists('should_bypass_email', $this->bypass_params)) {
			$kept[] = 'email';
		}
		if (isset($meta['form_actions']) && is_array($meta['form_actions'])) {
			$meta['form_actions'] = array_values(array_intersect($meta['form_actions'], $kept));
		}
		foreach (self::$integration_keys as $key) {
			unset($meta[$key]);
		}
		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			unset($meta['notifications']);
		}
		return $meta;
	}
}

endif;
