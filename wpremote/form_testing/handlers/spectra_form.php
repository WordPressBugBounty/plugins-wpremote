<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVSpectraFormHandler')) :

// Spectra Form block: CAPTCHA and email bypasses for the tested form in a signed test request.
class BVSpectraFormHandler {
	const SUBMIT_ACTION = 'uagb_process_forms';
	const NONCE_ACTION = 'uagb_forms_ajax_nonce';
	const SUCCESS_HOOK = 'uagb_form_success';

	private static $recaptcha_options = array('uag_recaptcha_site_key_v2', 'uag_recaptcha_secret_key_v2',
		'uag_recaptcha_site_key_v3', 'uag_recaptcha_secret_key_v3');
	private static $watcher = null;

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

		// Nonces depend on the current user, which is set by init.
		add_action('init', array($this, 'addMissingNonce'), PHP_INT_MAX);

		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			foreach (self::$recaptcha_options as $option) {
				add_filter('pre_option_' . $option, array($this, 'emptyOption'), PHP_INT_MAX);
			}
		}

		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			add_filter('pre_wp_mail', array($this, 'skipMail'), PHP_INT_MAX);
		}

		$handler = $this;
		$limit = function () use ($handler) {
			$handler->removeIntegrations();
		};
		add_action('wp_ajax_' . self::SUBMIT_ACTION, $limit, 0);
		add_action('wp_ajax_nopriv_' . self::SUBMIT_ACTION, $limit, 0);
	}

	/** The request is the Spectra submission of the tested block (any block when no id is given). */
	public static function isTestedSubmission($form_id) {
		if (!isset($_POST['action']) || $_POST['action'] !== self::SUBMIT_ACTION) {
			return false;
		}
		if ($form_id === null || $form_id === '') {
			return true;
		}

		return isset($_POST['block_id']) && is_string($_POST['block_id']) && (string) $form_id === sanitize_text_field(wp_unslash($_POST['block_id']));
	}

	public function addMissingNonce() {
		if (isset($_POST['nonce']) && is_string($_POST['nonce']) && $_POST['nonce'] !== '') {
			return;
		}
		if (!function_exists('wp_create_nonce')) {
			return;
		}
		$nonce = wp_create_nonce(self::NONCE_ACTION);
		$_POST['nonce'] = $nonce;
		$_REQUEST['nonce'] = $nonce;
	}

	public function emptyOption($value) {
		return '';
	}

	public function skipMail($return) {
		return $return === null ? true : $return;
	}

	/** Leaves only our own watcher on uagb_form_success. */
	public function removeIntegrations() {
		global $wp_filter;

		if (!isset($wp_filter[self::SUCCESS_HOOK]) || !is_object($wp_filter[self::SUCCESS_HOOK]) ||
				!isset($wp_filter[self::SUCCESS_HOOK]->callbacks) || !is_array($wp_filter[self::SUCCESS_HOOK]->callbacks)) {
			return;
		}

		foreach ($wp_filter[self::SUCCESS_HOOK]->callbacks as $priority => $callbacks) {
			foreach ((array) $callbacks as $callback) {
				if (isset($callback['function']) && $callback['function'] !== self::$watcher) {
					remove_action(self::SUCCESS_HOOK, $callback['function'], $priority);
				}
			}
		}
	}

	/** Watches for the handled submission (called by BVFormTesting when a run is recorded). */
	public static function watch($recorder) {
		self::$watcher = function ($form_data = array()) use ($recorder) {
			$block_id = isset($_POST['block_id']) && is_string($_POST['block_id']) ? sanitize_text_field(wp_unslash($_POST['block_id'])) : '';
			$recorder->addEvent('spectra', 'form_success', $block_id);
		};
		add_action(self::SUCCESS_HOOK, self::$watcher, PHP_INT_MAX, 1);
	}
}

endif;
