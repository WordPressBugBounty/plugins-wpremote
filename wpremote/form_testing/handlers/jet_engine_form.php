<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVJetEngineFormHandler')) :

// JetEngine legacy forms: CAPTCHA, email and notification bypasses for the tested form in a signed test request.
class BVJetEngineFormHandler {
	const FORM_ID_FIELD = '_jet_engine_booking_form_id';
	const CAPTCHA_META = '_captcha';
	const NONCE_FIELD = '_jet_engine_nonce';
	const NONCE_ACTION = '_jet_engine_booking_form';
	const NOTIFICATIONS_META = '_notifications_data';
	const SKIPPED_TYPE = 'bv_form_test_skipped';

	private static $kept_notifications = array('email', 'redirect');

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
		if ($this->form_id <= 0 || self::postedFormId() !== $this->form_id) {
			return;
		}

		$this->bypass_captcha = array_key_exists('should_bypass_captcha', $this->bypass_params);
		$this->bypass_email = array_key_exists('should_bypass_email', $this->bypass_params);

		add_filter('get_post_metadata', array($this, 'filterFormMeta'), PHP_INT_MAX, 4);
		add_action('jet-engine/forms/booking/notification/' . self::SKIPPED_TYPE, array($this, 'logSkipped'), 10, 2);
		if ($this->bypass_captcha) {
			$this->addMissingNonce();
		}
	}

	/**
	 * A test posted without the page's form (HTTP test) has no _jet_engine_nonce, which
	 * Jet_Engine_Booking_Forms_Handler checks against the '_jet_engine_booking_form' action: add a fresh one.
	 */
	private function addMissingNonce() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if (isset($_POST['values']) && is_array($_POST['values'])) {
			foreach ($_POST['values'] as $data) {
				if (is_array($data) && isset($data['name'], $data['value']) && $data['name'] === self::NONCE_FIELD && $data['value'] !== '') {
					return;
				}
			}
			$_POST['values'][] = array('name' => self::NONCE_FIELD, 'value' => wp_create_nonce(self::NONCE_ACTION));
		} elseif (empty($_POST[self::NONCE_FIELD])) {
			$_POST[self::NONCE_FIELD] = wp_create_nonce(self::NONCE_ACTION);
		}
		// phpcs:enable
	}

	/** The submitted form's id (posted with the AJAX request and the page-reload form alike), or 0. */
	public static function postedFormId() {
		// phpcs:ignore WordPress.Security.NonceVerification
		$posted = isset($_REQUEST[self::FORM_ID_FIELD]) ? $_REQUEST[self::FORM_ID_FIELD] : null;
		return is_scalar($posted) ? absint($posted) : 0;
	}

	/** The tested form's captcha settings (disabled) and notifications (side-effect notifications switched off). */
	public function filterFormMeta($value, $object_id, $meta_key, $single) {
		if (absint($object_id) !== $this->form_id || $this->reading_meta) {
			return $value;
		}

		if ($meta_key === self::CAPTCHA_META && $this->bypass_captcha) {
			return array(array('enabled' => false, 'use_global' => false, 'key' => '', 'secret' => ''));
		}

		if ($meta_key !== self::NOTIFICATIONS_META) {
			return $value;
		}

		$this->reading_meta = true;
		$raw = get_post_meta($object_id, self::NOTIFICATIONS_META, true);
		$this->reading_meta = false;

		$notifications = is_string($raw) ? json_decode(wp_unslash($raw), true) : null;
		if (!is_array($notifications)) {
			return $value;
		}

		foreach ($notifications as $index => $notification) {
			if (!is_array($notification)) {
				continue;
			}
			$type = isset($notification['type']) ? (string) $notification['type'] : '';
			$keep = in_array($type, self::$kept_notifications, true) && !($type === 'email' && $this->bypass_email);
			if (!$keep) {
				$notifications[$index] = array('type' => self::SKIPPED_TYPE, 'skipped_type' => $type);
			}
		}

		// Read back with wp_unslash() (Jet_Engine_Booking_Forms_Editor::get_notifications).
		return array(wp_slash(BVFormTestRecorder::jsonEncode(array_values($notifications))));
	}

	/** A switched-off notification counts as done, as the notification it replaces would on success. */
	public function logSkipped($notification, $notifications = null) {
		if (is_object($notifications) && isset($notifications->log) && is_array($notifications->log)) {
			$notifications->log[] = true;
		}
	}

	/** Watches for the handled submission (called by BVFormTesting when a run is recorded). */
	public static function watch($recorder) {
		add_action('jet-engine/forms/handler/after-send', function ($handler = null, $success = false) use ($recorder) {
			$form_id = is_object($handler) && isset($handler->form) && is_scalar($handler->form) ? $handler->form : BVJetEngineFormHandler::postedFormId();
			$recorder->addEvent('jet_engine', $success === true ? 'submitted' : 'submit_error', $form_id);
		}, PHP_INT_MAX, 2);
	}
}

endif;
