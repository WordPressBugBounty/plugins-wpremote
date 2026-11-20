<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVGravityFormHandler')) :

class BVGravityFormHandler {
	private $form_id;
	private $bypass_params = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = $form_id;
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			$this->bypassCaptcha();
		}

		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			$this->bypassEmail();
		}

		$this->bypassContentCreation();
		$this->keepSideEffectsInRequest();
		$this->bypassTotalValidation();
	}

	/**
	 * Gravity Forms 2.10+ sends notifications from a background request by default (and add-ons may
	 * process feeds in one), where the test's email suppression, mail capture and HTTP blocking are not
	 * active. Process them within the test request instead.
	 */
	public function keepSideEffectsInRequest() {
		if ($this->form_id === null) {
			return;
		}

		$form_id = absint($this->form_id);
		add_filter('gform_is_asynchronous_notifications_enabled_' . $form_id, '__return_false', PHP_INT_MAX);
		add_filter('gform_is_feed_asynchronous_' . $form_id, '__return_false', PHP_INT_MAX);
	}

	/**
	 * The Total field is filled by the browser from the pricing fields; Gravity Forms recalculates the
	 * total when it saves the entry, so the submitted value is not compared for a test submission.
	 */
	public function bypassTotalValidation() {
		if ($this->form_id === null) {
			return;
		}

		add_filter('gform_pre_validation_' . absint($this->form_id), function($form) {
			foreach ($form['fields'] as &$field) {
				if ($field->type === 'total') {
					$field->validateTotal = false;
				}
			}
			return $form;
		}, PHP_INT_MAX);
	}

	/**
	 * A test submission must not create posts (Post fields) or WordPress users (User Registration add-on)
	 * on the site. Advanced Post Creation feeds are skipped for the same reason.
	 */
	public function bypassContentCreation() {
		if ($this->form_id === null) {
			return;
		}

		$form_id = absint($this->form_id);
		add_filter('gform_disable_post_creation_' . $form_id, '__return_true', PHP_INT_MAX);
		add_filter('gform_gravityformsuserregistration_pre_process_feeds_' . $form_id, '__return_empty_array', PHP_INT_MAX);
		add_filter('gform_gravityformsadvancedpostcreation_pre_process_feeds_' . $form_id, '__return_empty_array', PHP_INT_MAX);
	}

	public function bypassCaptcha() {
		if ($this->form_id === null) {
			return;
		}

		add_filter('gform_pre_validation_' . $this->form_id, function($form) {
			foreach ($form['fields'] as &$field) {
				if ($field->type === 'captcha') {
					$field->visibility = 'hidden';
				}
			}
			return $form;
		}, PHP_INT_MAX);

		// Honeypot and the submission speed check (2.9.21+) mark a scripted submission as spam or abort it.
		add_filter('gform_pre_process_' . absint($this->form_id), function($form) {
			if (is_array($form)) {
				$form['enableHoneypot'] = false;
				$form['enableSubmitSpeedCheck'] = false;
			}
			return $form;
		}, PHP_INT_MAX);

		// Akismet (Gravity Forms' own integration) would mark the test entry as spam.
		add_filter('gform_akismet_enabled_' . absint($this->form_id), '__return_false', PHP_INT_MAX);
	}

	public function bypassEmail() {
		add_filter('gform_pre_send_email', function ($email_data) {
			$email_data['abort_email'] = true;
			return $email_data;
		}, PHP_INT_MAX);
	}
}

endif;