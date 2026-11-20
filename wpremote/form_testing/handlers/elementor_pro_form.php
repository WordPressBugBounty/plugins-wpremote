<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVElementorProFormHandler')) :

// Elementor Pro Form widget: CAPTCHA, email and after-submit action bypasses for the tested form in a signed test request.
class BVElementorProFormHandler {
	const SUBMIT_ACTION = 'elementor_pro_forms_send_form';
	const VALIDATION_HOOK = 'elementor_pro/forms/validation';
	const SKIP_TYPES_FILTER = 'elementor_pro/forms/validation/skip_types';
	const PROCESS_HOOK = 'elementor_pro/forms/process';
	const NEW_RECORD_HOOK = 'elementor_pro/forms/new_record';
	const FORMS_MODULE_CLASS = 'ElementorPro\\Modules\\Forms\\Module';
	const UPLOADS_SUBDIR = 'elementor/forms';

	private static $captcha_field_types = array('recaptcha', 'recaptcha_v3', 'hcaptcha', 'turnstile');
	private static $safe_actions = array('email', 'email2', 'save-to-database', 'redirect', 'popup');
	private static $email_actions = array('email', 'email2');
	private static $skipped_actions = array();

	private $form_id;
	private $bypass_params = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = $form_id;
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if (!$this->isTestedSubmission()) {
			return;
		}

		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			add_filter(self::SKIP_TYPES_FILTER, array($this, 'addSkipTypes'), PHP_INT_MAX, 1);
			add_action(self::VALIDATION_HOOK, array($this, 'removeCaptchaFields'), 1, 2);
		}

		add_action(self::PROCESS_HOOK, array($this, 'limitSubmitActions'), PHP_INT_MAX, 2);
		add_action(self::NEW_RECORD_HOOK, array($this, 'deleteUploads'), PHP_INT_MAX, 1);
	}

	/** Watches for the handled submission (called by BVFormTesting when a run is recorded). */
	public static function watch($recorder) {
		add_action(self::NEW_RECORD_HOOK, function ($record) use ($recorder) {
			$form_id = '';
			if (is_object($record) && method_exists($record, 'get_form_settings')) {
				$form_id = $record->get_form_settings('id');
			}
			$recorder->addEvent('elementor_pro', 'new_record', $form_id);
			foreach (self::$skipped_actions as $action) {
				$recorder->addEvent('elementor_pro', 'skipped_action:' . substr($action, 0, 40), $form_id);
			}
		}, PHP_INT_MAX - 1, 1);
	}

	/** The posted form is the one under test (the server sends its element id as bv_frm_id). */
	private function isTestedSubmission() {
		if (!isset($_POST['action']) || $_POST['action'] !== self::SUBMIT_ACTION) {
			return false;
		}
		if ($this->form_id === null || $this->form_id === '') {
			return true;
		}

		return isset($_POST['form_id']) && is_string($_POST['form_id']) && (string) $this->form_id === sanitize_text_field(wp_unslash($_POST['form_id']));
	}

	public function addSkipTypes($types) {
		return array_values(array_unique(array_merge(is_array($types) ? $types : array(), self::$captcha_field_types)));
	}

	/** Drops the CAPTCHA fields from the record before the CAPTCHA validators look for them. */
	public function removeCaptchaFields($record, $ajax_handler = null) {
		if (!is_object($record) || !method_exists($record, 'get_field') || !method_exists($record, 'remove_field')) {
			return;
		}

		foreach (self::$captcha_field_types as $type) {
			$fields = $record->get_field(array('type' => $type));
			foreach ((array) $fields as $id => $field) {
				$record->remove_field(is_array($field) && isset($field['id']) ? $field['id'] : $id);
			}
		}
	}

	/** Unregisters, for this request, the actions with outside side effects (see the class comment). */
	public function limitSubmitActions($record, $ajax_handler = null) {
		$registrar = $this->actionsRegistrar();
		if ($registrar === null) {
			return;
		}

		$allowed = self::$safe_actions;
		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			$allowed = array_diff($allowed, self::$email_actions);
		}

		$items = $this->registrarItems($registrar);
		if (!is_array($items)) {
			return;
		}

		$planned = array();
		if (is_object($record) && method_exists($record, 'get_form_settings')) {
			$planned = (array) $record->get_form_settings('submit_actions');
		}

		$kept = array();
		foreach ($items as $id => $action) {
			$name = (is_object($action) && method_exists($action, 'get_name')) ? $action->get_name() : (string) $id;
			if (in_array($name, $allowed, true)) {
				$kept[$id] = $action;
			} elseif (in_array($name, $planned, true)) {
				self::$skipped_actions[] = $name;
			}
		}
		self::$skipped_actions = array_values(array_unique(self::$skipped_actions));

		$this->registrarItems($registrar, $kept);
	}

	/** Deletes the files this test uploaded (Elementor's upload folder only). */
	public function deleteUploads($record) {
		if (!is_object($record) || !method_exists($record, 'get')) {
			return;
		}

		$files = $record->get('files');
		$uploads = wp_upload_dir();
		$base = isset($uploads['basedir']) ? realpath($uploads['basedir'] . DIRECTORY_SEPARATOR . self::UPLOADS_SUBDIR) : false;
		if (!is_array($files) || $base === false) {
			return;
		}

		foreach ($files as $file) {
			$paths = (is_array($file) && isset($file['path'])) ? (array) $file['path'] : array();
			foreach ($paths as $path) {
				$real = is_string($path) ? realpath($path) : false;
				if ($real !== false && is_file($real) && strpos($real, $base . DIRECTORY_SEPARATOR) === 0) {
					@unlink($real);
				}
			}
		}
	}

	private function actionsRegistrar() {
		if (!class_exists(self::FORMS_MODULE_CLASS) || !method_exists(self::FORMS_MODULE_CLASS, 'instance')) {
			return null;
		}

		$module = call_user_func(array(self::FORMS_MODULE_CLASS, 'instance'));
		if (!is_object($module) || !isset($module->actions_registrar) || !is_object($module->actions_registrar)) {
			return null;
		}

		return $module->actions_registrar;
	}

	/** Reads (or, with $items, replaces) the registrar's private item list, declared by its base Registrar class. */
	private function registrarItems($registrar, $items = null) {
		try {
			$class = new ReflectionClass($registrar);
			while ($class !== false && !$class->hasProperty('items')) {
				$class = $class->getParentClass();
			}
			if ($class === false) {
				return null;
			}

			$property = $class->getProperty('items');
			$property->setAccessible(true);
			if ($items !== null) {
				$property->setValue($registrar, $items);
			}

			return $property->getValue($registrar);
		} catch (ReflectionException $e) {
			return null;
		}
	}
}

endif;
