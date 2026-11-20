<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVFluentFormHandler')) :

// Fluent Forms: CAPTCHA, email and integration bypasses for the tested form in a signed test request.
class BVFluentFormHandler {
	const EMAIL_FEED = 'notifications';
	const EMAIL_INTEGRATION = 'email_notifications';

	private static $recorder = null;

	private $form_id;
	private $bypass_params = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = $form_id;
		$this->bypass_params = $bypass_params;
	}

	/** The run's recorder (called by BVFormTesting when a run is recorded): skipped feeds are noted in it. */
	public static function watch($recorder) {
		self::$recorder = $recorder;
	}

	public function bypass() {
		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			$this->bypassCaptcha();
			$this->bypassSpamChecks();
		}

		$this->acceptAttachedUploads();
		$this->limitFeeds();
	}

	private function bypassCaptcha() {
		$form_id = $this->form_id;
		add_filter('fluentform/disable_captcha', function ($disable, $form) use ($form_id) {
			return $this->isTestedForm($form, $form_id) ? true : $disable;
		}, PHP_INT_MAX, 2);
	}

	/**
	 * Fluent's own anti-spam checks for the tested form only: the honeypot and the protection token are
	 * filled in by the browser's JS, the per-IP limit blocks repeated monitor runs from one server, and
	 * Akismet / CleanTalk would score the sample values.
	 */
	private function bypassSpamChecks() {
		$form_id = (string) $this->form_id;
		$is_tested = function ($checked_form_id) use ($form_id) {
			return (string) $checked_form_id === $form_id;
		};

		foreach (array('fluentform/akismet_check_spam', 'fluentform/cleantalk_check_spam') as $filter) {
			add_filter($filter, function ($is_spam_check, $checked_form_id) use ($is_tested) {
				return $is_tested($checked_form_id) ? false : $is_spam_check;
			}, PHP_INT_MAX, 2);
		}

		foreach (array('fluentform/honeypot_status', 'fluentform/token_based_spam_protection_status', 'fluentform/prevent_malicious_attacks') as $filter) {
			add_filter($filter, function ($status, $checked_form_id = null) use ($is_tested) {
				return $is_tested($checked_form_id) ? false : $status;
			}, PHP_INT_MAX, 2);
		}
	}

	/** The tested form's feeds: see the class comment. */
	private function limitFeeds() {
		add_filter('fluentform/global_notification_active_types', array($this, 'filterFeedTypes'), PHP_INT_MAX, 2);
		add_filter('fluentform/notifying_async_' . self::EMAIL_INTEGRATION, array($this, 'keepInRequest'), PHP_INT_MAX, 2);
	}

	public function filterFeedTypes($types, $checked_form_id = null) {
		if (!is_array($types) || (string) $checked_form_id !== (string) $this->form_id) {
			return $types;
		}

		$kept = array();
		$removed = array();
		foreach ($types as $meta_key => $integration_key) {
			$keep = ((string) $meta_key === self::EMAIL_FEED) && !array_key_exists('should_bypass_email', $this->bypass_params);
			if ($keep) {
				$kept[$meta_key] = $integration_key;
			} else {
				$removed[] = (string) $meta_key;
			}
		}
		if (self::$recorder !== null) {
			foreach (self::enabledFeedKeys($checked_form_id, $removed) as $meta_key) {
				self::$recorder->addEvent('fluent_forms', 'skipped_feed:' . substr($meta_key, 0, 40), $checked_form_id);
			}
		}
		return $kept;
	}

	/**
	 * Of these feed types, the ones the form has an enabled feed of (its fluentform_form_meta rows, as Fluent's own
	 * GlobalNotificationService::getEnabledFeeds reads them; conditions are not evaluated): the feeds the test skipped.
	 */
	public static function enabledFeedKeys($form_id, $meta_keys) {
		global $wpdb;
		$form_id = absint($form_id);
		$meta_keys = array_values(array_unique(array_filter(array_map('strval', (array) $meta_keys))));
		if ($form_id === 0 || empty($meta_keys) || !is_object($wpdb)) {
			return array();
		}
		$meta_keys = array_slice($meta_keys, 0, 50);
		$placeholders = implode(', ', array_fill(0, count($meta_keys), '%s'));
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		$rows = $wpdb->get_results($wpdb->prepare("SELECT meta_key, value FROM {$wpdb->prefix}fluentform_form_meta WHERE form_id = %d AND meta_key IN ($placeholders) LIMIT 50",
			array_merge(array($form_id), $meta_keys)), ARRAY_A);
		// phpcs:enable
		$enabled = array();
		foreach ((array) $rows as $row) {
			$value = (is_array($row) && isset($row['value'])) ? json_decode((string) $row['value'], true) : null;
			if (is_array($value) && !empty($value['enabled']) && $value['enabled'] !== 'false') {
				$enabled[] = (string) $row['meta_key'];
			}
		}
		return array_values(array_unique($enabled));
	}

	/** The tested form's email notifications are sent in this request (where mail capture sees them), never queued. */
	public function keepInRequest($async, $checked_form_id = null) {
		return ((string) $checked_form_id === (string) $this->form_id) ? false : $async;
	}

	/** Before Fluent handles the tested form's submission (its handler runs at priority 10). */
	private function acceptAttachedUploads() {
		if (empty($_FILES)) {
			return;
		}
		foreach (array('wp_ajax_fluentform_submit', 'wp_ajax_nopriv_fluentform_submit') as $action) {
			add_action($action, array($this, 'uploadAttachedFiles'), 1);
		}
	}

	public function uploadAttachedFiles() {
		$form_id = isset($_POST['form_id']) ? absint($_POST['form_id']) : 0;
		if ($form_id === 0 || (string) $form_id !== (string) $this->form_id || !class_exists('FluentFormPro\Uploader') ||
				!function_exists('wpFluentForm') || !function_exists('wpFluent') || !function_exists('fluentValidator') ||
				!class_exists('FluentForm\App\Modules\Form\FormFieldsParser') || !class_exists('FluentForm\App\Helpers\Protector') ||
				!class_exists('FluentForm\App\Services\Parser\Validations')) {
			return;
		}
		$app = wpFluentForm();
		$form = wpFluent()->table('fluentform_forms')->find($form_id);
		// request is a container binding (magic property): isset() is false for it.
		$request = is_object($app) ? $app->request : null;
		if (!$form || !is_object($request) || !method_exists($request, 'files') || !method_exists($request, 'set')) {
			return;
		}

		$all_files = $request->files();
		$fields = FluentForm\App\Modules\Form\FormFieldsParser::getInputsByElementTypes($form, array('input_file', 'input_image'), array('rules', 'settings'));
		// One uploader for the request: overrideUploadDir() adds its upload folder and renaming filters each time.
		$uploader = new FluentFormPro\Uploader($app);
		$uploader->setForm($form->id);
		$uploader->overrideUploadDir();
		$pairs = array();
		foreach ((array) $fields as $name => $field) {
			if (!is_string($name) || !isset($all_files[$name])) {
				continue;
			}
			foreach ($this->uploadToTemp($form, $name, array($name => $field), $all_files[$name]) as $url) {
				$pairs[] = rawurlencode($name . '[]') . '=' . rawurlencode($url);
			}
		}
		if (empty($pairs)) {
			return;
		}

		$data = (string) $request->get('data', '');
		$data .= ($data === '' ? '' : '&') . implode('&', $pairs);
		$request->set('data', $data);
		$_POST['data'] = $data;
		$_REQUEST['data'] = $data;
	}

	/** The temp file URLs of one field's attached files, as FluentFormPro\Uploader::upload() returns them. */
	private function uploadToTemp($form, $name, $field, $files) {
		$files = is_array($files) ? array_values($files) : array($files);
		$urls = array();
		foreach (array_slice($files, 0, 5) as $file) {
			if (!is_object($file) || !method_exists($file, 'toArray')) {
				continue;
			}
			$input = array($name => $file);
			// FormFieldsParser::getField() and ::getValidations() cache their first result per form (which the
			// submission's own validation must not get): the field comes from the caller, the rules from the parser.
			list($rules, $messages) = (new FluentForm\App\Services\Parser\Validations($field, $input))->get();
			// Uploader::delegateValidations: the validator knows these rules as max and mimes.
			foreach ($rules as &$rule) {
				$rule = str_replace(array('max_file_size', 'allowed_file_types'), array('max', 'mimes'), $rule);
			}
			unset($rule);
			$renamed = array();
			foreach ($messages as $key => $message) {
				$renamed[str_replace(array('max_file_size', 'allowed_file_types'), array('max', 'mimes'), $key)] = $message;
			}
			$validations = apply_filters('fluentform/file_upload_validations', array($rules, $renamed), $form);
			if (fluentValidator($input, $validations[0], $validations[1])->validate()->fails()) {
				continue;
			}

			$file_array = $file->toArray();
			$args = apply_filters('fluentform/uploader_args', array('test_form' => false), $file_array, $form);
			$uploaded = wp_handle_upload($file_array, $args);
			if (!is_array($uploaded) || !empty($uploaded['error']) || empty($uploaded['file'])) {
				continue;
			}
			$basename = $uploaded['file'];
			$this->forgetTempFileAtShutdown($basename);
			$uploaded['file'] = FluentForm\App\Helpers\Protector::encrypt($basename);
			$uploaded['url'] = str_replace($basename, $uploaded['file'], $uploaded['url']);
			$uploaded = apply_filters('fluentform/file_uploaded', $uploaded, array('formId' => $form->id), $form);
			if (is_array($uploaded) && !empty($uploaded['url'])) {
				$urls[] = $uploaded['url'];
			}
		}
		return $urls;
	}

	/**
	 * The submission copies each temp upload into place (Uploader::initUploads), so the test's temp copy is deleted
	 * when the request ends instead of waiting for Pro's temp cleanup. Only the file this handler uploaded.
	 */
	private function forgetTempFileAtShutdown($basename) {
		$basename = basename((string) $basename);
		if ($basename === '' || strpos($basename, 'ff-') !== 0 || !defined('FLUENTFORM_UPLOAD_DIR')) {
			return;
		}
		$uploads = wp_upload_dir();
		$path = $uploads['basedir'] . FLUENTFORM_UPLOAD_DIR . '/temp/' . $basename;
		add_action('shutdown', function () use ($path) {
			if (is_file($path)) {
				BVFormTestRecorder::deleteFile($path);
			}
		});
	}

	private function isTestedForm($form, $form_id) {
		return is_object($form) && isset($form->id) && (string) $form->id === (string) $form_id;
	}
}

endif;
