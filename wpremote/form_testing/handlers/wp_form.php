<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVWPFormHandler')) :

// WPForms (Lite and Pro): CAPTCHA, anti-spam, email and upload handling for the tested form in a signed test request.
class BVWPFormHandler {
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

		$this->sendEmailsInRequest();
		$this->acceptModernUploads();
		$this->skipMediaLibrary();
	}

	public function bypassCaptcha() {
		add_filter('wpforms_process_bypass_captcha', '__return_true', PHP_INT_MAX);
		add_filter('wpforms_process_antispam', '__return_true', PHP_INT_MAX);
		add_filter('wpforms_process_honeypot', '__return_false', PHP_INT_MAX);
		add_filter('wpforms_process_anti_spam_honeypot_bypass', '__return_true', PHP_INT_MAX);
		add_filter('wpforms_process_anti_spam_direct_post_bypass', '__return_true', PHP_INT_MAX);
		$form_id = (string) $this->form_id;
		// Custom Captcha addon: validated as field type "captcha" (wpforms_process_validate_captcha).
		add_action('wpforms_process_validate_captcha', function ($field_id, $field_submit, $form_data) use ($form_id) {
			if (!is_array($form_data) || !isset($form_data['id']) || (string) $form_data['id'] !== $form_id || !function_exists('wpforms')) {
				return;
			}
			$process = wpforms()->get('process');
			if (is_object($process) && isset($process->errors[$form_data['id']][$field_id])) {
				unset($process->errors[$form_data['id']][$field_id]);
			}
		}, PHP_INT_MAX, 3);
	}

	public function bypassEmail() {
		add_filter('wpforms_entry_email', '__return_false', PHP_INT_MAX);
	}

	/**
	 * With "Optimize Email Sending" (setting email-async), WPForms 1.8.5+ queues each notification as an Action
	 * Scheduler task that a later request sends, outside test mode: a real email that mail capture never sees. Send
	 * the tested form's notifications in this request instead.
	 */
	public function sendEmailsInRequest() {
		$form_id = (string) $this->form_id;
		add_filter('wpforms_tasks_entry_emails_trigger_send_same_process', function ($same_process, $fields = array(), $entry = array(), $form_data = array()) use ($form_id) {
			if ($form_id === '' || (is_array($form_data) && isset($form_data['id']) && (string) $form_data['id'] === $form_id)) {
				return true;
			}
			return $same_process;
		}, PHP_INT_MAX, 4);
	}

	public function skipMediaLibrary() {
		$form_id = (string) $this->form_id;
		add_filter('wpforms_process_before_form_data', function ($form_data) use ($form_id) {
			if (!is_array($form_data) || !isset($form_data['id'], $form_data['fields']) || (string) $form_data['id'] !== $form_id || !is_array($form_data['fields'])) {
				return $form_data;
			}
			foreach ($form_data['fields'] as $key => $field) {
				if (is_array($field) && isset($field['type']) && in_array($field['type'], array('file-upload', 'camera'), true) && !empty($field['media_library'])) {
					$form_data['fields'][$key]['media_library'] = '0';
				}
			}
			return $form_data;
		}, PHP_INT_MAX, 1);
	}

	public function acceptModernUploads() {
		$form_id = (string) $this->form_id;
		add_action('wpforms_process_before', function ($entry, $form_data) use ($form_id) {
			if (!is_array($form_data) || !isset($form_data['id'], $form_data['fields']) || (string) $form_data['id'] !== $form_id ||
					empty($_FILES) || !function_exists('wpforms_upload_dir')) {
				return;
			}
			foreach ((array) $form_data['fields'] as $field) {
				if (is_array($field) && isset($field['type'], $field['id'], $field['style']) && $field['type'] === 'file-upload' && $field['style'] === 'modern') {
					BVWPFormHandler::storeModernUpload(sprintf('wpforms_%d_%d', absint($form_data['id']), absint($field['id'])), $field);
				}
			}
		}, 1, 2);
	}

	/**
	 * Extensions WPForms refuses whatever the site allows (WPForms FileMethodsTrait::$denylist, plus the other PHP
	 * extensions servers may run).
	 */
	private static $denied_extensions = array(
		'ade', 'adp', 'app', 'asp', 'bas', 'bat', 'cer', 'cgi', 'chm', 'cmd', 'com', 'cpl', 'crt', 'csh', 'csr', 'dfxp',
		'dll', 'drv', 'exe', 'flv', 'fxp', 'hlp', 'hta', 'htaccess', 'htm', 'html', 'htpasswd', 'inf', 'ins', 'isp',
		'jar', 'js', 'jse', 'jsp', 'ksh', 'lnk', 'mdb', 'mde', 'mdt', 'mdw', 'msc', 'msi', 'msp', 'mst', 'onetmp', 'ops',
		'pcd', 'phar', 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phtml', 'pif', 'pl', 'prg', 'ps1', 'ps2',
		'py', 'rb', 'reg', 'scr', 'sct', 'sh', 'shb', 'shs', 'swf', 'sys', 'tmp', 'torrent', 'url', 'vb', 'vbe', 'vbs',
		'vbscript', 'wsc', 'wsf', 'wsh'
	);

	/**
	 * The extensions a file upload field accepts, as WPForms works them out: the field's list (all when empty),
	 * limited to the file types WordPress allows, without the denied extensions.
	 */
	public static function allowedExtensions($field) {
		$allowed = array();
		foreach (array_keys(get_allowed_mime_types()) as $extensions) {
			foreach (explode('|', $extensions) as $extension) {
				$allowed[] = strtolower($extension);
			}
		}
		$allowed = array_diff($allowed, self::$denied_extensions);
		if (is_array($field) && !empty($field['extensions']) && is_string($field['extensions'])) {
			$listed = array();
			foreach (explode(',', $field['extensions']) as $extension) {
				$listed[] = strtolower(preg_replace('/[^A-Za-z0-9_-]/', '', $extension));
			}
			$allowed = array_intersect($allowed, $listed);
		}
		return array_values(array_unique($allowed));
	}

	/**
	 * Moves one posted file of a modern upload field into the WPForms tmp folder and posts its JSON description.
	 * A file whose extension or type the field doesn't accept is left out, and stays in PHP's upload folder (deleted
	 * when the request ends), so WPForms reports the field as empty or required. A file moved into the tmp folder that
	 * WPForms doesn't take into the form's folder is deleted when the request ends.
	 */
	public static function storeModernUpload($input_name, $field) {
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput
		if (!empty($_POST[$input_name]) || !isset($_FILES[$input_name]['tmp_name'], $_FILES[$input_name]['name'], $_FILES[$input_name]['error']) ||
				!is_string($_FILES[$input_name]['tmp_name']) || !is_string($_FILES[$input_name]['name']) ||
				(int) $_FILES[$input_name]['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($_FILES[$input_name]['tmp_name'])) {
			return;
		}
		$file = $_FILES[$input_name];
		unset($_FILES[$input_name]);
		// phpcs:enable

		$name = sanitize_file_name(wp_unslash($file['name']));
		$extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
		if ($name === '' || $extension === '' || !in_array($extension, self::allowedExtensions($field), true)) {
			return;
		}
		// WordPress's own check of the name against the content (images are sniffed): refused when it finds no
		// allowed type, or when it would rename the file.
		$filetype = wp_check_filetype_and_ext($file['tmp_name'], $name);
		if (empty($filetype['ext']) || empty($filetype['type']) || !empty($filetype['proper_filename']) ||
				strtolower($filetype['ext']) !== $extension) {
			return;
		}

		$upload_dir = wpforms_upload_dir();
		if (!is_array($upload_dir) || empty($upload_dir['path']) || empty($upload_dir['url'])) {
			return;
		}
		$tmp_dir = $upload_dir['path'] . '/tmp';
		if (!wp_mkdir_p($tmp_dir)) {
			return;
		}
		$tmp_name = wp_hash(wp_rand() . microtime() . $input_name) . '.' . $extension;
		$tmp_path = $tmp_dir . '/' . $tmp_name;
		if (!move_uploaded_file($file['tmp_name'], $tmp_path)) {
			return;
		}
		// WPForms moves the file out of the tmp folder when the entry is saved; anything left is a failed submission.
		add_action('shutdown', function () use ($tmp_path) {
			if (is_file($tmp_path)) {
				BVFormTestRecorder::deleteFile($tmp_path);
			}
		});
		if (function_exists('wpforms_sanitize_svg_file') && !wpforms_sanitize_svg_file($tmp_path)) {
			BVFormTestRecorder::deleteFile($tmp_path);
			return;
		}

		$_POST[$input_name] = wp_slash(BVFormTestRecorder::jsonEncode(array(array(
			'name' => $name,
			'file' => $tmp_name,
			'url' => $upload_dir['url'] . '/tmp/' . $tmp_name,
			'size' => filesize($tmp_path),
			'type' => $filetype['type'],
			'file_user_name' => $name
		))));
	}
}

endif;
