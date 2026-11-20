<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVKadenceFormHandler')) :

// Kadence Blocks forms (and Kadence Blocks Pro actions): CAPTCHA and email bypasses for the tested form in a signed test request.
class BVKadenceFormHandler {
	const LEGACY_ACTION = 'kb_process_ajax_submit';
	const ADVANCED_ACTION = 'kb_process_advanced_form_submit';
	const LEGACY_ID_BASE = 1000000000;

	private static $verify_urls = array(
		'https://www.google.com/recaptcha/api/siteverify',
		'https://www.recaptcha.net/recaptcha/api/siteverify',
		'https://challenges.cloudflare.com/turnstile/v0/siteverify',
		'https://api.hcaptcha.com/siteverify',
		'https://hcaptcha.com/siteverify'
	);
	private static $integration_actions = array('mailerlite', 'fluentCRM', 'sendinblue', 'mailchimp', 'convertkit',
		'getresponse', 'activecampaign', 'webhook');
	private static $email_actions = array('email', 'autoEmail');

	private static $legacy_unique_id = null;
	private static $removed_actions = array();

	private $form_id;
	private $bypass_params = array();
	private $uploads = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = absint($form_id);
		$this->bypass_params = $bypass_params;
	}

	/** The tested form's id as KadenceForm computes it for a legacy block. */
	public static function legacyFormId($post_id, $unique_id) {
		// %u: crc32() is unsigned on 64-bit PHP but may be negative on 32-bit builds.
		return self::LEGACY_ID_BASE + (int) fmod((float) sprintf('%u', crc32($post_id . ':' . $unique_id)), self::LEGACY_ID_BASE);
	}

	private static function postValue($key) {
		return (isset($_POST[$key]) && is_string($_POST[$key])) ? sanitize_text_field(wp_unslash($_POST[$key])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
	}

	/** 'legacy' / 'advanced' when this request is the submission of the tested form, else null. */
	private function testedKind() {
		$action = self::postValue('action');
		if ($action === self::ADVANCED_ACTION) {
			return absint(self::postValue('_kb_adv_form_post_id')) === $this->form_id ? 'advanced' : null;
		}
		if ($action === self::LEGACY_ACTION) {
			$post_id = self::postValue('_kb_form_post_id');
			$unique_id = self::postValue('_kb_form_id');
			if ($unique_id !== '' && $post_id !== '' && self::legacyFormId($post_id, $unique_id) === $this->form_id) {
				return 'legacy';
			}
		}
		return null;
	}

	public function bypass() {
		if ($this->form_id <= 0) {
			return;
		}
		$kind = $this->testedKind();
		if ($kind === null) {
			return;
		}

		$bypass_captcha = array_key_exists('should_bypass_captcha', $this->bypass_params);
		$bypass_email = array_key_exists('should_bypass_email', $this->bypass_params);

		// Honeypot and nonce: a signed test request fills neither.
		unset($_POST['_kb_verify_email']);
		add_filter('kadence_blocks_form_verify_nonce', '__return_false', PHP_INT_MAX);

		self::$removed_actions = self::$integration_actions;
		if ($bypass_email) {
			self::$removed_actions = array_merge(self::$removed_actions, self::$email_actions);
		}

		if ($bypass_captcha) {
			// Runs before the recorder's own HTTP blocking (PHP_INT_MAX), which keeps a non-false answer.
			add_filter('pre_http_request', array($this, 'answerCaptchaVerification'), 10, 3);
		}

		if ($kind === 'legacy') {
			self::$legacy_unique_id = self::postValue('_kb_form_id');
			self::$removed_actions[] = 'entry';
			if (!class_exists('BVKadenceLegacyBlockParser')) {
				return;
			}
			add_filter('block_parser_class', function () {
				return 'BVKadenceLegacyBlockParser';
			}, PHP_INT_MAX);
		} else {
			add_filter('kadence_blocks_advanced_form_form_args', array($this, 'filterAdvancedFormArgs'), PHP_INT_MAX, 3);
			add_filter('wp_handle_upload', array($this, 'collectUpload'), PHP_INT_MAX, 2);
			add_action('shutdown', array($this, 'deleteUploads'), PHP_INT_MAX - 1);
		}
	}

	/** Records that Kadence Blocks handled a form submission (it stores no entry of its own). */
	public static function watch($recorder) {
		add_action('kadence_blocks_form_submission', function ($form_args, $fields, $form_id, $post_id) use ($recorder) {
			$recorder->addEvent('kadence', 'submit', is_scalar($form_id) ? $form_id : '');
		}, PHP_INT_MAX, 4);
		add_action('kadence_blocks_advanced_form_submission', function ($form_args, $fields, $post_id) use ($recorder) {
			$recorder->addEvent('kadence', 'submit', is_scalar($post_id) ? $post_id : '');
		}, PHP_INT_MAX, 3);
	}

	public function answerCaptchaVerification($preempt, $args, $url) {
		if ($preempt !== false || !in_array(strtok((string) $url, '?'), self::$verify_urls, true)) {
			return $preempt;
		}
		return array(
			'headers' => array(),
			'body' => BVFormTestRecorder::jsonEncode(array('success' => true, 'score' => 0.9, 'action' => 'kb_form', 'hostname' => BVFormTestRecorder::parseUrl(home_url(), PHP_URL_HOST))),
			'response' => array('code' => 200, 'message' => 'OK'),
			'cookies' => array(),
			'filename' => null
		);
	}

	/** The tested advanced form's settings without the suppressed actions. */
	public function filterAdvancedFormArgs($form_args, $processed_fields, $post_id) {
		if (absint($post_id) !== $this->form_id || !is_array($form_args)) {
			return $form_args;
		}
		if (!isset($form_args['attributes']) || !is_array($form_args['attributes'])) {
			$form_args['attributes'] = array();
		}
		$actions = isset($form_args['attributes']['actions']) ? (array) $form_args['attributes']['actions'] : array('email');
		$form_args['attributes']['actions'] = self::withoutRemovedActions($actions);
		return $form_args;
	}

	private static function withoutRemovedActions($actions) {
		return array_values(array_filter($actions, function ($action) {
			return !in_array($action, self::$removed_actions, true);
		}));
	}

	/** The legacy kadence/form block of the tested form, wherever it is nested, with the suppressed actions removed. */
	public static function filterLegacyBlocks($blocks) {
		if (!is_array($blocks)) {
			return $blocks;
		}
		foreach ($blocks as $index => $block) {
			if (!is_array($block)) {
				continue;
			}
			if (isset($block['blockName']) && $block['blockName'] === 'kadence/form' && isset($block['attrs']['uniqueID']) &&
					$block['attrs']['uniqueID'] === self::$legacy_unique_id) {
				$actions = isset($block['attrs']['actions']) ? (array) $block['attrs']['actions'] : array('email');
				$blocks[$index]['attrs']['actions'] = self::withoutRemovedActions($actions);
			}
			if (!empty($block['innerBlocks'])) {
				$blocks[$index]['innerBlocks'] = self::filterLegacyBlocks($block['innerBlocks']);
			}
		}
		return $blocks;
	}

	/** Files the tested advanced form uploads (KB_Ajax_Advanced_Form stores them under uploads/kadence_form). */
	public function collectUpload($upload, $context = 'upload') {
		if (is_array($upload) && !empty($upload['file']) && strpos(str_replace('\\', '/', (string) $upload['file']), '/kadence_form/') !== false) {
			$this->uploads[] = (string) $upload['file'];
		}
		return $upload;
	}

	public function deleteUploads() {
		$uploads = wp_upload_dir();
		$base = isset($uploads['basedir']) ? realpath($uploads['basedir'] . DIRECTORY_SEPARATOR . 'kadence_form') : false;
		if ($base === false) {
			return;
		}
		foreach (array_slice($this->uploads, 0, 20) as $file) {
			$path = realpath($file);
			if ($path !== false && strpos($path, $base . DIRECTORY_SEPARATOR) === 0 && is_file($path)) {
				BVFormTestRecorder::deleteFile($path);
			}
		}
	}
}

/** WP_Block_Parser that hands the parsed blocks to BVKadenceFormHandler::filterLegacyBlocks (block_parser_class). */
if (class_exists('WP_Block_Parser') && !class_exists('BVKadenceLegacyBlockParser')) {
	class BVKadenceLegacyBlockParser extends WP_Block_Parser {
		public function parse($document) {
			return BVKadenceFormHandler::filterLegacyBlocks(parent::parse($document));
		}
	}
}

endif;
