<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVBeaverBuilderFormHandler')) :

// Beaver Builder Contact and Subscribe Form modules: CAPTCHA and email bypasses for the tested module in a signed test request.
class BVBeaverBuilderFormHandler {
	const CONTACT_ACTION = 'fl_builder_email';
	const SUBSCRIBE_ACTION = 'fl_builder_subscribe_form_submit';
	const LOCAL_SERVICE = 'email-address';
	const CAPTCHA_RESPONSE_KEYS = array('recaptcha', 'recaptcha_response', 'hcaptcha', 'hcaptcha_response', 'g-recaptcha-response', 'h-captcha-response');

	private $form_id;
	private $bypass_params = array();
	private $skip_next_mail = false;

	public function __construct($form_id, $bypass_params) {
		$this->form_id = $form_id;
		$this->bypass_params = $bypass_params;
	}

	public static function submittedAction() {
		$action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
		return in_array($action, array(self::CONTACT_ACTION, self::SUBSCRIBE_ACTION), true) ? $action : null;
	}

	/** Node ids whose settings the module reads in this request (the node and, for a global module, its template node). */
	public static function submittedNodeIds() {
		$ids = array();
		foreach (array('node_id', 'template_node_id') as $key) {
			if (isset($_POST[$key]) && is_string($_POST[$key]) && preg_match('/^[A-Za-z0-9_-]+$/', $_POST[$key]) === 1) {
				$ids[] = $_POST[$key];
			}
		}
		return $ids;
	}

	public function bypass() {
		$action = self::submittedAction();
		$node_ids = self::submittedNodeIds();
		if ($action === null || empty($node_ids)) {
			return;
		}

		if (array_key_exists('should_bypass_captcha', $this->bypass_params)) {
			// The subscribe module verifies a posted response whatever its captcha setting says (2.2).
			foreach (self::CAPTCHA_RESPONSE_KEYS as $key) {
				unset($_POST[$key], $_REQUEST[$key]);
			}
			$handler = $this;
			add_filter('fl_builder_layout_data', function ($data) use ($handler, $node_ids) {
				return $handler->hideCaptcha($data, $node_ids);
			}, PHP_INT_MAX);
		}

		$suppress_email = array_key_exists('should_bypass_email', $this->bypass_params);
		if ($action === self::SUBSCRIBE_ACTION) {
			$handler = $this;
			$stub = function () use ($handler, $suppress_email) {
				$handler->stubService($suppress_email);
			};
			// Before the module's own handler (priority 10).
			add_action('wp_ajax_' . self::SUBSCRIBE_ACTION, $stub, 1);
			add_action('wp_ajax_nopriv_' . self::SUBSCRIBE_ACTION, $stub, 1);
		} elseif ($suppress_email) {
			add_action('fl_module_contact_form_before_send', array($this, 'markFormMail'), PHP_INT_MAX);
			add_filter('pre_wp_mail', array($this, 'skipFormMail'), PHP_INT_MAX);
		}
	}

	public function hideCaptcha($data, $node_ids) {
		if (!is_array($data)) {
			return $data;
		}
		foreach ($node_ids as $node_id) {
			if (!isset($data[$node_id]) || !is_object($data[$node_id]) || !isset($data[$node_id]->settings) || !is_object($data[$node_id]->settings)) {
				continue;
			}
			// get_layout_data() clones nodes but not their settings, which stay shared with Beaver Builder's cache.
			$node = clone $data[$node_id];
			$settings = clone $node->settings;
			foreach (get_object_vars($settings) as $key => $value) {
				if (stripos($key, 'captcha') !== false && $value === 'show') {
					$settings->$key = 'hide';
				}
			}
			$node->settings = $settings;
			$data[$node_id] = $node;
		}
		return $data;
	}

	/** The posted subscribe module's settings, read as the module reads them. */
	private static function subscribeSettings() {
		if (!class_exists('FLBuilderModel')) {
			return null;
		}
		$node_id = isset($_POST['node_id']) ? sanitize_text_field($_POST['node_id']) : '';
		$template_id = isset($_POST['template_id']) ? sanitize_text_field($_POST['template_id']) : '';
		$template_node_id = isset($_POST['template_node_id']) ? sanitize_text_field($_POST['template_node_id']) : '';
		if ($node_id === '') {
			return null;
		}
		if ($template_id !== '') {
			$post_id = FLBuilderModel::get_node_template_post_id($template_id);
			$data = FLBuilderModel::get_layout_data('published', $post_id);
			return isset($data[$template_node_id]->settings) ? $data[$template_node_id]->settings : null;
		}
		$module = FLBuilderModel::get_module($node_id);
		return is_object($module) && isset($module->settings) ? $module->settings : null;
	}

	public function stubService($suppress_email) {
		if (!class_exists('FLBuilderServices')) {
			return;
		}
		$settings = self::subscribeSettings();
		$service = is_object($settings) && isset($settings->service) && is_string($settings->service) ? $settings->service : '';
		if ($service === '' || ($service === self::LOCAL_SERVICE && !$suppress_email)) {
			return;
		}
		$services = FLBuilderServices::get_services_data();
		if (!isset($services[$service]['class'])) {
			return;
		}
		$class = $services[$service]['class'];
		if (class_exists($class, false)) {
			// The real service class is already loaded and cannot be replaced: never reach the service from a test.
			wp_send_json(array('action' => false, 'error' => 'BlogVault form test: the ' . $service . ' subscribe service could not be stubbed', 'message' => false, 'url' => false));
		}
		BVBeaverBuilderStubService::$service = $service;
		class_alias('BVBeaverBuilderStubService', $class);
	}

	public function markFormMail() {
		$this->skip_next_mail = true;
	}

	public function skipFormMail($return) {
		if ($this->skip_next_mail !== true || $return !== null) {
			return $return;
		}
		$this->skip_next_mail = false;
		return true;
	}

	/** Watches for the handled submission (called by BVFormTesting when a run is recorded). */
	public static function watch($recorder) {
		add_action('fl_module_contact_form_after_send', function ($mailto = '', $subject = '', $template = '', $headers = array(), $settings = null, $result = true) use ($recorder) {
			$recorder->addEvent('beaver_builder', $result ? 'contact_sent' : 'contact_mail_error', BVBeaverBuilderFormHandler::postedNodeId());
		}, PHP_INT_MAX, 6);
		add_action('fl_builder_subscribe_form_submission_complete', function ($response = array(), $settings = null) use ($recorder) {
			$name = 'subscribe';
			if (is_array($response) && !empty($response['error'])) {
				$name = 'subscribe_error';
			} elseif (is_array($response) && !empty($response['bv_form_test_stub'])) {
				$name = 'subscribe_stubbed:' . $response['bv_form_test_stub'];
			}
			$recorder->addEvent('beaver_builder', $name, BVBeaverBuilderFormHandler::postedNodeId());
		}, PHP_INT_MAX, 2);
	}

	public static function postedNodeId() {
		return isset($_POST['node_id']) && is_string($_POST['node_id']) ? sanitize_text_field($_POST['node_id']) : '';
	}
}

/** Stands in for a Beaver Builder subscribe service class during a signed test submission: subscribes nobody. */
class BVBeaverBuilderStubService {
	public static $service = '';

	public function subscribe($settings, $email, $name = false) {
		return array('error' => false, 'bv_form_test_stub' => self::$service);
	}

	public function __call($method, $args) {
		return array('error' => false);
	}
}

endif;
