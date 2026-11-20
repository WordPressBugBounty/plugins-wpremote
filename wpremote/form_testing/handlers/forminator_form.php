<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVForminatorFormHandler')) :

class BVForminatorFormHandler {
	private $form_id;
	private $bypass_params = array();
	private $captcha_endpoints = array();
	private $created_posts = array();
	private $created_attachments = array();

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

		$this->allowPollTestVotes();
		$this->discardPostDataPosts();
	}

	private function isTestedModule($module_id) {
		return (string) $module_id === (string) $this->form_id;
	}

	/**
	 * Forminator verifies reCAPTCHA (v2 checkbox, v2 invisible, v3), hCaptcha and Turnstile tokens with
	 * Forminator_Captcha_Verification::verify(), a wp_remote_request() to the provider's siteverify URL that
	 * it passes through the forminator_<provider>_verify_endpoint filter. We note that URL and answer the
	 * request ourselves with a passing verdict, so only Forminator's own verification is affected.
	 */
	public function bypassCaptcha() {
		foreach (array('recaptcha', 'hcaptcha', 'turnstile') as $provider) {
			add_filter("forminator_{$provider}_verify_endpoint", function ($endpoint) use ($provider) {
				if (is_string($endpoint) && $endpoint !== '') {
					$this->captcha_endpoints[$endpoint] = $provider;
				}
				return $endpoint;
			}, PHP_INT_MAX);
		}
		add_filter('pre_http_request', array($this, 'stubCaptchaVerification'), PHP_INT_MAX - 1, 3);

		// Forminator before 1.58 skipped its captcha check while a Stripe field was hidden.
		// From 1.58 a hidden Stripe field means "verify the payment token", which needs a token we don't have.
		$this->whenForminatorLoaded(function () {
			if (defined('FORMINATOR_VERSION') && version_compare(FORMINATOR_VERSION, '1.58.0', '<')) {
				$this->markStripeHidden();
			}
		});
	}

	public function stubCaptchaVerification($preempt, $args, $url) {
		if ($preempt !== false || !is_string($url) || !isset($this->captcha_endpoints[$url])) {
			return $preempt;
		}

		$verdict = array('success' => true, 'hostname' => BVFormTestRecorder::parseUrl(home_url(), PHP_URL_HOST));
		// Only reCAPTCHA v3 checks a score, and it wants a high one.
		if ($this->captcha_endpoints[$url] === 'recaptcha') {
			$verdict['score'] = 1.0;
		}

		return array(
			'headers' => array(),
			'body' => BVFormTestRecorder::jsonEncode($verdict),
			'response' => array('code' => 200, 'message' => 'OK'),
			'cookies' => array(),
			'filename' => null
		);
	}

	private function markStripeHidden() {
		if (defined('WP_PLUGIN_DIR')) {
			$abstract_front_action_file_path = WP_PLUGIN_DIR . '/forminator/library/abstracts/abstract-class-front-action.php';
			$front_action_file_path = WP_PLUGIN_DIR . '/forminator/library/modules/custom-forms/front/front-action.php';
			if (is_file($abstract_front_action_file_path) && is_readable($abstract_front_action_file_path) &&
					is_file($front_action_file_path) && is_readable($front_action_file_path)) {
				require_once $abstract_front_action_file_path;
				require_once $front_action_file_path;
				if (class_exists('Forminator_CForm_Front_Action')) {
					Forminator_CForm_Front_Action::$hidden_fields[] = "bv-stripe-";
				}
			}
		}
	}

	public function bypassEmail() {
		foreach (['poll', 'quiz', 'form'] as $type) {
			add_filter("forminator_{$type}_get_admin_email_recipients", function() {
				return [];
			}, PHP_INT_MAX);
		}
	}

	/**
	 * Polls accept one vote per IP (or browser cookie). A test vote must neither be refused because an
	 * earlier test voted, nor lock the poll for the monitoring server's IP: we let the test vote through
	 * and don't store the voter IP with it.
	 */
	private function allowPollTestVotes() {
		add_filter('forminator_poll_handle_form_user_can_vote', function ($can_vote, $poll_id) {
			return $this->isTestedModule($poll_id) ? true : $can_vote;
		}, PHP_INT_MAX, 2);

		// Forminator also blocks the voter's IP for a few seconds after a vote; lift that block for a test vote.
		add_action('forminator_polls_submit_before_set_fields', function ($entry, $poll_id) {
			if ($this->isTestedModule($poll_id)) {
				add_action('shutdown', function () use ($poll_id) {
					$this->clearPollVoteLock($poll_id);
				}, 0);
			}
		}, PHP_INT_MAX, 2);

		add_filter('forminator_polls_submit_field_data', function ($field_data, $poll_id) {
			if (!$this->isTestedModule($poll_id) || !is_array($field_data)) {
				return $field_data;
			}
			return array_values(array_filter($field_data, function ($item) {
				return !(is_array($item) && isset($item['name']) && $item['name'] === '_forminator_user_ip');
			}));
		}, PHP_INT_MAX, 2);
	}

	private function clearPollVoteLock($poll_id) {
		if (!class_exists('Forminator_Geo') || !method_exists('Forminator_Geo', 'get_user_ip')) {
			return;
		}
		$user_ip = Forminator_Geo::get_user_ip();
		delete_transient('forminator_request_from_ip_' . $poll_id . '_' . $user_ip);
		delete_option('forminator_poll_ip_lock_' . $poll_id . '_' . md5($user_ip));
	}

	/**
	 * A Post Data field creates a post. For a test submission it is created as a draft (never published,
	 * so no publish notifications or auto-sharing) and deleted, with any featured image uploaded by the
	 * submission, once the request ends.
	 */
	private function discardPostDataPosts() {
		add_filter('forminator_post_data_post_info', function ($post) {
			if ($this->isCurrentForm() && is_array($post)) {
				$post['post_status'] = 'draft';
			}
			return $post;
		}, PHP_INT_MAX);

		add_action('forminator_post_data_field_post_saved', function ($post_id) {
			if ($this->isCurrentForm()) {
				$this->created_posts[] = absint($post_id);
			}
		}, PHP_INT_MAX);

		add_action('add_attachment', function ($attachment_id) {
			if ($this->isCurrentForm()) {
				$this->created_attachments[] = absint($attachment_id);
			}
		}, PHP_INT_MAX);

		add_action('shutdown', array($this, 'deleteCreatedPosts'), 0);
	}

	private function isCurrentForm() {
		return class_exists('Forminator_CForm_Front_Action') && isset(Forminator_CForm_Front_Action::$module_id) &&
				$this->isTestedModule(Forminator_CForm_Front_Action::$module_id);
	}

	public function deleteCreatedPosts() {
		foreach ($this->created_posts as $post_id) {
			$post = get_post($post_id);
			if ($post_id === 0 || !$post || $post->post_status !== 'draft') {
				continue;
			}
			$thumbnail_id = (int) get_post_thumbnail_id($post_id);
			if ($thumbnail_id > 0 && in_array($thumbnail_id, $this->created_attachments, true)) {
				wp_delete_attachment($thumbnail_id, true);
			}
			wp_delete_post($post_id, true);
		}
		$this->created_posts = array();
	}

	private function whenForminatorLoaded($callback) {
		if (did_action('plugins_loaded')) {
			call_user_func($callback);
		} else {
			add_action('plugins_loaded', $callback, PHP_INT_MIN);
		}
	}
}

endif;
