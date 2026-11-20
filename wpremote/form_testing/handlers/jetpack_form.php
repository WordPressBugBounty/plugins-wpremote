<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVJetpackFormHandler')) :

// Jetpack Forms: form token, spam check, email and integration bypasses for the tested form in a signed test request.
class BVJetpackFormHandler {
	const FORM_ID_FACTOR = 100;
	const JWT_INPUT = 'jetpack_contact_form_jwt';
	const FORM_CLASS = '\Automattic\Jetpack\Forms\ContactForm\Contact_Form';
	const INTEGRATIONS_HOOK = 'grunion_after_feedback_post_inserted';

	private $form_id;
	private $bypass_params = array();

	public function __construct($form_id, $bypass_params) {
		$this->form_id = absint($form_id);
		$this->bypass_params = $bypass_params;
	}

	public function bypass() {
		if (!$this->isTestedSubmission()) {
			return;
		}

		$handler = $this;
		// Jetpack registers its blocks and shortcodes on init; it handles the POST on template_redirect
		// (page) or wp_ajax_(nopriv_)grunion-contact-form, both after wp_loaded.
		add_action('wp_loaded', function () use ($handler) {
			$handler->addFormToken();
		}, PHP_INT_MAX);

		$bypass_captcha = array_key_exists('should_bypass_captcha', $this->bypass_params);
		// Both filters run in Contact_Form::process_submission() before the response is stored; the
		// disallowed-list one runs for every submission, so it also switches the integrations off there.
		add_filter('jetpack_contact_form_is_spam', function ($is_spam) use ($bypass_captcha) {
			return $bypass_captcha ? false : $is_spam;
		}, PHP_INT_MAX);
		add_filter('jetpack_contact_form_in_comment_disallowed_list', function ($in_list) use ($bypass_captcha) {
			remove_all_actions(BVJetpackFormHandler::INTEGRATIONS_HOOK);
			return $bypass_captcha ? false : $in_list;
		}, PHP_INT_MAX);

		if (array_key_exists('should_bypass_email', $this->bypass_params)) {
			add_filter('grunion_should_send_email', '__return_false', PHP_INT_MAX);
			add_filter('jetpack_forms_send_test_feedback_email', '__return_false', PHP_INT_MAX);
		}
	}

	/**
	 * Whether visitors can see the post, so a form in it is one the site shows. A published post is not enough: Jetpack
	 * stores each response as a published feedback post (a post type no one can view) holding the visitor's message,
	 * which may itself contain a [contact-form] shortcode.
	 */
	public static function isPublicPost($post) {
		if (!is_object($post) || !isset($post->post_type, $post->post_status) || $post->post_status !== 'publish' ||
				$post->post_type === 'feedback' || post_password_required($post)) {
			return false;
		}
		if (function_exists('is_post_publicly_viewable')) {
			return is_post_publicly_viewable($post);
		}
		return function_exists('is_post_type_viewable') && is_post_type_viewable($post->post_type);
	}

	/** The post holding the tested form and the contact-form-id Jetpack renders for it. */
	private function testedForm() {
		$post_id = intdiv($this->form_id, self::FORM_ID_FACTOR);
		$index = $this->form_id % self::FORM_ID_FACTOR;
		return array($post_id, ($index === 0) ? (string) $post_id : $post_id . '-' . $index);
	}

	/** Whether this request submits the tested form. */
	private function isTestedSubmission() {
		if ($this->form_id <= 0 || !isset($_POST['action'], $_POST['contact-form-id']) || $_POST['action'] !== 'grunion-contact-form' ||
				!is_string($_POST['contact-form-id'])) {
			return false;
		}
		list($post_id, $id) = $this->testedForm();
		return $post_id > 0 && wp_unslash($_POST['contact-form-id']) === $id;
	}

	/**
	 * A test submission without page HTML has no token: render the tested form's post as its page does
	 * (the post as the global post, so the form gets the same id, hash and source) and post that form's
	 * token and hash. A posted token (monitor run with the page's values) is left alone.
	 */
	public function addFormToken() {
		$class = self::FORM_CLASS;
		if ((isset($_POST[self::JWT_INPUT]) && is_string($_POST[self::JWT_INPUT]) && $_POST[self::JWT_INPUT] !== '') ||
				!class_exists($class) || !method_exists($class, 'get_jwt') || !property_exists($class, 'forms')) {
			return;
		}
		list($post_id, $id) = $this->testedForm();
		$post = get_post($post_id);
		if (!self::isPublicPost($post)) {
			return;
		}

		global $wp_query;
		$saved_post = isset($GLOBALS['post']) ? $GLOBALS['post'] : null;
		$saved_forms = $class::$forms;
		$saved_context = property_exists($class, 'forms_context') ? $class::$forms_context : null;
		// With a token posted, Jetpack does not validate the fields while rendering (that would record
		// errors for the form id); the real token replaces this placeholder below.
		$_POST[self::JWT_INPUT] = 'bv-form-test';
		$form = null;
		try {
			$class::$forms = array();
			if ($saved_context !== null) {
				$class::$forms_context = array();
			}
			$GLOBALS['post'] = $post;
			setup_postdata($post);
			apply_filters('the_content', $post->post_content);
			foreach ($class::$forms as $candidate) {
				if (is_object($candidate) && method_exists($candidate, 'get_attribute') && (string) $candidate->get_attribute('id') === $id) {
					$form = $candidate;
					break;
				}
			}
			if ($form !== null) {
				$_POST[self::JWT_INPUT] = $form->get_jwt();
				$_POST['contact-form-hash'] = $form->hash;
			}
		} catch (Throwable $e) {
			$form = null;
		}

		if ($form === null) {
			unset($_POST[self::JWT_INPUT]);
		}
		$class::$forms = $saved_forms;
		if ($saved_context !== null) {
			$class::$forms_context = $saved_context;
		}
		if (method_exists($class, 'reset_errors')) {
			$class::reset_errors();
		}
		if (is_object($wp_query) && method_exists($wp_query, 'reset_postdata')) {
			wp_reset_postdata();
		}
		$GLOBALS['post'] = $saved_post;
	}
}

endif;
