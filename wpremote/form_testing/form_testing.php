<?php

if (!defined('ABSPATH')) exit;

require_once dirname(__FILE__) . '/recorder.php';
require_once dirname(__FILE__) . '/entries.php';

if (!class_exists('BVFormTesting')) :

// Form test mode for one signed test submission: the tested form's CAPTCHA, email and anti-spam bypasses, and the recorder.
class BVFormTesting {
	private $form_type;
	private $form_id;
	private $spam_bypass;
	private $bypass_params = array();
	private $run_id;
	private $capture_mail;
	private $block_http;
	private $captcha_live;

	public function __construct($params) {
		$this->form_type = isset($params['bv_frm_typ']) ? sanitize_text_field(wp_unslash($params['bv_frm_typ'])) : null;
		$this->form_id = isset($params['bv_frm_id']) ? sanitize_text_field(wp_unslash($params['bv_frm_id'])) : null;
		$this->spam_bypass = isset($params['bv_ignr_spm_plgns']);

		$this->captcha_live = isset($params['bv_frm_cptch_live']);
		// A live-captcha run tests that the form rejects a wrong token: never bypass the captcha then.
		if (isset($params['bv_ignr_frm_cptch']) && !$this->captcha_live) {
			$this->bypass_params['should_bypass_captcha'] = true;
		}

		if (isset($params['bv_ignr_eml'])) {
			$this->bypass_params['should_bypass_email'] = true;
		}

		$run_id = isset($params['bv_frm_run']) && is_string($params['bv_frm_run']) ? sanitize_text_field(wp_unslash($params['bv_frm_run'])) : null;
		$this->run_id = BVFormTestRecorder::isValidRunId($run_id) ? $run_id : null;
		$this->capture_mail = isset($params['bv_frm_cptr_ml']);
		$this->block_http = isset($params['bv_frm_blk_http']);
	}

	/**
	 * Request fields that only a login, registration, checkout or comment sends: exact names, never a pattern (form fields
	 * such as "mf-password" must not match). WordPress's login sends "log" and "pwd" together.
	 */
	private static $refused_fields = array('woocommerce-login-nonce', 'woocommerce-register-nonce', 'woocommerce-process-checkout-nonce',
		'woocommerce-lost-password-nonce', 'woocommerce-reset-password-nonce', 'woocommerce-edit-account-nonce', 'wc-ajax', 'comment_post_ID');

	/**
	 * Whether this is a request a form test never makes (see the class comment): login, registration, comments,
	 * XML-RPC, cron, an admin screen other than admin-ajax.php, a WooCommerce login, checkout or account form.
	 */
	public function isRefusedRequest($request) {
		$request = (array) $request;
		if (defined('XMLRPC_REQUEST') || defined('DOING_CRON') || defined('WP_INSTALLING')) {
			return true;
		}
		$script = isset($_SERVER['SCRIPT_NAME']) && is_string($_SERVER['SCRIPT_NAME']) ? basename($_SERVER['SCRIPT_NAME']) : '';
		if (defined('DOING_AJAX') && DOING_AJAX) {
			if ($script !== 'admin-ajax.php') {
				return true;
			}
		} elseif (is_admin() || $script !== 'index.php') {
			return true;
		}
		if (isset($request['log'], $request['pwd'])) {
			return true;
		}
		foreach (self::$refused_fields as $field) {
			if (isset($request[$field])) {
				return true;
			}
		}
		return false;
	}

	public function init() {
		// Refused, not handled as a normal request: a test submission carried on without test mode would be a real one.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ($this->isRefusedRequest($_REQUEST)) {
			wp_die(esc_html('Form test refused for this request.'), '', array('response' => 403));
		}

		if ($this->spam_bypass === true) {
			$this->bypassSpamPlugins();
		}

		$recorder = null;
		if ($this->run_id !== null) {
			$recorder = new BVFormTestRecorder($this->run_id, $this->capture_mail, $this->block_http, $this->captcha_live,
				array_key_exists('should_bypass_captcha', $this->bypass_params), $this->form_id);
			$recorder->start();
			BVFormTestEntries::watch($recorder);
			$this->watchSubmissionEvents($recorder);
		}

		// Mail capture can only be decided once wp_mail() exists (after all plugins load), and the
		// plugin's own email suppression depends on it, so with capture requested both wait for
		// plugins_loaded. That is still before any form plugin handles the submission.
		if ($recorder !== null && $this->capture_mail) {
			$this->whenPluginsLoaded(function () use ($recorder) {
				$this->applyBypass($recorder);
			});
		} else {
			$this->applyBypass($recorder);
		}
	}

	private function applyBypass($recorder) {
		if ($recorder !== null) {
			$recorder->setupMailCapture();
			// Captured mail never leaves the site, so let the plugin send it to wp_mail() and record it.
			if ($recorder->captureMailEnabled()) {
				unset($this->bypass_params['should_bypass_email']);
			}
		}

		// Always, even with nothing to bypass: besides the CAPTCHA and email bypasses, each handler keeps the test's
		// side effects in check (integrations, created posts and users, asynchronous work), which a submission must
		// never skip. The wrong-CAPTCHA run (bv_frm_cptch_live) with mail capture has no bypass at all, and is exactly
		// the run that goes through as a real submission when the form accepts the wrong token.
		$handler = $this->getHandler($this->form_type);
		if ($handler !== null) {
			$handler->bypass();
		}
	}

	/** Form plugins that store no entry id, or whose handler reports what it did: record the submission's events. */
	private function watchSubmissionEvents($recorder) {
		switch ($this->form_type) {
		case 'ElementorProForm':
			require_once dirname(__FILE__) . '/handlers/elementor_pro_form.php';
			BVElementorProFormHandler::watch($recorder);
			break;
		case 'DiviForm':
			require_once dirname(__FILE__) . '/handlers/divi_form.php';
			BVDiviFormHandler::watch($recorder);
			break;
		case 'SpectraForm':
			require_once dirname(__FILE__) . '/handlers/spectra_form.php';
			BVSpectraFormHandler::watch($recorder);
			break;
		case 'KadenceForm':
			require_once dirname(__FILE__) . '/handlers/kadence_form.php';
			BVKadenceFormHandler::watch($recorder);
			break;
		case 'BeaverBuilderForm':
			require_once dirname(__FILE__) . '/handlers/beaver_builder_form.php';
			BVBeaverBuilderFormHandler::watch($recorder);
			break;
		case 'Mc4wpForm':
			require_once dirname(__FILE__) . '/handlers/mc4wp_form.php';
			BVMc4wpFormHandler::watch($recorder);
			break;
		case 'JetEngineForm':
			require_once dirname(__FILE__) . '/handlers/jet_engine_form.php';
			BVJetEngineFormHandler::watch($recorder);
			break;
		case 'FluentForm':
			require_once dirname(__FILE__) . '/handlers/fluent_form.php';
			BVFluentFormHandler::watch($recorder);
			break;
		}
	}

	private function whenPluginsLoaded($callback) {
		if (did_action('plugins_loaded')) {
			call_user_func($callback);
		} else {
			add_action('plugins_loaded', $callback, PHP_INT_MIN);
		}
	}

	private function getHandler($form_type) {
		switch ($form_type) {
		case 'ContactForm7':
			require_once dirname(__FILE__) . '/handlers/contact_form7.php';
			return new BVContactForm7Handler($this->form_id, $this->bypass_params);
		case 'WPForm':
			require_once dirname(__FILE__) . '/handlers/wp_form.php';
			return new BVWPFormHandler($this->form_id, $this->bypass_params);
		case 'NinjaForm':
			require_once dirname(__FILE__) . '/handlers/ninja_form.php';
			return new BVNinjaFormHandler($this->form_id, $this->bypass_params);
		case 'ForminatorForm':
			require_once dirname(__FILE__) . '/handlers/forminator_form.php';
			return new BVForminatorFormHandler($this->form_id, $this->bypass_params);
		case 'GravityForm':
			require_once dirname(__FILE__) . '/handlers/gravity_form.php';
			return new BVGravityFormHandler($this->form_id, $this->bypass_params);
		case 'FormidableForm':
			require_once dirname(__FILE__) . '/handlers/formidable_form.php';
			return new BVFormidableFormHandler($this->form_id, $this->bypass_params);
		case 'FluentForm':
			require_once dirname(__FILE__) . '/handlers/fluent_form.php';
			return new BVFluentFormHandler($this->form_id, $this->bypass_params);
		case 'ElementorProForm':
			require_once dirname(__FILE__) . '/handlers/elementor_pro_form.php';
			return new BVElementorProFormHandler($this->form_id, $this->bypass_params);
		case 'DiviForm':
			require_once dirname(__FILE__) . '/handlers/divi_form.php';
			return new BVDiviFormHandler($this->form_id, $this->bypass_params);
		case 'MetForm':
			require_once dirname(__FILE__) . '/handlers/met_form.php';
			return new BVMetFormHandler($this->form_id, $this->bypass_params);
		case 'JetFormBuilderForm':
			require_once dirname(__FILE__) . '/handlers/jet_form_builder_form.php';
			return new BVJetFormBuilderFormHandler($this->form_id, $this->bypass_params);
		case 'SureForm':
			require_once dirname(__FILE__) . '/handlers/sure_form.php';
			return new BVSureFormHandler($this->form_id, $this->bypass_params);
		case 'JetpackForm':
			require_once dirname(__FILE__) . '/handlers/jetpack_form.php';
			return new BVJetpackFormHandler($this->form_id, $this->bypass_params);
		case 'SpectraForm':
			require_once dirname(__FILE__) . '/handlers/spectra_form.php';
			return new BVSpectraFormHandler($this->form_id, $this->bypass_params);
		case 'KadenceForm':
			require_once dirname(__FILE__) . '/handlers/kadence_form.php';
			return new BVKadenceFormHandler($this->form_id, $this->bypass_params);
		case 'BeaverBuilderForm':
			require_once dirname(__FILE__) . '/handlers/beaver_builder_form.php';
			return new BVBeaverBuilderFormHandler($this->form_id, $this->bypass_params);
		case 'AvadaForm':
			require_once dirname(__FILE__) . '/handlers/avada_form.php';
			return new BVAvadaFormHandler($this->form_id, $this->bypass_params);
		case 'MailPoetForm':
			require_once dirname(__FILE__) . '/handlers/mail_poet_form.php';
			return new BVMailPoetFormHandler($this->form_id, $this->bypass_params);
		case 'Mc4wpForm':
			require_once dirname(__FILE__) . '/handlers/mc4wp_form.php';
			return new BVMc4wpFormHandler($this->form_id, $this->bypass_params);
		case 'JetEngineForm':
			require_once dirname(__FILE__) . '/handlers/jet_engine_form.php';
			return new BVJetEngineFormHandler($this->form_id, $this->bypass_params);
		default:
			return null;
		}
	}

	private function bypassSpamPlugins() {
		add_action('init', function() {
			global $apbct;
			if (isset($apbct) && is_object($apbct)) {
				$apbct->settings['forms__contact_forms_test'] = 0;
			}
		}, PHP_INT_MAX);

		add_filter('akismet_get_api_key', function () {
			return null;
		}, PHP_INT_MAX);
	}
}

endif;