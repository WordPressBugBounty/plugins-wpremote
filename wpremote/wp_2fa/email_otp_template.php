<?php
if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWP2FAEmailOTPTemplate')) :
class WPRWP2FAEmailOTPTemplate {
	const OTP_PLACEHOLDER = '{{otp}}';
	const DURATION_PLACEHOLDER = '{{duration}}';

	private $code;
	private $site_name;
	private $duration;

	public function __construct($code, $lifetime) {
		$this->code = $code;
		$this->site_name = $this->siteName();
		$this->duration = $this->duration($lifetime);
	}

	public function subject() {
		return sprintf('Your sign-in code for %s', $this->site_name);
	}

	public function body() {
		$custom_body = $this->customBody();

		return $custom_body !== null ? $custom_body : $this->defaultBody();
	}

	public function headers() {
		return array('Content-Type: text/plain; charset=UTF-8');
	}

	private function defaultBody() {
		return sprintf("Your sign-in code is %s.\n\nSite: %s (%s)\nThis code expires in %s.\n\nIf you did not request this code, you can ignore this email and review your account security.", $this->code, $this->site_name, home_url('/'), $this->duration);
	}

	private function customBody() {
		$payload = $this->getPayload();
		if (!is_array($payload) || !isset($payload['body_b64']) || !is_string($payload['body_b64'])) {
			return null;
		}

		$body = base64_decode($payload['body_b64'], true);
		if ($body === false) {
			return null;
		}

		$body = wp_strip_all_tags($body);
		if (strpos($body, self::OTP_PLACEHOLDER) === false || strpos($body, self::DURATION_PLACEHOLDER) === false) {
			return null;
		}

		return str_replace(array(self::OTP_PLACEHOLDER, self::DURATION_PLACEHOLDER), array($this->code, $this->duration), $body);
	}

	private function getPayload() {
		$settings = new WPRWPSettings();
		$site_settings = $settings->getOption('bv_site_settings');

		return is_array($site_settings) && isset($site_settings['wp_email_otp_template']) ? $site_settings['wp_email_otp_template'] : null;
	}

	private function siteName() {
		$site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);

		return trim(preg_replace('/[\x00-\x1F\x7F]/', ' ', $site_name));
	}

	private function duration($lifetime) {
		$minutes = max(1, intval(round($lifetime / MINUTE_IN_SECONDS)));

		return sprintf('%d %s', $minutes, $minutes === 1 ? 'minute' : 'minutes');
	}
}
endif;
