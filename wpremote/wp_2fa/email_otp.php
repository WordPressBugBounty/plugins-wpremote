<?php
if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWP2FAEmailOTP')) :

class WPRWP2FAEmailOTP {
	const DIGITS = 8;
	const LIFETIME = 600;
	const TRIES = 3;
	const SEND_COOLDOWN = 60;
	const SEND_WINDOW = 900;
	const SENDS_PER_WINDOW = 5;
	const SITE_SECRET_CONSTANT = 'AUTH_SALT';

	public static function hasSiteSecret() {
		return self::siteSecret() !== null;
	}

	public static function secondsUntilNextSend($user_id) {
		$rate = self::loadRate($user_id);
		$now = time();

		if ($now - $rate['window_at'] >= self::SEND_WINDOW) {
			return 0;
		}

		if ($rate['sends'] >= self::SENDS_PER_WINDOW) {
			return $rate['window_at'] + self::SEND_WINDOW - $now;
		}

		return max(0, $rate['last_sent_at'] + self::SEND_COOLDOWN - $now);
	}

	public static function hasLiveCode($user_id) {
		$challenge = self::loadChallenge($user_id);

		return $challenge !== null && intval($challenge['expires_at']) > time();
	}

	public static function issue($user) {
		$secret = self::siteSecret();
		if ($secret === null) {
			return null;
		}

		if (self::secondsUntilNextSend($user->ID) > 0) {
			return null;
		}

		try {
			$number = random_int(0, pow(10, self::DIGITS) - 1);
		} catch (Exception $error) {
			return null;
		}

		$code = str_pad(strval($number), self::DIGITS, '0', STR_PAD_LEFT);

		$challenge = array(
			'code_hash' => self::codeHash($user->ID, $code, $secret),
			'expires_at' => time() + self::LIFETIME,
			'tries_left' => self::TRIES
		);

		if (!self::recordSend($user->ID)) {
			return null;
		}

		if (!self::storeChallenge($user->ID, $challenge)) {
			return null;
		}

		return $code;
	}

	public static function redeem($user, $code) {
		$secret = self::siteSecret();
		if ($secret === null) {
			return false;
		}

		$code = self::parseCode($code);
		if ($code === null) {
			return false;
		}

		$challenge = self::loadChallenge($user->ID);
		if ($challenge === null) {
			return false;
		}

		if (intval($challenge['expires_at']) <= time()) {
			self::claim($user->ID, $challenge);
			return false;
		}

		if (!hash_equals($challenge['code_hash'], self::codeHash($user->ID, $code, $secret))) {
			self::spendTry($user->ID, $challenge);
			return false;
		}

		self::discard($user->ID);
		self::clearSendCount($user->ID);

		return true;
	}

	public static function revoke($user_id) {
		delete_user_meta($user_id, WPRWP2FA::EMAIL_RATE_META_KEY);

		return self::discard($user_id);
	}

	public static function discard($user_id) {
		delete_user_meta($user_id, WPRWP2FA::EMAIL_CHALLENGE_META_KEY);

		return !metadata_exists('user', $user_id, WPRWP2FA::EMAIL_CHALLENGE_META_KEY);
	}

	private static function spendTry($user_id, $challenge) {
		if (intval($challenge['tries_left']) <= 1) {
			self::claim($user_id, $challenge);
			return;
		}

		$spent = $challenge;
		$spent['tries_left'] = intval($challenge['tries_left']) - 1;

		if (update_user_meta($user_id, WPRWP2FA::EMAIL_CHALLENGE_META_KEY, $spent, $challenge) === false) {
			self::claim($user_id, $challenge);
		}
	}

	# Proving inbox control clears the window cap, so logging in repeatedly does
	# not lock someone out. The cooldown is kept so codes still cannot be pulled
	# back to back, and a failed write only means the budget is not returned.
	private static function clearSendCount($user_id) {
		$current = self::loadRate($user_id);
		$next = array(
			'sends' => 0,
			'window_at' => time(),
			'last_sent_at' => $current['last_sent_at']
		);

		update_user_meta($user_id, WPRWP2FA::EMAIL_RATE_META_KEY, $next, $current);
	}

	private static function loadRate($user_id) {
		$blank = array('sends' => 0, 'window_at' => 0, 'last_sent_at' => 0);
		$rate = get_user_meta($user_id, WPRWP2FA::EMAIL_RATE_META_KEY, true);

		if (!self::validRate($rate, $blank)) {
			delete_user_meta($user_id, WPRWP2FA::EMAIL_RATE_META_KEY);
			return $blank;
		}

		return $rate;
	}

	private static function validRate($rate, $blank) {
		if (!is_array($rate)) {
			return false;
		}

		foreach ($blank as $field => $default) {
			if (!isset($rate[$field]) || !is_int($rate[$field]) || $rate[$field] < 0) {
				return false;
			}
		}

		return true;
	}

	private static function recordSend($user_id) {
		$now = time();
		$current = self::loadRate($user_id);

		$window_at = $current['window_at'];
		$sends = $current['sends'];
		if ($now - $window_at >= self::SEND_WINDOW) {
			$window_at = $now;
			$sends = 0;
		}

		$next = array(
			'sends' => $sends + 1,
			'window_at' => $window_at,
			'last_sent_at' => $now
		);

		# $current is left untouched: it is the value the update guards on.
		return update_user_meta($user_id, WPRWP2FA::EMAIL_RATE_META_KEY, $next, $current) !== false;
	}

	private static function claim($user_id, $challenge) {
		return delete_user_meta($user_id, WPRWP2FA::EMAIL_CHALLENGE_META_KEY, $challenge) === true;
	}

	private static function loadChallenge($user_id) {
		$challenge = get_user_meta($user_id, WPRWP2FA::EMAIL_CHALLENGE_META_KEY, true);

		if (!is_array($challenge) || !isset($challenge['code_hash'], $challenge['expires_at'], $challenge['tries_left'])) {
			return null;
		}

		if (!is_string($challenge['code_hash']) || !is_int($challenge['expires_at']) || !is_int($challenge['tries_left'])) {
			return null;
		}

		return $challenge;
	}

	private static function storeChallenge($user_id, $challenge) {
		return update_user_meta($user_id, WPRWP2FA::EMAIL_CHALLENGE_META_KEY, $challenge) !== false;
	}

	private static function codeHash($user_id, $code, $secret) {
		return hash_hmac('sha256', intval($user_id) . "\0" . $code, $secret);
	}

	private static function siteSecret() {
		return WPRHelper::configSalt(self::SITE_SECRET_CONSTANT);
	}

	private static function parseCode($code) {
		if (!is_string($code)) {
			return null;
		}

		$code = trim($code);

		return WPRHelper::safePregMatch('/^\d{' . self::DIGITS . '}$/D', $code) === 1 ? $code : null;
	}
}
endif;
