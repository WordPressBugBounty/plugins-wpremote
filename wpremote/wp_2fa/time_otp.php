<?php
if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWP2FATimeOTP')) :

class WPRWP2FATimeOTP
{
	private static $code_length = 6;

	private static function getCode($secret_key, $time_slice) {
		$time = chr(0).chr(0).chr(0).chr(0).pack('N*', $time_slice);
		$hm = hash_hmac('SHA1', $time, $secret_key, true);
		$offset = ord(substr($hm, -1)) & 0x0F;
		$hashpart = substr($hm, $offset, 4);

		$value = unpack('N', $hashpart);
		$value = $value[1];
		$value = $value & 0x7FFFFFFF;

		$modulo = pow(10, self::$code_length);

		return str_pad($value % $modulo, self::$code_length, '0', STR_PAD_LEFT);
	}

	public static function verifyCode($secret, $code, $discrepancy = 1, $current_time_slice = null)	{
		return self::matchingSlice($secret, $code, $discrepancy, $current_time_slice) !== null;
	}

	# Returns the time slice the code belongs to, so the caller can refuse one it
	# has already accepted. Null when nothing matches.
	public static function matchingSlice($secret, $code, $discrepancy = 1, $current_time_slice = null) {
		if ($current_time_slice === null) {
			$current_time_slice = intdiv(time(), 30);
		}

		if (strlen($code) != self::$code_length) {
			return null;
		}

		# A secret that will not decode must never fall through to hash_hmac(),
		# which would take the false as an empty key and produce a code anyone
		# can compute from the clock alone.
		$secret_key = WPRWP2FAUtils::base32Decode($secret);
		if (!is_string($secret_key) || $secret_key === '') {
			return null;
		}

		for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
			$slice = intval($current_time_slice) + $i;
			if (hash_equals(self::getCode($secret_key, $slice), $code)) {
				return $slice;
			}
		}

		return null;
	}
}
endif;