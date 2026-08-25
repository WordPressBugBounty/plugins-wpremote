<?php
if (!defined('ABSPATH')) exit;

if (!class_exists('WPRWP2FAUtils')) :
	class WPRWP2FAUtils {
		const BASE32_LOOKUP_TABLE = array(
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
			'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
			'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
			'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
			'=',  // padding char
		);

		public static function base32Decode($secret) {
			$base32_chars = self::BASE32_LOOKUP_TABLE;
			$base32_chars_flipped = array_flip($base32_chars);

			$padding_char_count = substr_count($secret, $base32_chars[32]);
			$allowed_values = array(6, 4, 3, 1, 0);
			if (!in_array($padding_char_count, $allowed_values)) {
				return false;
			}
			for ($i = 0; $i < 4; ++$i) {
				if ($padding_char_count == $allowed_values[$i] &&
					substr($secret, -($allowed_values[$i])) != str_repeat($base32_chars[32], $allowed_values[$i])) {
					return false;
				}
			}
			$secret = str_replace('=', '', $secret);

			$secret = str_split($secret);
			$binary_string = '';
			for ($i = 0; $i < count($secret); $i = $i + 8) {
				$x = '';
				if (!in_array($secret[$i], $base32_chars)) {
					return false;
				}
				for ($j = 0; $j < 8; ++$j) {
					$x .= str_pad(base_convert(@$base32_chars_flipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
				}
				$eight_bits = str_split($x, 8);
				for ($z = 0; $z < count($eight_bits); ++$z) {
					$binary_string .= (($y = chr(base_convert($eight_bits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
				}
			}

			return $binary_string;
		}

		public static function getSecretInfo($info) {
			$default_info = array('secret' => null, 'is_encrypted' => null);

			if (empty($info) || !array_key_exists('secret', $info) || empty($info['secret']) ||
					!array_key_exists('is_encrypted', $info) || !is_bool($info['is_encrypted'])) {
				return $default_info;
			}

			$secret = base64_decode($info['secret'], true);
			if ($secret === false) {
				return $default_info;
			}

			return array('secret' => $secret, 'is_encrypted' => $info['is_encrypted']);
		}
	}
endif;