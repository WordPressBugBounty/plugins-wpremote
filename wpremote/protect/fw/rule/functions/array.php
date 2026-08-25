<?php
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped
if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!trait_exists('WPRProtectFWRuleArrayFunc_V669')) :
trait WPRProtectFWRuleArrayFunc_V669 {
	private function _rf_inArray() {
		$args = $this->processRuleFunctionParams(
			'inArray',
			func_num_args(),
			func_get_args(),
			2
		);
		$element = $args[0];
		$array = $args[1];
		$strict = isset($args[2]) ? $args[2] : false;

		if (!is_array($array)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("inArray: 2nd param is not an array")
			);
		}

		if (!is_bool($strict)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("inArray: 3rd param is not a boolean")
			);
		}

		return in_array($element, $array, $strict);
	}

	private function _rf_recInArray() {
		$args = $this->processRuleFunctionParams(
			'recInArray',
			func_num_args(),
			func_get_args(),
			2
		);
		$element = $args[0];
		$array = $args[1];

		if (is_array($array)) {
			foreach ($array as $key => $value) {
				if (is_array($value)) {
					if ($this->_rf_recInArray($element, $value)) {
						return true;
					}
				} else {
					if ($value === $element) {
						return true;
					}
				}
			}
		} else {
			throw new WPRProtectRuleError_V669(
				$this->addExState("recInArray: Expects an array")
			);
		}

		return false;
	}

	private function _rf_arrayKeyExists() {
		$args = $this->processRuleFunctionParams(
			'arrayKeyExists',
			func_num_args(),
			func_get_args(),
			2
		);
		$key = $args[0];
		$array = $args[1];

		if (!is_array($array)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("arrayKeyExists: Array must be of type array")
			);
		} elseif (!is_string($key) && !is_int($key)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("arrayKeyExists: Key must be of type string or int")
			);
		}

		return array_key_exists($key, $array);
	}

	private function _rf_isArrayEmpty() {
		$args = $this->processRuleFunctionParams(
			'isArrayEmpty',
			func_num_args(),
			func_get_args(),
			1,
			['array']
		);
		$array = $args[0];

		return $this->_rf_isEmpty($array);
	}

	private function _rf_getArrayKeys() {
		$args = $this->processRuleFunctionParams(
			'getArrayKeys',
			func_num_args(),
			func_get_args(),
			1,
			['array']
		);
		$array = $args[0];
		$recursive = isset($args[1]) ? $args[1] : false;

		if (!is_bool($recursive)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("getArrayKeys: 2nd param must be a boolean")
			);
		}

		if (!$recursive) {
			$this->enforceArrayTraversalLimit('getArrayKeys', count($array));
			return array_keys($array);
		}

		$keys = array();
		$traversed_keys = 0;
		$this->getArrayKeysRecursive($array, $keys, $traversed_keys);

		return $keys;
	}

	private function _rf_hasAnyArrayKey() {
		$args = $this->processRuleFunctionParams(
			'hasAnyArrayKey',
			func_num_args(),
			func_get_args(),
			2,
			['array', 'array']
		);
		$array = $args[0];
		$keys = $args[1];
		$recursive = isset($args[2]) ? $args[2] : false;

		if (!is_bool($recursive)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("hasAnyArrayKey: 3rd param must be a boolean")
			);
		}

		$key_lookup = array();
		foreach ($keys as $key) {
			if (!is_int($key) && !is_string($key)) {
				throw new WPRProtectRuleError_V669(
					$this->addExState("hasAnyArrayKey: Key must be of type string or int")
				);
			}

			$key_lookup[$key] = true;
		}

		if (empty($key_lookup)) {
			return false;
		}

		$traversed_keys = 0;
		if ($recursive) {
			return $this->hasAnyArrayKeyRecursive($array, $key_lookup, $traversed_keys);
		}

		foreach ($key_lookup as $key => $unused) {
			$traversed_keys += 1;
			$this->enforceArrayTraversalLimit('hasAnyArrayKey', $traversed_keys);
			if (array_key_exists($key, $array)) {
				return true;
			}
		}

		return false;
	}

	private function _rf_keyMatches() {
		$args = $this->processRuleFunctionParams(
			'keyMatches',
			func_num_args(),
			func_get_args(),
			2,
			['string', 'array']
		);
		$pattern = $args[0];
		$array = $args[1];
		$recursive = isset($args[2]) ? $args[2] : false;

		if (!is_bool($recursive)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("keyMatches: 3rd param must be a boolean")
			);
		}

		$this->validateKeyMatchPattern($pattern);

		$traversed_keys = 0;
		if ($recursive) {
			return $this->keyMatchesRecursive($array, $pattern, $traversed_keys);
		}

		foreach ($array as $key => $unused) {
			$traversed_keys += 1;
			$this->enforceArrayTraversalLimit('keyMatches', $traversed_keys);
			if ($this->keyMatchesPattern($pattern, $key)) {
				return true;
			}
		}

		return false;
	}

	private function validateKeyMatchPattern($pattern) {
		set_error_handler(function() {
			return true;
		});

		try {
			$resp = WPRHelper::safePregMatch($pattern, '');
		} finally {
			restore_error_handler();
		}

		if ($resp === false) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("keyMatches: Invalid regular expression")
			);
		}
	}

	private function keyMatchesPattern($pattern, $key) {
		$resp = WPRHelper::safePregMatch($pattern, (string) $key);
		if ($resp === false) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("keyMatches: Regex match failed")
			);
		}

		return $resp > 0;
	}

	private function keyMatchesRecursive($array, $pattern, &$traversed_keys, $depth = 1) {
		if ($depth > WPRProtectFWRuleEngine_V669::MAX_DEPTH_TO_ALLOWED_TYPE_FUNC) {
			return false;
		}

		foreach ($array as $key => $value) {
			$traversed_keys += 1;
			$this->enforceArrayTraversalLimit('keyMatches', $traversed_keys);
			if ($this->keyMatchesPattern($pattern, $key)) {
				return true;
			}

			if (is_array($value) && $this->keyMatchesRecursive($value, $pattern, $traversed_keys, $depth + 1)) {
				return true;
			}
		}

		return false;
	}

	private function getArrayKeysRecursive($array, &$keys, &$traversed_keys, $depth = 1) {
		if ($depth > WPRProtectFWRuleEngine_V669::MAX_DEPTH_TO_ALLOWED_TYPE_FUNC) {
			return;
		}

		foreach ($array as $key => $value) {
			$traversed_keys += 1;
			$this->enforceArrayTraversalLimit('getArrayKeys', $traversed_keys);
			$keys[] = $key;
			if (is_array($value)) {
				$this->getArrayKeysRecursive($value, $keys, $traversed_keys, $depth + 1);
			}
		}
	}

	private function hasAnyArrayKeyRecursive($array, $key_lookup, &$traversed_keys, $depth = 1) {
		if ($depth > WPRProtectFWRuleEngine_V669::MAX_DEPTH_TO_ALLOWED_TYPE_FUNC) {
			return false;
		}

		foreach ($array as $key => $value) {
			$traversed_keys += 1;
			$this->enforceArrayTraversalLimit('hasAnyArrayKey', $traversed_keys);
			if (isset($key_lookup[$key])) {
				return true;
			}

			if (is_array($value) && $this->hasAnyArrayKeyRecursive($value, $key_lookup, $traversed_keys, $depth + 1)) {
				return true;
			}
		}

		return false;
	}

	private function enforceArrayTraversalLimit($func_name, $traversed_keys) {
		if ($traversed_keys > WPRProtectFWRuleEngine_V669::MAX_ARRAY_KEYS_TO_TRAVERSE) {
			throw new WPRProtectRuleError_V669(
				$this->addExState(
					"TraversalLimitError: " . $func_name . " exceeded " .
					WPRProtectFWRuleEngine_V669::MAX_ARRAY_KEYS_TO_TRAVERSE .
					" array keys"
				)
			);
		}
	}

	private function _rf_digArray() {
		$args = $this->processRuleFunctionParams(
			'digArray',
			func_num_args(),
			func_get_args(),
			2,
			['array', 'array']
		);
		$array = $args[0];
		$keys = $args[1];

		foreach ($keys as $key) {
			if (!is_int($key) && !is_string($key)) {
				throw new WPRProtectRuleError_V669(
					$this->addExState("digArray: Keys must be a valid array of string, or integer type")
				);
			}
		}

		return WPRHelper::digArray($array, $keys);
	}

	private function _rf_digArrayValues() {
		$args = $this->processRuleFunctionParams(
			'digArrayValues',
			func_num_args(),
			func_get_args(),
			2,
			['mixed', 'array']
		);
		$array = $args[0];
		$keys = $args[1];

		if (empty($keys)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("digArrayValues: Keys must not be empty")
			);
		}

		if (count($keys) > WPRProtectFWRuleEngine_V669::MAX_DEPTH_TO_ALLOWED_TYPE_FUNC) {
			throw new WPRProtectRuleError_V669(
				$this->addExState(
					"digArrayValues: Keys exceeded " .
					WPRProtectFWRuleEngine_V669::MAX_DEPTH_TO_ALLOWED_TYPE_FUNC .
					" levels of traversal"
				)
			);
		}

		foreach ($keys as $key) {
			if (!is_int($key) && !is_string($key)) {
				throw new WPRProtectRuleError_V669(
					$this->addExState("digArrayValues: Keys must be a valid array of string, or integer type")
				);
			}
		}

		$nodes = array($array);
		$traversed_keys = 0;

		foreach ($keys as $key) {
			$next_nodes = array();

			foreach ($nodes as $node) {
				if (!is_array($node)) {
					continue;
				}

				if ($key === WPRProtectFWRuleEngine_V669::WILDCARD_KEY) {
					foreach ($node as $value) {
						$traversed_keys += 1;
						$this->enforceArrayTraversalLimit('digArrayValues', $traversed_keys);
						$next_nodes[] = $value;
					}

					continue;
				}

				$traversed_keys += 1;
				$this->enforceArrayTraversalLimit('digArrayValues', $traversed_keys);

				if (array_key_exists($key, $node)) {
					$next_nodes[] = $node[$key];
				}
			}

			if (empty($next_nodes)) {
				return array();
			}

			$nodes = $next_nodes;
		}

		return $nodes;
	}

	private function _rf_filterArray() {
		$args = $this->processRuleFunctionParams(
			'filterArray',
			func_num_args(),
			func_get_args(),
			2,
			['array', 'array']
		);
		$array = $args[0];
		$keys = $args[1];

		foreach ($keys as $key) {
			if (!is_int($key) && !is_string($key)) {
				throw new WPRProtectRuleError_V669(
					$this->addExState("filterArray: Keys must be a valid array of string, or integer type")
				);
			}
		}

		return WPRHelper::filterArray($array, $keys);
	}

	private function _rf_getArrayVal() {
		$args = $this->processRuleFunctionParams(
			'getArrayVal',
			func_num_args(),
			func_get_args(),
			2,
			['array']
		);
		$array = $args[0];
		$key = $args[1];

		if (!is_string($key) && !is_int($key)) {
			throw new WPRProtectRuleError_V669(
				$this->addExState("getArrayVal: Key must be a valid string or integer")
			);
		}

		if (array_key_exists($key, $array)) {
			return $array[$key];
		}

		return null;
	}

	private function _rf_arrayIntersection() {
		$args = $this->processRuleFunctionParams(
			'arrayIntersection',
			func_num_args(),
			func_get_args(),
			2,
			['array', 'array']
		);
		$array1 = $args[0];
		$array2 = $args[1];

		return array_intersect($array1, $array2);
	}

	private function _rf_arrayIntersectionAssoc() {
		$args = $this->processRuleFunctionParams(
			'arrayIntersectionAssoc',
			func_num_args(),
			func_get_args(),
			2,
			['array', 'array']
		);
		$array1 = $args[0];
		$array2 = $args[1];

		return array_intersect_assoc($array1, $array2);
	}

	private function _rf_arrayUnion() {
		$args = $this->processRuleFunctionParams(
			'arrayUnion',
			func_num_args(),
			func_get_args(),
			2,
			['array', 'array']
		);
		$array1 = $args[0];
		$array2 = $args[1];

		return ($array1 + $array2);
	}

	private function _rf_arrayMerge() {
		$args = $this->processRuleFunctionParams(
			'arrayMerge',
			func_num_args(),
			func_get_args(),
			2,
			['array', 'array']
		);
		$array1 = $args[0];
		$array2 = $args[1];

		return array_merge($array1, $array2);
	}

	private function _rf_arrayJoin() {
		$args = $this->processRuleFunctionParams(
			'arrayJoin',
			func_num_args(),
			func_get_args(),
			2,
			['string', 'array']
		);
		$separator = $args[0];
		$array = $args[1];

		foreach ($array as $element) {
			if (!is_scalar($element)) {
				throw new WPRProtectRuleError_V669(
					$this->addExState("arrayJoin: Array element must be of scalar type")
				);
			}
		}

		return implode($separator, $array);
	}
}
endif;
