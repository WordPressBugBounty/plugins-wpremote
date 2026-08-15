<?php

if (!defined('ABSPATH') && !defined('MCDATAPATH')) exit;

if (!class_exists('WPRProtectRequest_V665')) :
class WPRProtectRequest_V665 {
	public $ip;
	public $host = '';
	public $uri;
	public $method = '';
	public $path = '';
	public $timestamp;
	public $get_params;
	public $post_params;
	public $cookies;
	public $headers = array();
	public $file_names = array();
	public $json_params = array();
	public $raw_body = '';
	public $files;
	public $respcode;
	public $status = WPRProtectRequest_V665::STATUS_ALLOWED;
	public $category = WPRProtectRequest_V665::CATEGORY_NORMAL;

	public $wp_user;

	private $can_get_raw_body = false;
	private $can_decode_json = false;
	private $can_get_uploaded_file_content = false;

	private $max_raw_body_length = 1000000;
	private $max_json_decode_depth = 512;
	private $max_uploaded_file_content_length = 8192;
	private $max_total_uploaded_file_content_length = 65536;

	private $raw_body_status = 'not_loaded';
	private $json_params_status = 'not_loaded';
	private $raw_body_truncated = false;
	private $raw_body_loaded = false;
	private $json_params_loaded = false;
	private $uploaded_file_content_statuses = array();
	private $uploaded_file_content_cache = array();
	private $uploaded_file_content_bytes_read = 0;

	#XNOTE: SHould be part of Protect.
	const STATUS_ALLOWED  = 1;
	const STATUS_BLOCKED  = 2;
	const STATUS_BYPASSED = 3;

	const CATEGORY_BLACKLISTED        = 1;
	const CATEGORY_NORMAL             = 10;
	const CATEGORY_WHITELISTED        = 20;
	const CATEGORY_BOT_BLOCKED        = 30;
	const CATEGORY_COUNTRY_BLOCKED    = 40;
	const CATEGORY_USER_BLACKLISTED   = 50;
	const CATEGORY_RULE_BLOCKED       = 60;
	const CATEGORY_RULE_ALLOWED       = 70;
	const CATEGORY_PRIVATEIP          = 80;
	const CATEGORY_GLOBAL_BOT_BLOCKED = 90;

	public function __construct($ip_header, $config) {
		$this->ip = WPRProtectUtils_V665::getIP($ip_header);
		$this->timestamp = time();
		$this->get_params = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$this->cookies = $_COOKIE;
		$this->post_params = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$this->files = $_FILES; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if (array_key_exists('cangetrawbody', $config) && is_bool($config['cangetrawbody'])) {
			$this->can_get_raw_body = $config['cangetrawbody'];
		}

		if (array_key_exists('maxrawbodylength', $config) && is_int($config['maxrawbodylength'])) {
			$this->max_raw_body_length = $config['maxrawbodylength'];
		}

		if (array_key_exists('candecodejson', $config) && is_bool($config['candecodejson'])) {
			$this->can_decode_json = $config['candecodejson'];
		}

		if (array_key_exists('maxjsondecodedepth', $config) && is_int($config['maxjsondecodedepth'])) {
			$this->max_json_decode_depth = $config['maxjsondecodedepth'];
		}

		if (array_key_exists('cangetuploadedfilecontent', $config) && is_bool($config['cangetuploadedfilecontent'])) {
			$this->can_get_uploaded_file_content = $config['cangetuploadedfilecontent'];
		}

		if (array_key_exists('maxuploadedfilecontentlength', $config) && is_int($config['maxuploadedfilecontentlength'])) {
			$this->max_uploaded_file_content_length = $config['maxuploadedfilecontentlength'];
		}

		if (array_key_exists('maxtotaluploadedfilecontentlength', $config) && is_int($config['maxtotaluploadedfilecontentlength'])) {
			$this->max_total_uploaded_file_content_length = $config['maxtotaluploadedfilecontentlength'];
		}

		if (!empty($_FILES)) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			foreach ($_FILES as $input => $file) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$this->file_names[$input] = $file['name'];
			}
		}
		if (is_array($_SERVER)) {
			foreach ($_SERVER as $key => $value) {
				if (strpos($key, 'HTTP_') === 0) {
					$header = $this->normalizeHeaderName($key);
					$this->headers[$header] = $value;
				}
			}
			$content_type = WPRHelper::getRawParam('SERVER', 'CONTENT_TYPE');
			if (isset($content_type)) {
				$this->headers['Content-Type'] = $content_type;
			}
			$content_length = WPRHelper::getRawParam('SERVER', 'CONTENT_LENGTH');
			if (isset($content_length)) {
				$this->headers['Content-Length'] = $content_length;
			}
			$referer = WPRHelper::getRawParam('SERVER', 'REFERER');
			if (isset($referer)) {
				$this->headers['Referer'] = $referer;
			}
			$http_user_agent = WPRHelper::getRawParam('SERVER', 'HTTP_USER_AGENT');
			if (isset($http_user_agent)) {
				$this->headers['User-Agent'] = $http_user_agent;
			}

			if (array_key_exists('Host', $this->headers)) {
				$this->host = $this->headers['Host'];
			} elseif (array_key_exists('SERVER_NAME', $_SERVER)) {
				$this->host = WPRHelper::getRawParam('SERVER', 'SERVER_NAME');
			}

			$request_method = WPRHelper::getRawParam('SERVER', 'REQUEST_METHOD');
			$this->method = isset($request_method) ? $request_method : 'GET';
			$request_uri = WPRHelper::getRawParam('SERVER', 'REQUEST_URI');
			$this->uri = isset($request_uri) ? $request_uri : '';
			$_uri = parse_url($this->uri);
			$this->path = (is_array($_uri) && array_key_exists('path', $_uri)) ? $_uri['path']  : $this->uri;
		}

	}

	public static function blacklistedCategories() {
		return array(
			WPRProtectRequest_V665::CATEGORY_BOT_BLOCKED,
			WPRProtectRequest_V665::CATEGORY_COUNTRY_BLOCKED,
			WPRProtectRequest_V665::CATEGORY_USER_BLACKLISTED,
			WPRProtectRequest_V665::CATEGORY_GLOBAL_BOT_BLOCKED
		);
	}

	public static function whitelistedCategories() {
		return array(WPRProtectRequest_V665::CATEGORY_WHITELISTED);
	}

	public function setRespCode($code) {
		$this->respcode = $code;
	}

	public function getRespCode() {
		if (!isset($this->respcode) && function_exists('http_response_code')) {
			$this->respcode = http_response_code();
		}

		return $this->respcode;
	}

	public function getStatus() {
		return $this->status;
	}

	public function getCategory() {
		return $this->category;
	}

	private function getKeyVal($array, $key) {
		if (is_array($array)) {
			if (is_array($key)) {
				$_key = array_shift($key);
				if (array_key_exists($_key, $array)) {
					if (count($key) > 0) {
						return $this->getKeyVal($array[$_key], $key);
					} else {
						return $array[$_key];
					}
				}
			} else {
				return array_key_exists($key, $array) ? $array[$key] : null;
			}
		}
		return null;
	}

	private function isJsonContentType($content_type) {
		if (!is_string($content_type)) {
			return false;
		}

		return preg_match('/(^|\s|,)application\/([\w!#\$&-\^\.\+]+\+)?json(\+oembed)?($|\s|;|,)/i', $content_type) === 1;
	}

	private function normalizeHeaderName($name) {
		if (!is_string($name)) {
			return null;
		}

		$name = trim($name);
		if (stripos($name, 'HTTP_') === 0) {
			$name = substr($name, 5);
		}
		$name = str_replace(array('-', '_'), ' ', $name);
		return str_replace(' ', '-', ucwords(strtolower($name)));
	}

	private function isUploadedFileKey($key) {
		return is_string($key) || is_int($key);
	}

	private function normalizeUploadedFileIndexKeys($index) {
		if ($index === null) {
			return array();
		}

		if ($this->isUploadedFileKey($index)) {
			return array($index);
		}

		if (!is_array($index) || empty($index)) {
			return null;
		}

		foreach ($index as $key) {
			if (!$this->isUploadedFileKey($key)) {
				return null;
			}
		}

		return array_values($index);
	}

	private function buildUploadedFileStatusKey($field_name, $index_keys) {
		$status_key = (string) $field_name;
		foreach ($index_keys as $key) {
			$status_key .= '[' . (string) $key . ']';
		}

		return $status_key;
	}

	private function setUploadedFileContentStatus($field_name, $index_keys, $status) {
		$status_key = $this->buildUploadedFileStatusKey($field_name, $index_keys);
		if ($status_key !== '') {
			$this->uploaded_file_content_statuses[$status_key] = $status;
		}
	}

	private function resolveUploadedFileEntry($field_name) {
		if (!$this->isUploadedFileKey($field_name)) {
			return null;
		}

		if (!is_array($this->files) || !array_key_exists($field_name, $this->files) ||
				!is_array($this->files[$field_name])) {
			$this->setUploadedFileContentStatus($field_name, array(), 'missing_file');
			return null;
		}

		return $this->files[$field_name];
	}

	private function getUploadedFileMetaValue($file_entry, $meta_key, $index_keys) {
		if (!is_array($file_entry) || !array_key_exists($meta_key, $file_entry)) {
			return null;
		}

		if (empty($index_keys)) {
			return $file_entry[$meta_key];
		}

		return $this->getKeyVal($file_entry[$meta_key], $index_keys);
	}

	private function isUploadedFilePath($path) {
		return is_string($path) && $path !== '' && is_uploaded_file($path);
	}

	private function normalizeUploadedFileSize($size) {
		if (is_int($size)) {
			return $size;
		}

		if (is_string($size) && preg_match('/^\d+$/', $size) === 1) {
			return (int) $size;
		}

		return null;
	}

	private function resolveUploadedFileReadStatus($read_limit, $requested_limit, $per_file_limit, $limited_by_total,
			$file_size, $content_length) {

		if ($content_length === 0) {
			return 'empty';
		}

		if (isset($file_size) && $file_size <= $content_length) {
			return 'available';
		}

		if ($limited_by_total) {
			return 'truncated_by_total_limit';
		}

		if (isset($file_size) && $file_size > $read_limit) {
			if ($requested_limit > $per_file_limit) {
				return 'truncated_by_config_limit';
			}

			return 'truncated_by_function_limit';
		}

		if (!isset($file_size) && $content_length >= $read_limit) {
			if ($requested_limit > $per_file_limit) {
				return 'truncated_by_config_limit';
			}

			if ($read_limit < $requested_limit) {
				return 'truncated_by_function_limit';
			}
		}

		return 'available';
	}

	private function readUploadedFileContent($file_entry, $field_name, $index_keys, $max_bytes) {
		if (!$this->can_get_uploaded_file_content) {
			$this->setUploadedFileContentStatus($field_name, $index_keys, 'disabled_by_config');
			return null;
		}

		$error = $this->getUploadedFileMetaValue($file_entry, 'error', $index_keys);
		if ((string) $error !== '0') {
			$this->setUploadedFileContentStatus($field_name, $index_keys, 'upload_error');
			return null;
		}

		$tmp_name = $this->getUploadedFileMetaValue($file_entry, 'tmp_name', $index_keys);
		if (!is_string($tmp_name) || $tmp_name === '') {
			$this->setUploadedFileContentStatus($field_name, $index_keys, 'missing_tmp_name');
			return null;
		}

		if (!$this->isUploadedFilePath($tmp_name)) {
			$this->setUploadedFileContentStatus($field_name, $index_keys, 'not_uploaded_file');
			return null;
		}

		$requested_limit = max(0, (int) $max_bytes);
		$per_file_limit = max(0, $this->max_uploaded_file_content_length);
		$total_limit = max(0, $this->max_total_uploaded_file_content_length);
		$configured_target = min($requested_limit, $per_file_limit);
		if ($configured_target <= 0) {
			$this->setUploadedFileContentStatus($field_name, $index_keys, 'empty');
			return '';
		}

		$status_key = $this->buildUploadedFileStatusKey($field_name, $index_keys);
		$cached_length = 0;
		if (array_key_exists($status_key, $this->uploaded_file_content_cache)) {
			$cached_length = strlen($this->uploaded_file_content_cache[$status_key]['content']);
		}

		$remaining_limit = max(0, $total_limit - $this->uploaded_file_content_bytes_read);
		$read_limit = min($configured_target, $cached_length + $remaining_limit);
		$limited_by_total = $read_limit < $configured_target;
		if ($read_limit <= 0) {
			$this->setUploadedFileContentStatus($field_name, $index_keys, 'total_limit_exceeded');
			return null;
		}

		if (array_key_exists($status_key, $this->uploaded_file_content_cache) &&
				$cached_length >= $read_limit) {

			$content = substr($this->uploaded_file_content_cache[$status_key]['content'], 0, $read_limit);
		} else {
			$content = file_get_contents($tmp_name, false, null, 0, $read_limit);
			if ($content === false) {
				$this->setUploadedFileContentStatus($field_name, $index_keys, 'read_failed');
				return null;
			}

			$this->uploaded_file_content_bytes_read += max(0, strlen($content) - $cached_length);
			$this->uploaded_file_content_cache[$status_key] = array(
				'content' => $content,
				'limit' => $read_limit
			);
		}

		$file_size = $this->normalizeUploadedFileSize($this->getUploadedFileMetaValue($file_entry, 'size', $index_keys));
		$this->setUploadedFileContentStatus(
			$field_name,
			$index_keys,
			$this->resolveUploadedFileReadStatus(
				$read_limit,
				$requested_limit,
				$per_file_limit,
				$limited_by_total,
				$file_size,
				strlen($content)
			)
		);

		return $content;
	}

	private function readUploadedFileContents($file_entry, $field_name, $index_keys, $max_bytes) {
		$tmp_name = $this->getUploadedFileMetaValue($file_entry, 'tmp_name', $index_keys);

		if (is_array($tmp_name)) {
			$contents = array();
			foreach ($tmp_name as $key => $value) {
				$contents[$key] = $this->readUploadedFileContents(
					$file_entry,
					$field_name,
					array_merge($index_keys, array($key)),
					$max_bytes
				);
			}
			return $contents;
		}

		if ($tmp_name === null) {
			$this->setUploadedFileContentStatus($field_name, $index_keys, 'missing_file');
			return null;
		}

		return $this->readUploadedFileContent($file_entry, $field_name, $index_keys, $max_bytes);
	}

	private function loadRawBody() {
		if ($this->raw_body_loaded) {
			return;
		}

		$this->raw_body_loaded = true;
		if (!$this->can_get_raw_body) {
			$this->raw_body_status = 'disabled_by_config';
			return;
		}

		$read_limit = max(0, $this->max_raw_body_length);
		$_raw_body = file_get_contents("php://input", false, null, 0, $read_limit + 1);
		if ($_raw_body === false) {
			$this->raw_body_status = 'read_failed';
			return;
		}

		$is_truncated = strlen($_raw_body) > $read_limit;
		$this->raw_body = $_raw_body;
		$this->raw_body_truncated = $is_truncated;
		$this->raw_body_status = $is_truncated ? 'truncated_by_limit' : 'available';
	}

	private function loadJsonParams() {
		if ($this->json_params_loaded) {
			return;
		}

		$this->json_params_loaded = true;
		if (!$this->can_decode_json) {
			$this->json_params_status = 'disabled_by_config';
			return;
		}

		if (!$this->isJsonContentType($this->getContentType())) {
			$this->json_params_status = 'unsupported_content_type';
			return;
		}

		$this->loadRawBody();
		if (!in_array($this->raw_body_status, array('available', 'truncated_by_limit'), true)) {
			$this->json_params_status = 'raw_body_unavailable';
			return;
		}

		if ($this->raw_body_status === 'truncated_by_limit') {
			$this->json_params_status = 'raw_body_truncated';
			return;
		}

		$_json_params = WPRProtectUtils_V665::safeDecodeJSON(
			$this->raw_body,
			true,
			$this->max_json_decode_depth
		);
		if (isset($_json_params)) {
			$this->json_params['JSON'] = $_json_params;
			$this->json_params_status = 'available';
		} elseif (function_exists('json_last_error') && json_last_error() === JSON_ERROR_NONE) {
			$this->json_params_status = 'decoded_null';
		} else {
			$this->json_params_status = 'decode_failed';
		}
	}

	public function getPostParams() {
		if (func_num_args() > 0) {
			$args = func_get_args();
			return $this->getKeyVal($this->post_params, $args);
		}
		return $this->post_params;
	}

	public function getCookies() {
		if (func_num_args() > 0) {
			$args = func_get_args();
			return $this->getKeyVal($this->cookies, $args);
		}
		return $this->cookies;
	}
	
	public function getGetParams() {
		if (func_num_args() > 0) {
			$args = func_get_args();
			return $this->getKeyVal($this->get_params, $args);
		}
		return $this->get_params;
	}

	public function getAllParams() {
		return array("getParams" => $this->get_params, "postParams" => $this->post_params, "jsonParams" => $this->getJsonParams());
	}

	public function getHeader($key) {
		$key = $this->normalizeHeaderName($key);
		return isset($key) && array_key_exists($key, $this->headers) ? $this->headers[$key] : null;
	}

	public function getHeaders() {
		if (func_num_args() > 0) {
			$args = func_get_args();
			$args[0] = $this->normalizeHeaderName($args[0]);
			if (!isset($args[0])) {
				return null;
			}
			return $this->getKeyVal($this->headers, $args);
		}
		return $this->headers;
	}

	public function getFiles() {
		if (func_num_args() > 0) {
			$args = func_get_args();
			return $this->getKeyVal($this->files, $args);
		}
		return $this->files;
	}

	public function getFileNames() {
		if (func_num_args() > 0) {
			$args = func_get_args();
			return $this->getKeyVal($this->file_names, $args);
		}
		return $this->file_names;
	}

	public function getUploadedFileContent($field_name, $max_bytes, $index = null) {
		$index_keys = $this->normalizeUploadedFileIndexKeys($index);
		if (!is_array($index_keys)) {
			return null;
		}

		$file_entry = $this->resolveUploadedFileEntry($field_name);
		if (!is_array($file_entry)) {
			return null;
		}

		return $this->readUploadedFileContents($file_entry, $field_name, $index_keys, $max_bytes);
	}

	public function getUploadedFileMeta($field_name, $meta_key, $index = null) {
		if (!is_string($meta_key) || $meta_key === '') {
			return null;
		}

		$index_keys = $this->normalizeUploadedFileIndexKeys($index);
		if (!is_array($index_keys)) {
			return null;
		}

		$file_entry = $this->resolveUploadedFileEntry($field_name);
		if (!is_array($file_entry)) {
			return null;
		}

		$meta_value = $this->getUploadedFileMetaValue($file_entry, $meta_key, $index_keys);
		if ($meta_key === 'size' && !is_array($meta_value)) {
			return $this->normalizeUploadedFileSize($meta_value);
		}

		return $meta_value;
	}

	public function getUploadedFileContentStatus($field_name = null, $index = null) {
		if ($field_name === null) {
			return $this->uploaded_file_content_statuses;
		}

		if (!$this->isUploadedFileKey($field_name)) {
			return null;
		}

		$index_keys = $this->normalizeUploadedFileIndexKeys($index);
		if (!is_array($index_keys)) {
			return null;
		}

		$status_key = $this->buildUploadedFileStatusKey($field_name, $index_keys);
		return array_key_exists($status_key, $this->uploaded_file_content_statuses) ?
			$this->uploaded_file_content_statuses[$status_key] : null;
	}

	public function getHost() {
		return $this->host;
	}

	public function getURI() {
		return $this->uri;
	}

	public function getAction() {
		$post_action = $this->getPostParams('action');
		if (isset($post_action)) {
			return $post_action;
		} else {
			return $this->getGetParams('action');
		}
	}

	public function getPath() {
		return $this->path;
	}

	public function getIP() {
		return $this->ip;
	}

	public function getMethod() {
		return $this->method;
	}

	public function getTimestamp() {
		return $this->timestamp;
	}

	public function getRequestID() {
		if (!defined("WPR_REQUEST_ID")) {
			define("WPR_REQUEST_ID", uniqid(mt_rand())); // phpcs:ignore WordPress.WP.AlternativeFunctions.rand_mt_rand
		}

		return WPR_REQUEST_ID;
	}

	public function getServerValue($key) {
		$val = WPRHelper::getRawParam('SERVER', $key);
		return isset($val) ? $val : false;
	}

	public function getHeadersV2() {
		return $this->headers;
	}

	public function getFilesV2() {
		return $this->files;
	}

	public function getFileNamesV2() {
		return $this->file_names;
	}

	public function getPostParamsV2() {
		return $this->post_params;
	}

	public function getGetParamsV2() {
		return $this->get_params;
	}

	public function getCookiesV2() {
		return $this->cookies;
	}

	public function getJsonParams() {
		$this->loadJsonParams();
		return $this->json_params;
	}

	public function getRawBody() {
		$this->loadRawBody();
		return $this->raw_body;
	}

	public function getBodyParserStatus() {
		return array(
			'raw_body_status' => $this->raw_body_status,
			'raw_body_truncated' => $this->raw_body_truncated,
			'json_params_status' => $this->json_params_status,
			'uploaded_file_content_statuses' => $this->uploaded_file_content_statuses,
			'uploaded_file_content_bytes_read' => $this->uploaded_file_content_bytes_read,
			'max_uploaded_file_content_length' => $this->max_uploaded_file_content_length,
			'max_total_uploaded_file_content_length' => $this->max_total_uploaded_file_content_length
		);
	}

	public function getContentType() {
		return $this->getHeader('Content-Type');
	}

	public function getContentLength() {
		return $this->getHeader('Content-Length');
	}
}
endif;