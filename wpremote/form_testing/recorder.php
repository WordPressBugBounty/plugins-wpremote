<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVFormTestRecorder')) :

// Records what a signed form test submission did (emails, outgoing calls, entries, uploads) without sending anything out.
// The record is a site transient (one per network on multisite, so the server's callback finds it whichever site of the
// network it reaches); the server reads it, then asks for the test's entries and files to be deleted (sending back the
// record it read), which removes it after them, or only removes it when there is nothing to delete (form testing wing:
// "rcrd", "dlt", "rmrcrd").
class BVFormTestRecorder {
	const TRANSIENT_PREFIX = 'bvfrmtst_';
	const TTL = 3600;
	const MAX_ITEMS = 20;
	const RUN_ID_PATTERN = '/\A[A-Za-z0-9_-]{8,64}\z/';
	const LOCK_TIMEOUT = 5;
	/** What the HTTP blocking covers: only calls made through the WordPress HTTP API (pre_http_request). */
	const HTTP_SCOPE = 'wp_http_api';

	private $run_id;
	private $capture_mail;
	private $block_http;
	private $captcha_live;
	private $bypass_captcha;
	private $site_hosts = array();
	private $home_host = '';
	private $tested_form_id;
	private $record = array();

	public function __construct($run_id, $capture_mail, $block_http, $captcha_live = false, $bypass_captcha = true, $tested_form_id = '') {
		global $wpdb;
		$this->run_id = $run_id;
		$this->tested_form_id = is_scalar($tested_form_id) ? (string) $tested_form_id : '';
		$this->bypass_captcha = ($bypass_captcha === true) && ($captcha_live !== true);
		$this->capture_mail = ($capture_mail === true);
		$this->block_http = ($block_http === true);
		$this->captcha_live = ($captcha_live === true);
		$this->record = array(
			'run_id' => $run_id,
			'started_at' => time(),
			// The site the entries were stored in (the cleanup switches to it on multisite) and its table prefix (the
			// server writes the cleanup's SQL with it).
			'blog_id' => function_exists('get_current_blog_id') ? get_current_blog_id() : 1,
			'db_prefix' => (is_object($wpdb) && isset($wpdb->prefix)) ? (string) $wpdb->prefix : '',
			'mail' => array('mode' => 'off', 'count' => 0, 'failed' => 0, 'items' => array()),
			'http' => array('mode' => 'off', 'count' => 0, 'loopbacks' => 0, 'items' => array()),
			'entries' => array(),
			'uploads' => array(),
			'events' => array(),
			'captcha' => array('mode' => $this->captcha_live ? 'live' : 'stubbed', 'verify_calls' => 0, 'verdicts' => array()),
			'requests' => 1,
			'fatal_error' => null
		);
	}

	/**
	 * WordPress 4.0 compatible stand-ins: wp_json_encode (4.1), wp_delete_file (4.2) and wp_parse_url (4.4, a component
	 * only from 4.7). The plugin requires PHP 7, whose parse_url() handles every URL wp_parse_url() exists for.
	 */
	public static function jsonEncode($data) {
		return function_exists('wp_json_encode') ? wp_json_encode($data) : json_encode($data); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
	}

	public static function deleteFile($path) {
		if (function_exists('wp_delete_file')) {
			wp_delete_file($path);
		} else {
			@unlink($path); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink, WordPress.PHP.NoSilencedErrors.Discouraged
		}
	}

	public static function parseUrl($url, $component = -1) {
		return @parse_url((string) $url, $component); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url, WordPress.PHP.NoSilencedErrors.Discouraged
	}

	public static function isValidRunId($run_id) {
		return is_string($run_id) && preg_match(self::RUN_ID_PATTERN, $run_id) === 1;
	}

	public static function transientKey($run_id) {
		return self::TRANSIENT_PREFIX . $run_id;
	}

	/**
	 * Whether outgoing mail can be captured: WordPress 5.7+ (pre_wp_mail) and a core wp_mail().
	 * A plugin that replaces wp_mail() would bypass the filter, so we must not rely on it then.
	 */
	public static function canCaptureMail() {
		global $wp_version;

		if (!isset($wp_version) || version_compare($wp_version, '5.7', '<')) {
			return false;
		}
		if (!function_exists('wp_mail') || !class_exists('ReflectionFunction')) {
			return false;
		}

		try {
			$function = new ReflectionFunction('wp_mail');
			$file = wp_normalize_path((string) $function->getFileName());
		} catch (Exception $e) {
			return false;
		}

		return substr($file, -strlen('wp-includes/pluggable.php')) === 'wp-includes/pluggable.php';
	}

	public function captureMailEnabled() {
		return $this->record['mail']['mode'] === 'captured';
	}

	/** Whether this request's outgoing HTTP (WordPress HTTP API) is blocked and recorded. */
	public function httpBlocked() {
		return $this->block_http;
	}

	public function start() {
		if ($this->block_http) {
			$this->record['http']['mode'] = 'blocked';
			$this->record['http']['scope'] = self::HTTP_SCOPE;
			$this->site_hosts = $this->siteHosts();
			add_filter('pre_http_request', array($this, 'onPreHttpRequest'), PHP_INT_MAX, 3);
		}
		if ($this->captcha_live) {
			add_action('http_api_debug', array($this, 'onHttpApiDebug'), PHP_INT_MAX, 5);
		}

		add_action('shutdown', array($this, 'save'), PHP_INT_MAX);
		add_action('wp_mail_failed', array($this, 'onWpMailFailed'), PHP_INT_MAX, 1);
	}

	/** wp_mail() reported a failure (the site's mail server, or a filter that stopped it). */
	public function onWpMailFailed($error) {
		$this->record['mail']['failed']++;
	}

	/**
	 * Turns on mail capture when it is requested and safe. Call it once wp_mail() is defined
	 * (plugins_loaded): pluggable.php loads after all plugins, so earlier we cannot tell whether
	 * another plugin replaced wp_mail().
	 */
	public function setupMailCapture() {
		if (!$this->capture_mail || $this->record['mail']['mode'] !== 'off') {
			return;
		}

		if (self::canCaptureMail()) {
			$this->record['mail']['mode'] = 'captured';
			add_filter('pre_wp_mail', array($this, 'onPreWpMail'), PHP_INT_MAX, 2);
		} else {
			$this->record['mail']['mode'] = 'unsupported';
		}
	}

	/**
	 * pre_wp_mail: a non-null return short-circuits wp_mail(). We return true (sent) so the form
	 * plugin reports its normal success, and nothing leaves the site.
	 */
	public function onPreWpMail($return, $atts) {
		if ($return !== null) {
			// Another filter already decided: false means the site's mail did not go out.
			if ($return === false) {
				$this->record['mail']['failed']++;
			}
			return $return;
		}

		$this->record['mail']['count']++;
		if (count($this->record['mail']['items']) < self::MAX_ITEMS) {
			$atts = is_array($atts) ? $atts : array();
			$recipients = $this->recipients(isset($atts['to']) ? $atts['to'] : array());
			$this->record['mail']['items'][] = array(
				'recipients' => count($recipients),
				'recipient_domains' => $this->domains($recipients),
				'has_attachments' => !empty($atts['attachments'])
			);
		}

		return true;
	}

	/**
	 * pre_http_request: calls to the site itself go through, except background requests it fires at itself without
	 * waiting (see the class comment); calls to any other host are blocked and recorded. CAPTCHA verification and
	 * Akismet get a passing stub so the test is not rejected by our own blocking.
	 */
	public function onPreHttpRequest($preempt, $args, $url) {
		if ($preempt !== false) {
			return $preempt;
		}

		$parts = BVFormTestRecorder::parseUrl((string) $url);
		$host = (is_array($parts) && isset($parts['host'])) ? strtolower($parts['host']) : '';
		$path = (is_array($parts) && isset($parts['path'])) ? (string) $parts['path'] : '/';
		if ($host === '') {
			return $preempt;
		}
		if (in_array($host, $this->site_hosts, true)) {
			if (is_array($args) && array_key_exists('blocking', $args) && $args['blocking'] === false) {
				return $this->blockLoopback($host, $path, $args);
			}
			return $preempt;
		}

		$kind = $this->stubKind($host, $path);

		if ($kind === 'captcha') {
			$this->record['captcha']['verify_calls']++;
			// Not bypassed (or live captcha): the provider judges the token (live mode records its verdict).
			if (!$this->bypass_captcha) {
				return $preempt;
			}
		}

		$this->addHttpItem($host, $args, $kind, null);
		return $this->stubResponse($kind);
	}

	/**
	 * A non-blocking request to the site itself starts work in another request (WP-Cron, a queue runner) where none
	 * of the test's capture and blocking applies: answer it here instead. Only the target script's name is recorded.
	 */
	private function blockLoopback($host, $path, $args) {
		$this->record['http']['loopbacks']++;
		$script = basename($path);
		$target = in_array($script, array('wp-cron.php', 'admin-ajax.php', 'admin-post.php'), true) ? $script : 'other';
		$this->addHttpItem($host, $args, 'loopback', $target);
		return $this->stubResponse('loopback');
	}

	/** One recorded call: host, method and kind (and a loopback's target script), never the path or query. */
	private function addHttpItem($host, $args, $kind, $target) {
		$this->record['http']['count']++;
		if (count($this->record['http']['items']) >= self::MAX_ITEMS) {
			return;
		}
		$item = array(
			'host' => substr($host, 0, 120),
			'method' => (is_array($args) && isset($args['method'])) ? strtoupper(substr((string) $args['method'], 0, 10)) : 'GET',
			'kind' => $kind
		);
		if ($target !== null) {
			$item['target'] = $target;
		}
		$this->record['http']['items'][] = $item;
	}

	/** Live captcha mode: the provider's verdict on the token (success true/false), nothing else. */
	public function onHttpApiDebug($response, $context, $class, $args, $url) {
		if ($context !== 'response') {
			return;
		}
		$parts = BVFormTestRecorder::parseUrl((string) $url);
		$host = (is_array($parts) && isset($parts['host'])) ? strtolower($parts['host']) : '';
		$path = isset($parts['path']) ? (string) $parts['path'] : '/';
		if ($this->stubKind($host, $path) !== 'captcha' || count($this->record['captcha']['verdicts']) >= self::MAX_ITEMS) {
			return;
		}

		$verdict = array('host' => substr($host, 0, 60), 'success' => null);
		if (is_wp_error($response)) {
			$verdict['error'] = 'request_failed';
		} else {
			$body = json_decode((string) wp_remote_retrieve_body($response), true);
			if (is_array($body) && array_key_exists('success', $body)) {
				$verdict['success'] = ($body['success'] === true);
			}
		}
		$this->record['captcha']['verdicts'][] = $verdict;
	}

	public function addEntry($plugin, $entry_id, $form_id) {
		$entry_id = absint($entry_id);
		if ($entry_id === 0 || count($this->record['entries']) >= self::MAX_ITEMS) {
			return;
		}

		$this->record['entries'][] = array(
			'plugin' => substr((string) $plugin, 0, 40),
			'entry_id' => $entry_id,
			'form_id' => is_scalar($form_id) ? substr((string) $form_id, 0, 40) : ''
		);
	}

	/** A Media Library attachment created in this request (its file, and the attachment, are the test's). */
	public function addUpload($attachment_id) {
		$attachment_id = absint($attachment_id);
		if ($attachment_id > 0) {
			$this->addUploadItem($attachment_id, get_attached_file($attachment_id));
		}
	}

	/** A file stored through wp_handle_upload() in this request, with or without an attachment. */
	public function addUploadedFile($path) {
		$this->addUploadItem(0, $path);
	}

	/**
	 * Uploads are kept by path, relative to the uploads folder (files elsewhere are never the cleanup's), with the
	 * attachment id when there is one. The md5 is taken when the request ends (save), once the plugin is done with it.
	 */
	private function addUploadItem($attachment_id, $path) {
		$relative = self::uploadsRelativePath($path);
		if ($relative === null) {
			return;
		}
		foreach ($this->record['uploads'] as $index => $item) {
			if ($item['path'] === $relative) {
				if ($attachment_id > 0) {
					$this->record['uploads'][$index]['id'] = $attachment_id;
				}
				return;
			}
		}
		if (count($this->record['uploads']) < self::MAX_ITEMS) {
			$this->record['uploads'][] = array('id' => $attachment_id, 'path' => $relative, 'md5' => null);
		}
	}

	/** Fills the md5 of each upload that has none yet and whose file is there and readable. */
	private static function withMd5($uploads) {
		foreach ((array) $uploads as $index => $item) {
			if (!empty($item['md5'])) {
				continue;
			}
			$path = self::uploadsPath($item['path']);
			$md5 = ($path !== false && is_readable($path)) ? md5_file($path) : false;
			$uploads[$index]['md5'] = ($md5 !== false) ? $md5 : null;
		}
		return $uploads;
	}

	/** The uploads folder's real path; false when there is none. */
	public static function uploadsBase() {
		$uploads = function_exists('wp_upload_dir') ? wp_upload_dir(null, false) : array();
		return isset($uploads['basedir']) ? realpath($uploads['basedir']) : false;
	}

	/** A path below the uploads folder as "yyyy/mm/name.ext"; null for any other path. */
	public static function uploadsRelativePath($path) {
		$base = self::uploadsBase();
		$real = (is_string($path) && $path !== '') ? realpath($path) : false;
		if ($base === false || $real === false || strpos($real, $base . DIRECTORY_SEPARATOR) !== 0) {
			return null;
		}
		return str_replace(DIRECTORY_SEPARATOR, '/', substr($real, strlen($base) + 1));
	}

	/** The real path of an uploads-relative path when that file exists inside the uploads folder; false otherwise. */
	public static function uploadsPath($relative) {
		$base = self::uploadsBase();
		if ($base === false || !is_string($relative) || $relative === '' || strpos($relative, "\0") !== false) {
			return false;
		}
		$real = realpath($base . DIRECTORY_SEPARATOR . $relative);
		return ($real !== false && strpos($real, $base . DIRECTORY_SEPARATOR) === 0 && is_file($real)) ? $real : false;
	}

	/** A form plugin reported handling the submission (for plugins without an entry id to record). */
	public function addEvent($source, $name, $form_id) {
		if (count($this->record['events']) >= self::MAX_ITEMS) {
			return;
		}

		$this->record['events'][] = array(
			'source' => substr((string) $source, 0, 40),
			'name' => substr((string) $name, 0, 60),
			'form_id' => is_scalar($form_id) ? substr((string) $form_id, 0, 60) : ''
		);
	}

	public function save() {
		$error = error_get_last();
		$fatal_types = array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR);
		if (is_array($error) && isset($error['type']) && in_array($error['type'], $fatal_types, true)) {
			$this->record['fatal_error'] = array(
				'type' => $error['type'],
				'file' => isset($error['file']) ? basename((string) $error['file']) : '',
				'line' => isset($error['line']) ? intval($error['line']) : 0
			);
		}

		$this->record['finished_at'] = time();
		$this->record['uploads'] = self::withMd5($this->record['uploads']);
		// Each entry's form, scope and signature, read back now that the plugin has written all of it.
		$this->record['entries'] = BVFormTestEntries::describe($this->record['entries'], $this->run_id, $this->tested_form_id);

		$key = self::transientKey($this->run_id);
		// Requests of one run can end at the same time (a browser test signs every POST to the site while it
		// submits): read, merge and write under the run's lock so neither overwrites the other's part.
		$locked = self::lock($this->run_id);
		$existing = get_site_transient($key);
		$record = is_array($existing) ? self::merge($existing, $this->record) : $this->record;
		// An earlier request's upload may not have been readable when it ended (Formidable Pro write-protects a dropzone
		// upload until the entry is saved): its md5 is taken by the run's next request.
		$record['uploads'] = self::withMd5($record['uploads']);
		set_site_transient($key, $record, self::TTL);
		if ($locked) {
			self::unlock($this->run_id);
		}
	}

	/**
	 * A MySQL named lock for one run. GET_LOCK is atomic and is released when the connection ends, so a request that
	 * dies cannot leave it held. Best effort: without it (another database engine, the wait timed out) the caller
	 * goes on unlocked, as before.
	 */
	public static function lock($run_id) {
		global $wpdb;
		if (!is_object($wpdb) || !method_exists($wpdb, 'get_var') || !method_exists($wpdb, 'prepare')) {
			return false;
		}
		$suppress = method_exists($wpdb, 'suppress_errors') ? $wpdb->suppress_errors(true) : null;
		$got = $wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s, %d)', self::lockName($run_id), self::LOCK_TIMEOUT));
		if ($suppress !== null) {
			$wpdb->suppress_errors($suppress);
		}
		return (string) $got === '1';
	}

	public static function unlock($run_id) {
		global $wpdb;
		if (!is_object($wpdb) || !method_exists($wpdb, 'get_var') || !method_exists($wpdb, 'prepare')) {
			return;
		}
		$suppress = method_exists($wpdb, 'suppress_errors') ? $wpdb->suppress_errors(true) : null;
		$wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)', self::lockName($run_id)));
		if ($suppress !== null) {
			$wpdb->suppress_errors($suppress);
		}
	}

	/**
	 * At most 64 characters (MySQL's limit for lock names) and unique per site: sites can share a database server.
	 * The network's base prefix, as the record is one per network.
	 */
	public static function lockName($run_id) {
		global $wpdb;
		$site = (is_object($wpdb) && isset($wpdb->base_prefix)) ? (string) $wpdb->base_prefix : '';
		$site .= defined('DB_NAME') ? '|' . DB_NAME : '';
		return 'bvfrmtst_' . md5($site . '|' . (string) $run_id);
	}

	/** Combines the records of two requests of the same run (earlier first). */
	public static function merge($a, $b) {
		$out = $a;
		$out['started_at'] = min(isset($a['started_at']) ? intval($a['started_at']) : time(), isset($b['started_at']) ? intval($b['started_at']) : time());
		$out['finished_at'] = isset($b['finished_at']) ? $b['finished_at'] : (isset($a['finished_at']) ? $a['finished_at'] : time());
		$out['requests'] = (isset($a['requests']) ? intval($a['requests']) : 1) + (isset($b['requests']) ? intval($b['requests']) : 1);

		foreach (array('mail', 'http') as $part) {
			$pa = isset($a[$part]) && is_array($a[$part]) ? $a[$part] : array('mode' => 'off', 'count' => 0, 'items' => array());
			$pb = isset($b[$part]) && is_array($b[$part]) ? $b[$part] : array('mode' => 'off', 'count' => 0, 'items' => array());
			$out[$part] = array(
				// "captured"/"blocked" wins over "off"/"unsupported" from a request that did not need it.
				'mode' => (isset($pb['mode']) && $pb['mode'] !== 'off') ? $pb['mode'] : (isset($pa['mode']) ? $pa['mode'] : 'off'),
				'count' => intval(isset($pa['count']) ? $pa['count'] : 0) + intval(isset($pb['count']) ? $pb['count'] : 0),
				'failed' => intval(isset($pa['failed']) ? $pa['failed'] : 0) + intval(isset($pb['failed']) ? $pb['failed'] : 0),
				'items' => array_slice(array_merge(isset($pa['items']) ? (array) $pa['items'] : array(), isset($pb['items']) ? (array) $pb['items'] : array()), 0, self::MAX_ITEMS)
			);
			if ($part === 'http') {
				$out[$part]['loopbacks'] = intval(isset($pa['loopbacks']) ? $pa['loopbacks'] : 0) + intval(isset($pb['loopbacks']) ? $pb['loopbacks'] : 0);
				if (isset($pb['scope'])) {
					$out[$part]['scope'] = $pb['scope'];
				} elseif (isset($pa['scope'])) {
					$out[$part]['scope'] = $pa['scope'];
				}
			}
		}

		foreach (array('entries', 'uploads', 'events') as $list) {
			$out[$list] = array_slice(array_merge(isset($a[$list]) ? (array) $a[$list] : array(), isset($b[$list]) ? (array) $b[$list] : array()), 0, self::MAX_ITEMS);
		}

		$ca = isset($a['captcha']) && is_array($a['captcha']) ? $a['captcha'] : array('mode' => 'stubbed', 'verify_calls' => 0, 'verdicts' => array());
		$cb = isset($b['captcha']) && is_array($b['captcha']) ? $b['captcha'] : array('mode' => 'stubbed', 'verify_calls' => 0, 'verdicts' => array());
		$out['captcha'] = array(
			'mode' => ($ca['mode'] === 'live' || $cb['mode'] === 'live') ? 'live' : 'stubbed',
			'verify_calls' => intval($ca['verify_calls']) + intval($cb['verify_calls']),
			'verdicts' => array_slice(array_merge((array) $ca['verdicts'], (array) $cb['verdicts']), 0, self::MAX_ITEMS)
		);

		$out['fatal_error'] = !empty($a['fatal_error']) ? $a['fatal_error'] : (isset($b['fatal_error']) ? $b['fatal_error'] : null);
		return $out;
	}

	/** A run's record, read under the run's lock (a request of the run may still be merging its part); null when none. */
	public static function read($run_id) {
		if (!self::isValidRunId($run_id)) {
			return null;
		}
		$locked = self::lock($run_id);
		$record = get_site_transient(self::transientKey($run_id));
		if ($locked) {
			self::unlock($run_id);
		}
		return is_array($record) ? $record : null;
	}

	/** Removes a run's record (the server is done with it); whether it was there. */
	public static function remove($run_id) {
		return self::isValidRunId($run_id) ? delete_site_transient(self::transientKey($run_id)) : false;
	}

	private function siteHosts() {
		$hosts = array('localhost', '127.0.0.1', '::1');
		foreach (array(home_url(), site_url()) as $url) {
			$parts = BVFormTestRecorder::parseUrl($url);
			if (is_array($parts) && isset($parts['host'])) {
				$hosts[] = strtolower($parts['host']);
				if ($this->home_host === '') {
					$this->home_host = strtolower($parts['host']);
				}
			}
		}

		return array_values(array_unique($hosts));
	}

	private function stubKind($host, $path) {
		$captcha_verify = array(
			array('hosts' => array('www.google.com', 'google.com', 'www.recaptcha.net', 'recaptcha.net'), 'path' => '/recaptcha/api/siteverify'),
			array('hosts' => array('hcaptcha.com', 'api.hcaptcha.com'), 'path' => '/siteverify'),
			array('hosts' => array('challenges.cloudflare.com'), 'path' => '/turnstile/v0/siteverify')
		);
		foreach ($captcha_verify as $rule) {
			if (in_array($host, $rule['hosts'], true) && strpos($path, $rule['path']) === 0) {
				return 'captcha';
			}
		}

		if ($host === 'rest.akismet.com' || substr($host, -strlen('.rest.akismet.com')) === '.rest.akismet.com') {
			return 'akismet';
		}

		return 'integration';
	}

	private function stubResponse($kind) {
		if ($kind === 'captcha') {
			// Score 1.0: some forms require the top score (JetFormBuilder, Divi minimum score settings).
			$body = BVFormTestRecorder::jsonEncode(array('success' => true, 'score' => 1.0, 'hostname' => $this->home_host));
		} elseif ($kind === 'akismet') {
			$body = 'false';
		} elseif ($kind === 'loopback') {
			$body = '';
		} else {
			$body = '{}';
		}

		return array(
			'headers' => array(),
			'body' => $body,
			'response' => array('code' => 200, 'message' => 'OK'),
			'cookies' => array(),
			'filename' => null
		);
	}

	private function recipients($to) {
		if (is_string($to)) {
			$to = explode(',', $to);
		}

		$recipients = array();
		foreach ((array) $to as $address) {
			if (!is_string($address)) {
				continue;
			}
			$address = trim($address);
			if (preg_match('/<([^>]+)>/', $address, $match)) {
				$address = trim($match[1]);
			}
			if ($address !== '') {
				$recipients[] = $address;
			}
		}

		return $recipients;
	}

	private function domains($recipients) {
		$domains = array();
		foreach ($recipients as $address) {
			$at = strrpos($address, '@');
			if ($at !== false) {
				$domains[] = strtolower(substr($address, $at + 1, 120));
			}
		}

		return array_values(array_unique($domains));
	}
}

endif;
