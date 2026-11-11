<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('WPRLinksCallback')) :

// Checks the links in a site's content for the Broken Link Checker. Unrelated to WordPress's own
// Link Manager (the wp_links table). Only the BlogVault, MalCare and WP Remote plugins carry it.
class WPRLinksCallback extends WPRCallbackBase {
	const LINKS_WING_VERSION = 1.0;

	public function __construct($callback_handler) {
	}

	// Scheduling, retries and result classification belong to the server. No site identity
	// reaches the plugin: every target resolves the way a visitor's request would, and the
	// server checks password-protected sites itself.
	//
	// This server makes the requests, on the server's instruction, to addresses taken from the
	// site's content, which anyone who can comment can write to. So redirects are followed here,
	// one hop at a time, and every hop is checked before it is requested: http or https on ports
	// 80 and 443, no credentials, and a host whose every address is public. The request then goes
	// to the address that was checked, so a second DNS answer cannot swap in an internal one. The
	// site's own host is the one exception: some hosts resolve it to this machine.
	public function checkLinks($params) {
		$results = array();
		if (!function_exists('curl_multi_init')) {
			// Report per target so every outcome uses one response shape.
			foreach ($params['targets'] as $target) {
				$results[] = array('id' => $target['id'], 'error_code' => 'parallel_http_unavailable');
			}
			return $this->linkResponse($params, $results);
		}

		$waiting = $params['targets'];
		$deadline = microtime(true) + $params['callback_budget_seconds'];
		$own_hosts = $this->ownLinkHosts();
		$multi = curl_multi_init();
		$active = array();
		$next_key = 0;
		$unfinished_error = 'batch_deadline';

		try {
			while ((!empty($waiting) || !empty($active)) && microtime(true) < $deadline) {
				// Fill the available request slots.
				while (!empty($waiting) && count($active) < $params['concurrency'] && microtime(true) < $deadline) {
					$target = array_shift($waiting);
					// One budget covers the whole redirect chain for this target.
					$target_deadline = min($deadline, microtime(true) + $params['request_timeout_seconds']);
					$running = $this->startLinkRequest($multi, $target, $target['url'], 0, $target_deadline, $own_hosts, $params, $next_key);
					if (isset($running->error)) {
						$results[] = array('id' => $target['id'], 'error_code' => $running->error);
						continue;
					}
					$active[$running->key] = $running;
				}

				if (microtime(true) >= $deadline) {
					break;
				}
				do {
					$code = curl_multi_exec($multi, $running_count);
				} while ($code === CURLM_CALL_MULTI_PERFORM);
				if ($code !== CURLM_OK) {
					$unfinished_error = 'request_failed';
					break;
				}

				while ($info = curl_multi_info_read($multi)) {
					$key = (string) curl_getinfo($info['handle'], CURLINFO_PRIVATE);
					if (!isset($active[$key])) {
						curl_multi_remove_handle($multi, $info['handle']);
						continue;
					}
					$running = $active[$key];
					$http_code = (int) curl_getinfo($running->handle, CURLINFO_HTTP_CODE);
					$final_url = (string) curl_getinfo($running->handle, CURLINFO_EFFECTIVE_URL);
					curl_multi_remove_handle($multi, $running->handle);
					// PHP 8 frees the handle itself and deprecates the call.
					if (is_resource($running->handle)) {
						curl_close($running->handle);
					}
					unset($active[$key]);

					$body_stopped = $info['result'] === CURLE_WRITE_ERROR && $running->stopped_body;
					$request_failed = $info['result'] !== CURLE_OK && !$body_stopped;

					// A redirect: check where it leads before following it, within the same budget.
					if (!$request_failed && $params['redirect_level'] > 0 && $http_code >= 300 && $http_code < 400 && $running->location !== '') {
						$next_url = $this->resolveLinkLocation($final_url, $running->location);
						if ($running->hop >= $params['redirect_level']) {
							// Covers an exhausted hop budget and a redirect loop alike.
							$results[] = array('id' => $running->target['id'], 'http_status' => $http_code,
								'final_url' => $final_url, 'error_code' => 'redirect_limit');
							continue;
						}
						$next = $this->startLinkRequest($multi, $running->target, $next_url, $running->hop + 1, $running->deadline, $own_hosts, $params, $next_key);
						if (isset($next->error)) {
							$results[] = array('id' => $running->target['id'], 'http_status' => $http_code,
								'final_url' => $next_url, 'error_code' => $next->error);
							continue;
						}
						$active[$next->key] = $next;
						continue;
					}

					$result = array(
						'id' => $running->target['id'],
						'http_status' => $http_code,
						'final_url' => $final_url
					);
					if ($request_failed) {
						$result['error_code'] = $this->linkErrorCode($info['result']);
					}
					if ($http_code !== 200) {
						$result['headers'] = $running->headers;
						// A zero server limit captures nothing, so there is no sample to describe.
						if ($params['response_body_limit_bytes'] > 0) {
							$result['sample_base64'] = base64_encode($running->body);
							$result['truncated'] = $running->truncated;
						}
					} elseif (!$request_failed && $running->sample_text) {
						$result['whitespace_only'] = $running->whitespace_only;
					}
					$results[] = $result;
				}

				if (!empty($active) && curl_multi_select($multi, 0.1) === -1) {
					usleep(10000);
				}
			}

			foreach ($waiting as $target) {
				$results[] = array('id' => $target['id'], 'error_code' => $unfinished_error);
			}
			foreach ($active as $running) {
				$results[] = array('id' => $running->target['id'], 'error_code' => $unfinished_error);
			}
		} finally {
			foreach ($active as $running) {
				curl_multi_remove_handle($multi, $running->handle);
				if (is_resource($running->handle)) {
					curl_close($running->handle);
				}
			}
			curl_multi_close($multi);
		}

		return $this->linkResponse($params, $results);
	}

	// A TLS failure here may be this server's own old certificate store rather than the link, so it
	// is reported as such and the server confirms it from elsewhere before calling the link broken.
	private function linkErrorCode($curl_error) {
		if ($curl_error === CURLE_OPERATION_TIMEDOUT) {
			return 'request_timeout';
		}
		if ($curl_error === CURLE_COULDNT_RESOLVE_HOST) {
			return 'dns_failed';
		}
		// SSL connect, peer verification, certificate, cipher, CA store, CRL, issuer, pinned key, status.
		if (in_array($curl_error, array(35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91), true)) {
			return 'tls_failed';
		}
		return 'request_failed';
	}

	// The origin a browser sends as Referer by default, or null when it is not an http(s) address.
	private function linkReferer($target) {
		if (!isset($target['referer']) || !is_string($target['referer']) || strlen($target['referer']) > 2048) {
			return null;
		}
		$parts = parse_url($target['referer']);
		if (!$parts || !isset($parts['scheme'], $parts['host']) || isset($parts['user']) || !in_array(strtolower($parts['scheme']), array('http', 'https'), true)) {
			return null;
		}
		$port = isset($parts['port']) ? ':' . (int) $parts['port'] : '';
		return strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . $port . '/';
	}

	// Evidence is transient; return it through the existing envelope, never logs. The envelope
	// serializes binary safely, so response bytes are never re-encoded as JSON here.
	private function linkResponse($params, $results) {
		return array('request_id' => $params['request_id'], 'results' => $results);
	}

	private function ownLinkHosts() {
		$hosts = array();
		foreach (array(home_url(), site_url()) as $url) {
			$host = parse_url($url, PHP_URL_HOST);
			if (is_string($host) && $host !== '') {
				$hosts[] = strtolower($host);
			}
		}
		return array_unique($hosts);
	}

	// Checks one hop's address, prepares its request and adds it to the batch.
	private function startLinkRequest($multi, $target, $url, $hop, $deadline, $own_hosts, $params, &$next_key) {
		$timeout_ms = (int) (($deadline - microtime(true)) * 1000);
		if ($timeout_ms <= 0) {
			return (object) array('error' => 'request_timeout');
		}
		$address = $this->checkLinkAddress($url, $own_hosts);
		if (isset($address['error'])) {
			return (object) array('error' => $address['error']);
		}
		$running = $this->prepareLinkRequest($target, $url, $timeout_ms, $params, $address);
		if (isset($running->error)) {
			return $running;
		}
		// Carry our own key on the handle so completions need no handle identity.
		$running->key = (string) $next_key++;
		$running->hop = $hop;
		$running->deadline = $deadline;
		curl_setopt($running->handle, CURLOPT_PRIVATE, $running->key);
		if (curl_multi_add_handle($multi, $running->handle) !== CURLM_OK) {
			if (is_resource($running->handle)) {
				curl_close($running->handle);
			}
			return (object) array('error' => 'request_failed');
		}
		return $running;
	}

	// The host, port and checked address of a URL this server may request, or the reason it may not.
	private function checkLinkAddress($url, $own_hosts) {
		$parts = parse_url($url);
		if (!$parts || !isset($parts['scheme'], $parts['host']) || !in_array(strtolower($parts['scheme']), array('http', 'https'), true) ||
			isset($parts['user']) || isset($parts['pass']) || (isset($parts['port']) && !in_array($parts['port'], array(80, 443), true))) {
			return array('error' => 'unsafe_url');
		}
		$host = strtolower(trim($parts['host'], '[]'));
		$port = isset($parts['port']) ? $parts['port'] : (strtolower($parts['scheme']) === 'https' ? 443 : 80);
		if (in_array($host, $own_hosts, true)) {
			return array('host' => $host, 'port' => $port, 'ip' => null);
		}
		if (filter_var($host, FILTER_VALIDATE_IP)) {
			$addresses = array($host);
		} else {
			$addresses = $this->resolveLinkHost($host);
			if (empty($addresses)) {
				return array('error' => 'dns_failed');
			}
		}
		foreach ($addresses as $address) {
			if (!$this->isPublicLinkAddress($address)) {
				return array('error' => 'unsafe_destination');
			}
		}
		if (!defined('CURLOPT_RESOLVE')) {
			return array('error' => 'address_pinning_unavailable');
		}
		return array('host' => $host, 'port' => $port, 'ip' => $addresses[0]);
	}

	private function resolveLinkHost($host) {
		$addresses = function_exists('gethostbynamel') ? @gethostbynamel($host) : false;
		if (!empty($addresses)) {
			return $addresses;
		}
		$addresses = array();
		if (function_exists('dns_get_record')) {
			$records = @dns_get_record($host, DNS_AAAA);
			if (is_array($records)) {
				foreach ($records as $record) {
					if (isset($record['ipv6'])) {
						$addresses[] = $record['ipv6'];
					}
				}
			}
		}
		return $addresses;
	}

	// Public unicast only: no private, loopback, link-local, shared, reserved, documentation,
	// benchmark or multicast range, and no internal IPv4 address carried inside an IPv6 one.
	private function isPublicLinkAddress($address) {
		$binary = @inet_pton($address);
		if ($binary === false) {
			return false;
		}
		if (strlen($binary) === 16) {
			$bytes = array_values(unpack('C16', $binary));
			$embedded = array_slice($bytes, 12, 4);
			$prefix = array_slice($bytes, 0, 12);
			// ::ffff:a.b.c.d (mapped), ::a.b.c.d (compatible) and 64:ff9b::a.b.c.d (NAT64).
			if ($prefix === array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255) || $prefix === array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) ||
				$prefix === array(0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0)) {
				return $this->isPublicLinkAddress(implode('.', $embedded));
			}
			if (($bytes[0] & 0xfe) === 0xfc || $bytes[0] === 0xff || ($bytes[0] === 0xfe && ($bytes[1] & 0xc0) === 0x80) ||
				($bytes[0] === 0xfe && ($bytes[1] & 0xc0) === 0xc0) || ($bytes[0] === 0x20 && $bytes[1] === 0x01 && $bytes[2] === 0x0d && $bytes[3] === 0xb8)) {
				return false;
			}
			return (bool) filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
		}
		if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
			return false;
		}
		$value = ip2long($address);
		$blocked = array(array('0.0.0.0', 8), array('10.0.0.0', 8), array('100.64.0.0', 10), array('127.0.0.0', 8),
			array('169.254.0.0', 16), array('172.16.0.0', 12), array('192.0.0.0', 24), array('192.0.2.0', 24),
			array('192.168.0.0', 16), array('198.18.0.0', 15), array('198.51.100.0', 24), array('203.0.113.0', 24),
			array('224.0.0.0', 4), array('240.0.0.0', 4));
		foreach ($blocked as $range) {
			$mask = -1 << (32 - $range[1]);
			if (($value & $mask) === (ip2long($range[0]) & $mask)) {
				return false;
			}
		}
		return true;
	}

	// The absolute URL a Location header points at, relative to the URL that returned it.
	private function resolveLinkLocation($base, $location) {
		if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $location)) {
			return $location;
		}
		$parts = parse_url($base);
		$origin = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
		if (strpos($location, '//') === 0) {
			return $parts['scheme'] . ':' . $location;
		}
		if (strpos($location, '/') === 0) {
			return $origin . $location;
		}
		$path = isset($parts['path']) ? $parts['path'] : '/';
		if (strpos($location, '?') === 0) {
			return $origin . $path . $location;
		}
		$directory = substr($path, 0, strrpos($path, '/') + 1);
		return $origin . $directory . $location;
	}

	private function prepareLinkRequest($target, $url, $timeout_ms, $params, $address) {
		$running = (object) array(
			'target' => $target, 'body' => '', 'headers' => array(), 'status' => 0, 'sample_text' => true,
			'truncated' => false, 'stopped_body' => false, 'whitespace_only' => true, 'location' => ''
		);
		$http = new WP_Http();
		if ($http->block_request($url)) {
			$running->error = 'external_requests_disabled';
			return $running;
		}
		// The server owns which headers are evidence, so new ones need no plugin release.
		$keep_headers = isset($params['response_headers']) ? $params['response_headers'] : array();
		$following = $params['redirect_level'] > 0;
		$limit = $params['response_body_limit_bytes'];
		$running->handle = curl_init($url);
		$options = array(
			// Redirects are followed by checkLinks, one checked hop at a time.
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_HTTPGET => true,
			CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
			// A site that reaches the internet only through a proxy is checked by the server instead.
			CURLOPT_PROXY => '',
			CURLOPT_NOSIGNAL => true,
			CURLOPT_TIMEOUT_MS => $timeout_ms, CURLOPT_CONNECTTIMEOUT_MS => $timeout_ms,
			CURLOPT_USERAGENT => $params['user_agent'],
			CURLOPT_HEADERFUNCTION => function($handle, $line) use ($running, $keep_headers) {
				if (preg_match('#^HTTP/\S+\s+(\d{3})#i', $line, $status)) {
					$running->status = (int) $status[1];
					$running->headers = array();
					$running->location = '';
				}
				$pair = explode(':', $line, 2);
				if (count($pair) === 2) {
					$name = strtolower(trim($pair[0]));
					if (in_array($name, $keep_headers, true)) {
						$running->headers[$name] = substr(trim($pair[1]), 0, 8192);
					}
					if ($name === 'location') {
						$running->location = trim($pair[1]);
					}
					if ($name === 'content-type') {
						$running->sample_text = stripos($pair[1], 'html') !== false || stripos(trim($pair[1]), 'text/') === 0;
					}
				}
				return strlen($line);
			},
			CURLOPT_WRITEFUNCTION => function($handle, $chunk) use ($running, $following, $limit) {
				// A redirect about to be followed needs no body.
				if ($following && $running->status >= 300 && $running->status < 400) {
					$running->stopped_body = true;
					return 0;
				}
				if (!$running->sample_text) {
					$running->stopped_body = true;
					return 0;
				}
				if ($running->status === 200) {
					if (trim($chunk) === '') {
						return strlen($chunk);
					}
					$running->whitespace_only = false;
					$running->stopped_body = true;
					return 0;
				}
				if ($limit <= 0) {
					$running->stopped_body = true;
					return 0;
				}
				$remaining = $limit - strlen($running->body);
				$running->body .= substr($chunk, 0, $remaining);
				if (strlen($chunk) > $remaining) {
					$running->truncated = true;
					$running->stopped_body = true;
					return 0;
				}
				return strlen($chunk);
			}
		);
		// Sent on every hop, as a browser keeps the page's referer across redirects; never empty.
		$referer = $this->linkReferer($target);
		if ($referer !== null) {
			$options[CURLOPT_REFERER] = $referer;
		}
		if ($address['ip'] !== null) {
			// Connect only to the address that was checked.
			$options[CURLOPT_RESOLVE] = array($address['host'] . ':' . $address['port'] . ':' . $address['ip']);
		}
		curl_setopt_array($running->handle, $options);
		if (defined('CURLOPT_PROTOCOLS_STR')) {
			curl_setopt($running->handle, CURLOPT_PROTOCOLS_STR, 'http,https');
		} else {
			curl_setopt($running->handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
		}
		return $running;
	}
	public function process($request) {
		$params = $request->params;
		switch ($request->method) {
		case "chklnk":
			$resp = $this->checkLinks($params);
			break;
		default:
			$resp = false;
		}
		return $resp;
	}
}
endif;
