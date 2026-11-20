<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('BVFormTestEntries')) :

// Entries a form plugin stored for a form test submission. The test request records each entry with its form, its scope
// (the tested form's: "ours"; created through one of ours: "linked"; any other form: "other_form") and a signature of what
// it stored. The server later asks for entries and files to be deleted, and every item is checked against the run's record
// and the site as it is now before the plugin's own delete API (or the server's SQL, for the plugins without one) runs.
class BVFormTestEntries {
	const MAX_CLEANUP = 20;

	private static $post_types = array(
		'flamingo' => array('flamingo_inbound', 'flamingo_contact'),
		'ninja_forms' => array('nf_sub'),
		'metform' => array('metform-entry'),
		'jetpack_forms' => array('feedback')
	);

	/**
	 * What a signature covers, per plugin: the columns and values the submission wrote, never what changes when the entry
	 * is viewed, starred, marked spam, paid, edited or processed later (read flags, status, update times, notes, IPs).
	 *   rows:   the entry row (cols) and its value rows (child: key columns => value column, filtered by key)
	 *   single: the entry row (cols), with JSON columns decoded
	 *   post:   the entry post (cols) and its meta keys matching meta
	 * form: the column (or meta key) holding the entry's form; link: the column naming a parent entry.
	 */
	private static $readers = array(
		'gravity_forms' => array('shape' => 'rows', 'table' => 'gf_entry', 'id' => 'id', 'form' => 'form_id',
			'cols' => array('id', 'form_id', 'date_created', 'source_url'),
			'child' => array('table' => 'gf_entry_meta', 'fk' => 'entry_id', 'key' => array('meta_key', 'item_index'), 'value' => 'meta_value',
				'keep' => '/\A\d+(\.\d+)?\z/')),
		'formidable' => array('shape' => 'rows', 'table' => 'frm_items', 'id' => 'id', 'form' => 'form_id', 'link' => 'parent_item_id',
			'cols' => array('id', 'item_key', 'form_id', 'parent_item_id', 'created_at'),
			'child' => array('table' => 'frm_item_metas', 'fk' => 'item_id', 'key' => array('field_id'), 'value' => 'meta_value')),
		'forminator' => array('shape' => 'rows', 'table' => 'frmt_form_entry', 'id' => 'entry_id', 'form' => 'form_id',
			'cols' => array('entry_id', 'form_id', 'entry_type', 'date_created'),
			'child' => array('table' => 'frmt_form_entry_meta', 'fk' => 'entry_id', 'key' => array('meta_key'), 'value' => 'meta_value',
				'skip' => '/\A(_|stripe-)/')),
		'elementor_pro' => array('shape' => 'rows', 'table' => 'e_submissions', 'id' => 'id', 'form' => 'element_id',
			'cols' => array('id', 'hash_id', 'element_id', 'post_id', 'form_name', 'created_at_gmt'),
			'child' => array('table' => 'e_submissions_values', 'fk' => 'submission_id', 'key' => array('key'), 'value' => 'value')),
		'kadence_form' => array('shape' => 'rows', 'table' => 'kbp_form_entry', 'id' => 'id', 'form' => 'form_id',
			'cols' => array('id', 'form_id', 'post_id', 'uuid', 'date_created'),
			'child' => array('table' => 'kbp_form_entrymeta', 'fk' => 'kbp_form_entry_id', 'key' => array('meta_key'), 'value' => 'meta_value',
				'skip' => '/\A_/')),
		'jet_form_builder' => array('shape' => 'rows', 'table' => 'jet_fb_records', 'id' => 'id', 'form' => 'form_id',
			'cols' => array('id', 'form_id', 'created_at'),
			'child' => array('table' => 'jet_fb_records_fields', 'fk' => 'record_id', 'key' => array('field_name', 'field_type'), 'value' => 'field_value')),
		'avada_forms' => array('shape' => 'rows', 'table' => 'fusion_form_submissions', 'id' => 'id', 'form' => 'form_id',
			'cols' => array('id', 'form_id', 'time'),
			'child' => array('table' => 'fusion_form_entries', 'fk' => 'submission_id', 'key' => array('field_id'), 'value' => 'value')),
		'fluent_forms' => array('shape' => 'single', 'table' => 'fluentform_submissions', 'id' => 'id', 'form' => 'form_id',
			'cols' => array('id', 'form_id', 'serial_number', 'created_at', 'response'), 'json' => array('response')),
		'wpforms' => array('shape' => 'single', 'table' => 'wpforms_entries', 'id' => 'entry_id', 'form' => 'form_id',
			'cols' => array('entry_id', 'form_id', 'date', 'fields'), 'json' => array('fields')),
		'sureforms' => array('shape' => 'single', 'table' => 'srfm_entries', 'id' => 'ID', 'form' => 'form_id',
			'cols' => array('ID', 'form_id', 'created_at', 'form_data'), 'json' => array('form_data')),
		'mailpoet' => array('shape' => 'single', 'table' => 'mailpoet_subscribers', 'id' => 'id', 'form' => null,
			'cols' => array('id', 'email', 'first_name', 'last_name', 'source', 'created_at')),
		'ninja_forms' => array('shape' => 'post', 'cols' => array('ID', 'post_type', 'post_date_gmt'),
			'meta' => '/\A(_form_id|_seq_num|_field_\d+)\z/', 'form' => '_form_id'),
		'metform' => array('shape' => 'post', 'cols' => array('ID', 'post_type', 'post_date_gmt'),
			'meta' => '/\Ametform_entries__(form_id|form_data|file_upload_new)\z/', 'form' => 'metform_entries__form_id'),
		'jetpack_forms' => array('shape' => 'post', 'cols' => array('ID', 'post_type', 'post_date_gmt', 'post_parent', 'post_content'),
			'meta' => '/\A_feedback_(email|extra_fields)\z/', 'form' => 'post_parent'),
		// Flamingo keeps a message (the form's channel term) and a contact per email address (no form: linked to a message).
		'flamingo' => array('shape' => 'post', 'cols' => array('ID', 'post_type', 'post_date_gmt', 'post_title'),
			'meta' => '/\A(_from_email|_field_.+|_email|_name)\z/', 'form' => 'flamingo_channel')
	);

	/** How each plugin's entry is deleted, for the cleanup's answer. */
	private static $delete_calls = array(
		'gravity_forms' => array('api', 'GFAPI::delete_entry'),
		'formidable' => array('api', 'FrmEntry::destroy'),
		'forminator' => array('api', 'Forminator_Form_Entry_Model::delete_by_entry'),
		'fluent_forms' => array('api', 'FluentForm Submission::remove'),
		'wpforms' => array('api', 'WPForms entry handler delete'),
		'elementor_pro' => array('api', 'Elementor Pro submissions Query::delete_submission'),
		'kadence_form' => array('api', 'KBP\\Queries\\Entry::delete_item'),
		'sureforms' => array('api', 'SRFM Entries::delete'),
		'avada_forms' => array('api', 'Fusion_Form_DB_Submissions::delete'),
		'jet_form_builder' => array('sql', 'server SQL'),
		'mailpoet' => array('sql+api', 'server SQL, then SubscribersRepository::bulkDelete'),
		'ninja_forms' => array('wp_delete_post', 'wp_delete_post'),
		'flamingo' => array('wp_delete_post', 'wp_delete_post'),
		'metform' => array('wp_delete_post', 'wp_delete_post'),
		'jetpack_forms' => array('wp_delete_post', 'wp_delete_post')
	);

	public static function watch($recorder) {
		add_action('add_attachment', function ($attachment_id) use ($recorder) {
			$recorder->addUpload($attachment_id);
		}, PHP_INT_MAX, 1);

		// Files stored without an attachment too (a plugin's own upload folder, a JetEngine or Kadence upload).
		add_filter('wp_handle_upload', function ($upload, $context = 'upload') use ($recorder) {
			if (is_array($upload) && empty($upload['error']) && !empty($upload['file'])) {
				$recorder->addUploadedFile($upload['file']);
			}
			return $upload;
		}, PHP_INT_MAX, 2);

		add_action('wpforms_process_complete', function ($fields, $entry, $form_data, $entry_id) use ($recorder) {
			$recorder->addEntry('wpforms', $entry_id, (is_array($form_data) && isset($form_data['id'])) ? $form_data['id'] : '');
		}, PHP_INT_MAX, 4);

		add_action('gform_after_submission', function ($entry, $form) use ($recorder) {
			if (is_array($entry) && isset($entry['id'])) {
				$recorder->addEntry('gravity_forms', $entry['id'], (is_array($form) && isset($form['id'])) ? $form['id'] : '');
			}
		}, PHP_INT_MAX, 2);

		add_action('ninja_forms_after_submission', function ($data) use ($recorder) {
			if (is_array($data) && isset($data['actions']['save']['sub_id'])) {
				$recorder->addEntry('ninja_forms', $data['actions']['save']['sub_id'], isset($data['form_id']) ? $data['form_id'] : '');
			}
		}, PHP_INT_MAX, 1);

		add_action('frm_after_create_entry', function ($entry_id, $form_id) use ($recorder) {
			$recorder->addEntry('formidable', $entry_id, $form_id);
		}, PHP_INT_MAX, 2);

		add_action('forminator_custom_form_submit_before_set_fields', function ($entry, $form_id) use ($recorder) {
			if (is_object($entry) && isset($entry->entry_id)) {
				$recorder->addEntry('forminator', $entry->entry_id, $form_id);
			}
		}, PHP_INT_MAX, 2);

		// Forminator polls and quizzes store entries in the same table (Forminator_Form_Entry_Model).
		foreach (array('forminator_polls_submit_before_set_fields', 'forminator_quizzes_submit_before_set_fields') as $hook) {
			add_action($hook, function ($entry, $form_id) use ($recorder) {
				if (is_object($entry) && isset($entry->entry_id)) {
					$recorder->addEntry('forminator', $entry->entry_id, $form_id);
				}
			}, PHP_INT_MAX, 2);
		}

		add_action('fluentform/submission_inserted', function ($insert_id, $form_data, $form) use ($recorder) {
			$recorder->addEntry('fluent_forms', $insert_id, (is_object($form) && isset($form->id)) ? $form->id : '');
		}, PHP_INT_MAX, 3);

		// MetForm: its entry is a metform-entry post. metform/entries/after_insert only exists since MetForm 4.3.4, so the
		// post insert itself is recorded (every version); the payment-first flow's auto-draft placeholder is skipped.
		add_action('wp_insert_post', function ($post_id, $post, $update) use ($recorder) {
			if (!$update && is_object($post) && isset($post->post_type, $post->post_status) &&
					in_array($post->post_type, self::$post_types['metform'], true) && $post->post_status !== 'auto-draft') {
				$recorder->addEntry('metform', $post_id, '');
			}
		}, PHP_INT_MAX, 3);

		add_action('jet-form-builder/form-record/save-record-action', function ($record_id) use ($recorder) {
			$form_id = function_exists('jet_fb_handler') ? jet_fb_handler()->get_form_id() : '';
			$recorder->addEntry('jet_form_builder', $record_id, $form_id);
		}, PHP_INT_MAX, 1);

		add_filter('kadence_advanced_form_actions', function ($results, $actions = array(), $form_args = array(), $fields = array(), $post_id = 0) use ($recorder) {
			if (is_array($results) && !empty($results['entry_id'])) {
				$recorder->addEntry('kadence_form', $results['entry_id'], $post_id);
			}
			return $results;
		}, PHP_INT_MAX, 5);

		// MailPoet: only a subscriber this request created (a resubscribing existing subscriber is left alone).
		add_action('mailpoet_subscription_after_subscribe', function ($subscriber, $data = array(), $segment_ids = array(), $form = null) use ($recorder) {
			if (!is_object($subscriber) || !method_exists($subscriber, 'getId') || !method_exists($subscriber, 'getCreatedAt')) {
				return;
			}
			$created = $subscriber->getCreatedAt();
			$since = isset($_SERVER['REQUEST_TIME']) ? (int) $_SERVER['REQUEST_TIME'] : time();
			if ($created instanceof DateTimeInterface && $created->getTimestamp() >= $since - 1) {
				$recorder->addEntry('mailpoet', $subscriber->getId(), (is_object($form) && method_exists($form, 'getId')) ? $form->getId() : '');
			}
		}, PHP_INT_MAX, 4);

		// Avada Forms: each entry row of a stored submission names it (recorded once per submission).
		add_filter('fusion_form_entries_insert_query_args', function ($args) use ($recorder) {
			static $recorded = array();
			if (is_array($args) && !empty($args['submission_id']) && !isset($recorded[$args['submission_id']])) {
				$recorded[$args['submission_id']] = true;
				$recorder->addEntry('avada_forms', $args['submission_id'], isset($args['form_id']) ? $args['form_id'] : '');
			}
			return $args;
		}, PHP_INT_MAX, 1);

		// SureForms: the stored entry's id is in the submission response (no entry when the form does not store them).
		add_filter('srfm_form_submission_response', function ($response, $form_data = array()) use ($recorder) {
			if (is_array($response) && !empty($response['success']) && isset($response['data']['submission_id'])) {
				$recorder->addEntry('sureforms', $response['data']['submission_id'], (is_array($form_data) && isset($form_data['form-id'])) ? $form_data['form-id'] : '');
			}
			return $response;
		}, PHP_INT_MAX, 2);

		// Elementor Pro: read the submission id from the Collect Submissions action right after it ran.
		add_action('elementor_pro/forms/actions/after_run', function ($action, $exception = null) use ($recorder) {
			if ($exception !== null || !is_object($action) || !method_exists($action, 'get_name') || $action->get_name() !== 'save-to-database' ||
					!property_exists($action, 'submission_id')) {
				return;
			}
			$read = Closure::bind(function () {
				return $this->submission_id;
			}, $action, get_class($action));
			if ($read) {
				$recorder->addEntry('elementor_pro', $read(), '');
			}
		}, PHP_INT_MAX, 2);

		add_action('wp_insert_post', function ($post_id, $post, $update) use ($recorder) {
			if ($update || !is_object($post) || !isset($post->post_type)) {
				return;
			}
			if (in_array($post->post_type, self::$post_types['flamingo'], true)) {
				$recorder->addEntry('flamingo', $post_id, $post->post_type);
			}
		}, PHP_INT_MAX, 3);

		add_action('wp_insert_post', function ($post_id, $post, $update) use ($recorder) {
			if (!$update && is_object($post) && isset($post->post_type) && in_array($post->post_type, self::$post_types['jetpack_forms'], true)) {
				$recorder->addEntry('jetpack_forms', $post_id, $post->post_type);
			}
		}, PHP_INT_MAX, 3);
	}

	/**
	 * The recorded entries of this request, each with its form (as stored), scope and signature. An entry that can't be
	 * read back gets scope "unknown" and no signature: it can never be deleted.
	 */
	public static function describe($entries, $run_id, $tested_form_id) {
		$described = array();
		foreach ((array) $entries as $entry) {
			if (!is_array($entry) || !isset($entry['plugin'], $entry['entry_id']) || isset($entry['scope'])) {
				$described[] = $entry;
				continue;
			}
			$info = null;
			try {
				$info = self::read($entry['plugin'], $entry['entry_id']);
			} catch (Throwable $e) {
				$info = null;
			}
			if ($info === null) {
				$entry['scope'] = 'unknown';
				$entry['signature'] = null;
				$described[] = $entry;
				continue;
			}
			if ($info['form_id'] !== null) {
				$entry['form_id'] = $info['form_id'];
			}
			$entry['scope'] = self::matchesTested($entry['plugin'], $entry['form_id'], $tested_form_id) ? 'ours' : 'other_form';
			$entry['signature'] = self::signature($run_id, $entry['plugin'], $entry['entry_id'], $entry['form_id'], $info['fields']);
			$entry['link'] = $info['link'];
			$described[] = $entry;
		}

		// An entry another of ours created: a Formidable child entry (repeater, embedded form) of our entry, or the
		// Flamingo contact of our message's sender.
		foreach ($described as $index => $entry) {
			if (!is_array($entry) || !isset($entry['scope']) || $entry['scope'] !== 'other_form' || empty($entry['link'])) {
				continue;
			}
			foreach ($described as $parent) {
				if (is_array($parent) && isset($parent['scope']) && $parent['scope'] === 'ours' && $parent['plugin'] === $entry['plugin'] &&
						self::isLinked($entry, $parent)) {
					$described[$index]['scope'] = 'linked';
					$described[$index]['parent'] = $parent['entry_id'];
					break;
				}
			}
		}
		foreach ($described as $index => $entry) {
			unset($described[$index]['link']);
		}
		return $described;
	}

	private static function isLinked($entry, $parent) {
		if ($entry['plugin'] === 'formidable') {
			return (string) $entry['link'] === (string) $parent['entry_id'];
		}
		// Flamingo: the contact's email is the message's sender (link: "email:<address>" on both).
		return $entry['plugin'] === 'flamingo' && isset($parent['link']) && $parent['link'] === $entry['link'] && $parent['entry_id'] !== $entry['entry_id'];
	}

	/** Whether an entry's form is the tested one (bv_frm_id: the plugin's own form id, except where noted). */
	private static function matchesTested($plugin, $form_id, $tested_form_id) {
		$tested = trim((string) $tested_form_id);
		if ($tested === '' || $form_id === null || (string) $form_id === '') {
			return false;
		}
		switch ($plugin) {
		case 'jetpack_forms':
			// Our Jetpack form id is post_id * 100 + the form's index in the post; the entry's form is its post.
			return ctype_digit($tested) && intdiv((int) $tested, 100) === absint($form_id);
		case 'flamingo':
			// The message's channel is the Contact Form 7 form's (its _flamingo meta names the channel term).
			$meta = ctype_digit($tested) ? get_post_meta((int) $tested, '_flamingo', true) : null;
			return is_array($meta) && isset($meta['channel']) && (string) absint($meta['channel']) === (string) $form_id;
		case 'avada_forms':
			// A submission names Avada's fusion_forms row, whose form_id is the form's post (our form id).
			global $wpdb;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$post_id = $wpdb->get_var($wpdb->prepare("SELECT form_id FROM {$wpdb->prefix}fusion_forms WHERE id = %d", absint($form_id)));
			return $post_id !== null && (string) absint($post_id) === $tested;
		default:
			return $tested === trim((string) $form_id);
		}
	}

	public static function signature($run_id, $plugin, $entry_id, $form_id, $fields) {
		return 'sha256:' . hash('sha256', BVFormTestRecorder::jsonEncode(array((string) $run_id, (string) $plugin, (string) absint($entry_id),
			(string) $form_id, $fields)));
	}

	/**
	 * An entry as the plugin stored it: {form_id, fields (what the signature covers, normalized), link}; null when it is
	 * not there (or its tables are not).
	 */
	public static function read($plugin, $entry_id) {
		$entry_id = absint($entry_id);
		if ($entry_id === 0 || !isset(self::$readers[$plugin])) {
			return null;
		}
		$reader = self::$readers[$plugin];
		if ($reader['shape'] === 'post') {
			return self::readPost($plugin, $reader, $entry_id);
		}

		global $wpdb;
		if (!is_object($wpdb)) {
			return null;
		}
		$suppress = $wpdb->suppress_errors(true);
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$table = $wpdb->prefix . $reader['table'];
		$cols = '`' . implode('`, `', $reader['cols']) . '`';
		$row = $wpdb->get_row($wpdb->prepare("SELECT {$cols} FROM `{$table}` WHERE `{$reader['id']}` = %d", $entry_id), ARRAY_A);
		$values = null;
		if (is_array($row) && $reader['shape'] === 'rows') {
			$child = $reader['child'];
			$key_cols = '`' . implode('`, `', $child['key']) . '`';
			$rows = $wpdb->get_results($wpdb->prepare("SELECT {$key_cols}, `{$child['value']}` AS v FROM `{$wpdb->prefix}{$child['table']}` WHERE `{$child['fk']}` = %d",
				$entry_id), ARRAY_A);
			$values = array();
			foreach ((array) $rows as $value_row) {
				$name = (string) $value_row[$child['key'][0]];
				if ((isset($child['keep']) && !preg_match($child['keep'], $name)) || (isset($child['skip']) && preg_match($child['skip'], $name))) {
					continue;
				}
				$key_parts = array();
				foreach ($child['key'] as $key_col) {
					$key_parts[] = (string) $value_row[$key_col];
				}
				$values[implode('|', $key_parts)][] = self::canon($value_row['v']);
			}
			ksort($values, SORT_STRING);
		}
		// phpcs:enable
		$wpdb->suppress_errors($suppress);
		if (!is_array($row)) {
			return null;
		}

		$form_id = ($reader['form'] !== null && isset($row[$reader['form']])) ? (string) $row[$reader['form']] : null;
		$link = (isset($reader['link']) && !empty($row[$reader['link']])) ? (string) $row[$reader['link']] : null;
		foreach ($row as $col => $value) {
			$row[$col] = (isset($reader['json']) && in_array($col, $reader['json'], true)) ? self::canon(json_decode((string) $value, true)) : self::canon($value);
		}
		$fields = ($values === null) ? array('row' => $row) : array('row' => $row, 'values' => $values);
		return array('form_id' => $form_id, 'fields' => $fields, 'link' => $link);
	}

	private static function readPost($plugin, $reader, $post_id) {
		$post = get_post($post_id);
		if (!is_object($post) || !in_array($post->post_type, self::$post_types[$plugin], true)) {
			return null;
		}
		$row = array();
		foreach ($reader['cols'] as $col) {
			$row[$col] = self::canon(isset($post->$col) ? $post->$col : null);
		}
		$meta = array();
		foreach ((array) get_post_meta($post_id) as $key => $values) {
			if (preg_match($reader['meta'], (string) $key)) {
				$meta[$key] = array_map(array(__CLASS__, 'canon'), (array) $values);
			}
		}
		ksort($meta, SORT_STRING);

		$form_id = null;
		$link = null;
		if ($reader['form'] === 'post_parent') {
			$form_id = (string) $post->post_parent;
		} elseif ($reader['form'] === 'flamingo_channel') {
			if ($post->post_type === 'flamingo_inbound') {
				$terms = wp_get_object_terms($post_id, 'flamingo_inbound_channel', array('fields' => 'ids'));
				$form_id = (is_array($terms) && !empty($terms)) ? (string) $terms[0] : null;
				$link = isset($meta['_from_email'][0]) ? 'email:' . strtolower((string) $meta['_from_email'][0]) : null;
			} else {
				$link = isset($meta['_email'][0]) ? 'email:' . strtolower((string) $meta['_email'][0]) : null;
			}
		} elseif (isset($meta[$reader['form']][0])) {
			$form_id = (string) $meta[$reader['form']][0];
		}
		return array('form_id' => $form_id, 'fields' => array('row' => $row, 'meta' => $meta), 'link' => $link);
	}

	/**
	 * A stored value in one form whatever the plugin wrapped it in: serialized data (no objects) and JSON decoded, keys
	 * sorted, strings trimmed with \n line ends.
	 */
	public static function canon($value) {
		if (is_string($value)) {
			$trimmed = trim($value);
			if (is_serialized($trimmed)) {
				$decoded = @unserialize($trimmed, array('allowed_classes' => false)); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize, WordPress.PHP.NoSilencedErrors.Discouraged
				if ($decoded !== false || $trimmed === 'b:0;') {
					return self::canon($decoded);
				}
			}
			if ($trimmed !== '' && ($trimmed[0] === '{' || $trimmed[0] === '[')) {
				$decoded = json_decode($trimmed, true);
				if (is_array($decoded)) {
					return self::canon($decoded);
				}
			}
			return str_replace("\r\n", "\n", $trimmed);
		}
		if (is_array($value)) {
			$out = array();
			foreach ($value as $key => $item) {
				$out[(string) $key] = self::canon($item);
			}
			ksort($out, SORT_STRING);
			return $out;
		}
		if (is_object($value)) {
			return self::canon(get_object_vars($value));
		}
		return ($value === null) ? null : (string) $value;
	}

	/**
	 * The server's cleanup request for a run ($params: entries, uploads, file_md5s, dry_run), checked item by item against
	 * the run's record and the site as it is now. Returns {entries: [...], uploads: [...]}, one result per requested item.
	 */
	public static function cleanup($record, $params) {
		$dry_run = !empty($params['dry_run']);
		$file_md5s = array();
		foreach (array_slice((array) (isset($params['file_md5s']) ? $params['file_md5s'] : array()), 0, 200) as $md5) {
			if (is_string($md5) && preg_match('/\A[a-f0-9]{32}\z/', $md5)) {
				$file_md5s[$md5] = true;
			}
		}

		$switched = false;
		if (function_exists('is_multisite') && is_multisite() && isset($record['blog_id']) && absint($record['blog_id']) !== get_current_blog_id()) {
			$switched = switch_to_blog(absint($record['blog_id']));
		}

		$entries = array();
		$done = array();
		foreach (array_slice((array) (isset($params['entries']) ? $params['entries'] : array()), 0, self::MAX_CLEANUP) as $item) {
			$result = self::cleanupEntry($record, $item, $done, $dry_run, $file_md5s);
			if (in_array($result['status'], array('deleted', 'would_delete', 'not_found'), true)) {
				$done[$result['plugin'] . ':' . $result['entry_id']] = true;
			}
			$entries[] = $result;
		}

		$uploads = array();
		foreach (array_slice((array) (isset($params['uploads']) ? $params['uploads'] : array()), 0, BVFormTestRecorder::MAX_ITEMS) as $item) {
			$uploads[] = self::cleanupUpload($record, $item, $dry_run, $file_md5s);
		}

		if ($switched) {
			restore_current_blog();
		}
		return array('dry_run' => $dry_run, 'entries' => $entries, 'uploads' => $uploads);
	}

	private static function cleanupEntry($record, $item, $done, $dry_run, $file_md5s) {
		$plugin = (is_array($item) && isset($item['plugin'])) ? substr((string) $item['plugin'], 0, 40) : '';
		$entry_id = (is_array($item) && isset($item['entry_id'])) ? absint($item['entry_id']) : 0;
		$result = array('plugin' => $plugin, 'entry_id' => $entry_id, 'status' => null, 'deleted' => false);
		if (isset(self::$delete_calls[$plugin])) {
			list($result['method'], $result['call']) = self::$delete_calls[$plugin];
		}

		$recorded = null;
		foreach ((array) (isset($record['entries']) ? $record['entries'] : array()) as $entry) {
			if (is_array($entry) && isset($entry['plugin'], $entry['entry_id']) && $entry['plugin'] === $plugin && absint($entry['entry_id']) === $entry_id) {
				$recorded = $entry;
				break;
			}
		}
		$form_id = isset($item['form_id']) ? (string) $item['form_id'] : '';
		if ($entry_id === 0 || $recorded === null) {
			$result['status'] = 'not_in_record';
			return $result;
		}
		if (empty($recorded['signature']) || !isset($item['signature']) || $item['signature'] !== $recorded['signature'] ||
				(string) $recorded['form_id'] !== $form_id) {
			$result['status'] = 'record_mismatch';
			return $result;
		}
		$scope = isset($recorded['scope']) ? $recorded['scope'] : 'unknown';
		if ($scope === 'linked') {
			if (!isset($recorded['parent']) || empty($done[$plugin . ':' . absint($recorded['parent'])])) {
				$result['status'] = 'parent_not_deleted';
				return $result;
			}
		} elseif ($scope !== 'ours') {
			$result['status'] = $scope === 'other_form' ? 'other_form' : 'unknown_scope';
			return $result;
		}

		$info = self::read($plugin, $entry_id);
		if ($info === null) {
			$result['status'] = 'not_found';
			return $result;
		}
		if (self::signature($record['run_id'], $plugin, $entry_id, $form_id, $info['fields']) !== $recorded['signature']) {
			$result['status'] = 'signature_mismatch';
			return $result;
		}

		// The server's SQL for this verified entry, run as sent and in its order (Blogs::Forms::TestCleanupSql).
		$queries = array();
		if (isset($result['method']) && strpos($result['method'], 'sql') === 0) {
			foreach ((array) (isset($item['queries']) ? $item['queries'] : array()) as $sql) {
				if (is_string($sql) && trim($sql) !== '') {
					$queries[] = trim($sql);
				}
			}
			if (empty($queries)) {
				$result['status'] = 'no_queries';
				return $result;
			}
		}

		if ($dry_run) {
			$result['status'] = 'would_delete';
			if (!empty($queries)) {
				$result['queries'] = array_map(function ($sql) {
					return array('sql' => $sql, 'rows' => null);
				}, $queries);
			}
			return $result;
		}

		try {
			$files = array();
			if ($plugin === 'metform') {
				$files = self::deleteMetFormGeneratedFiles($entry_id);
			}
			$ran = array();
			$reason = self::delete($plugin, $entry_id, $form_id, $queries, $ran);
			if (!empty($ran)) {
				$result['queries'] = $ran;
			}
			if (!empty($files)) {
				$result['files'] = $files;
			}
			$result['status'] = ($reason === null) ? 'deleted' : $reason;
			$result['deleted'] = ($reason === null);
		} catch (Throwable $e) {
			$result['status'] = 'error';
			$result['error'] = substr(get_class($e) . ': ' . $e->getMessage(), 0, 200);
		}
		return $result;
	}

	/**
	 * A file the test uploaded: deleted only when it is in the run's record with the same id and md5, the md5 is one of the
	 * server's test files, and the file is still there with that md5 (inside the uploads folder). An attachment goes with
	 * wp_delete_attachment (post, meta, sizes and file), a plain file with wp_delete_file.
	 */
	private static function cleanupUpload($record, $item, $dry_run, $file_md5s) {
		$path = (is_array($item) && isset($item['path'])) ? substr((string) $item['path'], 0, 400) : '';
		$id = (is_array($item) && isset($item['id'])) ? absint($item['id']) : 0;
		$md5 = (is_array($item) && isset($item['md5'])) ? (string) $item['md5'] : '';
		$result = array('path' => $path, 'id' => $id, 'status' => null, 'deleted' => false);

		$recorded = null;
		foreach ((array) (isset($record['uploads']) ? $record['uploads'] : array()) as $upload) {
			if (is_array($upload) && isset($upload['path']) && $upload['path'] === $path) {
				$recorded = $upload;
				break;
			}
		}
		if ($path === '' || $recorded === null) {
			$result['status'] = 'not_in_record';
			return $result;
		}
		if (absint($recorded['id']) !== $id || (string) $recorded['md5'] !== $md5 || $md5 === '') {
			$result['status'] = 'record_mismatch';
			return $result;
		}
		if (!isset($file_md5s[$md5])) {
			$result['status'] = 'not_a_test_file';
			return $result;
		}

		$real = BVFormTestRecorder::uploadsPath($path);
		$is_attachment = $id > 0 && get_post_type($id) === 'attachment';
		if ($real === false) {
			// The plugin's own delete (or the plugin itself) already removed the file.
			$result['status'] = $is_attachment ? 'file_missing' : 'gone';
			return $result;
		}
		if (md5_file($real) !== $md5) {
			$result['status'] = 'md5_mismatch';
			return $result;
		}
		if ($id > 0 && (!$is_attachment || BVFormTestRecorder::uploadsRelativePath(get_attached_file($id)) !== $path)) {
			$result['status'] = 'attachment_mismatch';
			return $result;
		}
		if ($dry_run) {
			$result['status'] = 'would_delete';
			return $result;
		}

		if ($id > 0) {
			wp_delete_attachment($id, true);
		} else {
			BVFormTestRecorder::deleteFile($real);
		}
		clearstatcache();
		$result['deleted'] = !is_file($real) && ($id === 0 || get_post_type($id) !== 'attachment');
		$result['status'] = $result['deleted'] ? 'deleted' : 'delete_failed';
		return $result;
	}

	/** Runs the server's statements for a verified entry; a table the plugin never created is skipped. Fills $ran with {sql, rows}. */
	private static function runStatements($statements, &$ran) {
		global $wpdb;
		$ok = true;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
		foreach ($statements as $sql) {
			if (preg_match('/\ADELETE (?:\w+ )?FROM (\w+)/', $sql, $match) && $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($match[1]))) !== $match[1]) {
				$ran[] = array('sql' => $sql, 'rows' => null, 'skipped' => 'table_missing');
				continue;
			}
			$rows = $wpdb->query($sql);
			$ran[] = array('sql' => $sql, 'rows' => ($rows === false) ? null : (int) $rows);
			$ok = $ok && ($rows !== false);
		}
		// phpcs:enable
		return $ok;
	}

	/** Deletes one checked entry; null when deleted, else the reason. */
	private static function delete($plugin, $entry_id, $form_id, $statements, &$ran) {
		switch ($plugin) {
		case 'wpforms':
			return self::deleteWPFormsEntry($entry_id, $form_id);

		case 'gravity_forms':
			if (!class_exists('GFAPI') || !method_exists('GFAPI', 'delete_entry')) {
				return 'api_unavailable';
			}
			$deleted = GFAPI::delete_entry($entry_id);
			return (is_wp_error($deleted) || $deleted === false) ? 'delete_failed' : null;

		case 'formidable':
			if (!class_exists('FrmEntry') || !method_exists('FrmEntry', 'destroy')) {
				return 'api_unavailable';
			}
			return FrmEntry::destroy($entry_id) ? null : 'delete_failed';

		case 'forminator':
			if (!class_exists('Forminator_Form_Entry_Model') || !method_exists('Forminator_Form_Entry_Model', 'delete_by_entry')) {
				return 'api_unavailable';
			}
			Forminator_Form_Entry_Model::delete_by_entry($entry_id);
			return null;

		case 'fluent_forms':
			$class = 'FluentForm\App\Models\Submission';
			if (!class_exists($class) || !method_exists($class, 'remove') || $form_id === '') {
				return 'api_unavailable';
			}
			// Pro file/image uploads first (only files no other submission references), as Fluent's own entry delete does.
			$service = 'FluentForm\App\Services\Submission\SubmissionService';
			if (class_exists($service) && method_exists($service, 'deleteFiles')) {
				$submissions = new $service();
				$submissions->deleteFiles(array(absint($entry_id)), absint($form_id));
			}
			call_user_func(array($class, 'remove'), array($entry_id), absint($form_id));
			return null;

		case 'elementor_pro':
			$class = 'ElementorPro\\Modules\\Forms\\Submissions\\Database\\Query';
			if (!class_exists($class) || !method_exists($class, 'get_instance')) {
				return 'api_unavailable';
			}
			$query = call_user_func(array($class, 'get_instance'));
			if (!is_object($query) || !method_exists($query, 'delete_submission')) {
				return 'api_unavailable';
			}
			$deleted = $query->delete_submission($entry_id);
			if ($deleted === false) {
				return 'delete_failed';
			}
			return ($deleted === 0) ? 'not_found' : null;

		case 'ninja_forms':
		case 'flamingo':
		case 'metform':
		case 'jetpack_forms':
			return self::deletePost($plugin, $entry_id);

		case 'jet_form_builder':
			return self::runStatements($statements, $ran) ? null : 'delete_failed';

		case 'sureforms':
			return self::deleteSureFormsEntry($entry_id);

		case 'kadence_form':
			return self::deleteKadenceEntry($entry_id);

		case 'mailpoet':
			return self::deleteMailPoetSubscriber($entry_id, $statements, $ran);

		case 'avada_forms':
			return self::deleteAvadaSubmission($entry_id);

		default:
			return 'unknown_plugin';
		}
	}

	/**
	 * Deletes a WPForms Pro entry with the entry handler, which also deletes its fields and meta rows and the files its
	 * file upload fields stored. The handler checks the delete_entry_single capability unless 'cap' is empty: the
	 * cleanup request has no logged-in user. Camera field files are deleted first with the camera field's own helper
	 * (the handler leaves them), and both helpers are told to delete Media Library copies too.
	 */
	private static function deleteWPFormsEntry($entry_id, $form_id) {
		if (!function_exists('wpforms') || !is_object(wpforms()) || !method_exists(wpforms(), 'obj')) {
			return 'api_unavailable';
		}
		$handler = wpforms()->obj('entry');
		if (!is_object($handler) || !method_exists($handler, 'delete') || !method_exists($handler, 'get')) {
			return 'api_unavailable';
		}
		$force_filters = array('wpforms_pro_forms_fields_file_upload_field_delete_uploaded_file_force', 'wpforms_pro_forms_fields_camera_field_delete_uploaded_file_force');
		foreach ($force_filters as $filter) {
			add_filter($filter, '__return_true', PHP_INT_MAX);
		}
		$camera = 'WPForms\\Pro\\Forms\\Fields\\Camera\\Field';
		if (class_exists($camera) && method_exists($camera, 'delete_uploaded_files_from_entry')) {
			call_user_func(array($camera, 'delete_uploaded_files_from_entry'), $entry_id);
		}
		$handler->delete($entry_id, array('cap' => false));
		foreach ($force_filters as $filter) {
			remove_filter($filter, '__return_true', PHP_INT_MAX);
		}
		return is_object($handler->get($entry_id, array('cap' => false))) ? 'delete_failed' : null;
	}

	/** Deletes an Avada Forms submission with Avada's own API (its entry rows, uploads and the form's submissions count). */
	private static function deleteAvadaSubmission($submission_id) {
		$class = 'Fusion_Form_DB_Submissions';
		if (!class_exists($class)) {
			return 'api_unavailable';
		}
		$submissions = new $class();
		if (!method_exists($submissions, 'delete')) {
			return 'api_unavailable';
		}
		$submissions->delete(absint($submission_id));
		return null;
	}

	/**
	 * Deletes a MailPoet subscriber a form test created: never a WordPress user or WooCommerce customer. The server's
	 * statements (form statistics row, welcome email tasks queued for it alone, task links) run first, then
	 * SubscribersRepository::bulkDelete removes it with its segment links, custom field values and tags.
	 */
	private static function deleteMailPoetSubscriber($subscriber_id, $statements, &$ran) {
		global $wpdb;
		$container = 'MailPoet\\DI\\ContainerWrapper';
		$repository = 'MailPoet\\Subscribers\\SubscribersRepository';
		if (!class_exists($container) || !class_exists($repository)) {
			return 'api_unavailable';
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row($wpdb->prepare("SELECT wp_user_id, is_woocommerce_user FROM {$wpdb->prefix}mailpoet_subscribers WHERE id = %d", $subscriber_id), ARRAY_A);
		if (!is_array($row) || !empty($row['wp_user_id']) || !empty($row['is_woocommerce_user'])) {
			return 'not_found';
		}
		$subscribers = call_user_func(array($container, 'getInstance'))->get($repository);
		if (!is_object($subscribers) || !method_exists($subscribers, 'bulkDelete')) {
			return 'api_unavailable';
		}
		if (!self::runStatements($statements, $ran)) {
			return 'delete_failed';
		}
		return $subscribers->bulkDelete(array($subscriber_id)) > 0 ? null : 'delete_failed';
	}

	/** Deletes a Kadence Blocks Pro form entry (BerlinDB query; deletes its meta too). */
	private static function deleteKadenceEntry($entry_id) {
		$class = 'KBP\\Queries\\Entry';
		if (!class_exists($class)) {
			return 'api_unavailable';
		}
		$query = new $class();
		if (!method_exists($query, 'delete_item')) {
			return 'api_unavailable';
		}
		return $query->delete_item($entry_id) ? null : 'delete_failed';
	}

	/** Deletes a SureForms entry (srfm_entries row); SureForms Pro deletes the entry's uploaded files as it does. */
	private static function deleteSureFormsEntry($entry_id) {
		$class = 'SRFM\\Inc\\Database\\Tables\\Entries';
		if (!class_exists($class) || !method_exists($class, 'delete')) {
			return 'api_unavailable';
		}
		$deleted = call_user_func(array($class, 'delete'), $entry_id);
		if ($deleted === false) {
			return 'delete_failed';
		}
		return ($deleted === 0) ? 'not_found' : null;
	}

	/**
	 * The PNG MetForm Pro's signature field writes for an entry (Action::covert_base64_to_png: uploads/<yyyy/mm>/<input
	 * name><unix time>.png, its URL kept as the field's value): drawn by the test, so not one of the server's test files.
	 * Only for a checked entry, only a file of that name pattern from the last day. Returns the deleted paths.
	 */
	private static function deleteMetFormGeneratedFiles($entry_id) {
		$uploads = wp_upload_dir(null, false);
		$base = BVFormTestRecorder::uploadsBase();
		$base_url = isset($uploads['baseurl']) ? (string) $uploads['baseurl'] : '';
		$data = get_post_meta($entry_id, 'metform_entries__form_data', true);
		$deleted = array();
		foreach ((is_array($data) ? $data : array()) as $input => $value) {
			if ($base === false || !is_string($value) || $base_url === '' || strpos($value, $base_url . '/') !== 0 ||
					!preg_match('#^/(\d{4}/\d{2}/)?' . preg_quote((string) $input, '#') . '\d{9,}\.png$#', substr($value, strlen($base_url)))) {
				continue;
			}
			$relative = ltrim(substr($value, strlen($base_url)), '/');
			$path = BVFormTestRecorder::uploadsPath($relative);
			if ($path !== false && filemtime($path) > time() - DAY_IN_SECONDS) {
				BVFormTestRecorder::deleteFile($path);
				$deleted[] = $relative;
			}
		}
		return $deleted;
	}

	/** Deletes a post that a form plugin uses as its entry storage, checking its type first. */
	private static function deletePost($plugin, $post_id) {
		$post_type = get_post_type($post_id);
		if ($post_type === false || !in_array($post_type, self::$post_types[$plugin], true)) {
			return 'not_found';
		}

		return wp_delete_post($post_id, true) ? null : 'delete_failed';
	}
}

endif;
