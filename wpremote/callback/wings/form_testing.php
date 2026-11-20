<?php

if (!defined('ABSPATH')) exit;
if (!class_exists('WPRFormTestingCallback')) :

// The server's side of a form test run (form_testing/): read the run's record ("rcrd"), delete the test's entries and
// files it names ("dlt": each checked against the record the server read and sent, and the site; dry_run only checks)
// and then remove the record, or only remove the record when there is nothing to delete ("rmrcrd"). "dlt" does not
// read the record again: it may have changed on the site since. Only the BlogVault, MalCare and WP Remote plugins
// carry it.
class WPRFormTestingCallback extends WPRCallbackBase {
	const FORM_TESTING_WING_VERSION = 1.0;

	public function __construct($callback_handler) {
	}

	public function process($request) {
		$module_dir = dirname(__FILE__) . '/../../form_testing';
		require_once $module_dir . '/recorder.php';
		require_once $module_dir . '/entries.php';

		$params = $request->params;
		$run_id = (is_array($params) && isset($params['run_id']) && is_string($params['run_id'])) ? $params['run_id'] : '';
		if (!BVFormTestRecorder::isValidRunId($run_id)) {
			return array('error' => 'invalid_run_id');
		}

		switch ($request->method) {
		case "rcrd":
			$resp = array('form_test_record' => BVFormTestRecorder::read($run_id));
			break;
		case "dlt":
			// The record the server read ("rcrd") and sent back; the entries and files first, then the record on the site.
			$record = isset($params['record']) ? $params['record'] : null;
			if (!is_array($record) || !isset($record['run_id']) || $record['run_id'] !== $run_id) {
				$resp = array('error' => 'no_record');
				break;
			}
			$resp = BVFormTestEntries::cleanup($record, $params);
			$resp['record'] = BVFormTestRecorder::remove($run_id) ? 'removed' : 'remove_failed';
			break;
		case "rmrcrd":
			$resp = array('removed' => BVFormTestRecorder::remove($run_id));
			break;
		default:
			$resp = false;
		}
		return $resp;
	}
}
endif;
