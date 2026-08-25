<?php
if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWP2FAEmailOTPSender')) :
class WPRWP2FAEmailOTPSender {
	public static function send($user, $code, $lifetime) {
		$site_name = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
		$minutes = max(1, intval(round($lifetime / MINUTE_IN_SECONDS)));
		$subject = sprintf('Your sign-in code for %s', $site_name);
		$message = sprintf("Your sign-in code is %s.\n\nSite: %s (%s)\nThis code expires in %d minutes.\n\nIf you did not request this code, you can ignore this email and review your account security.", $code, $site_name, home_url('/'), $minutes);
		return wp_mail($user->user_email, $subject, $message);
	}
}
endif;
