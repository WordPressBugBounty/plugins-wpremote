<?php
if (!defined('ABSPATH')) exit;
if (!class_exists('WPRWP2FAEmailOTPSender')) :
class WPRWP2FAEmailOTPSender {
	public static function send($user, $code, $lifetime) {
		$template = new WPRWP2FAEmailOTPTemplate($code, $lifetime);

		return wp_mail($user->user_email, $template->subject(), $template->body(), $template->headers());
	}
}
endif;
