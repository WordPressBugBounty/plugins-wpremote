(function () {
	'use strict';

	document.addEventListener('click', function (event) {
		if (!event.target || event.target.id !== 'twofa-resend') return;
		event.preventDefault();
		var form = document.getElementById('loginform');
		if (!form) return;
		var codeField = form.querySelector('input[name="twofa_code"]');
		if (codeField) codeField.value = '';
		var input = form.querySelector('input[name="twofa_resend"]');
		if (!input) {
			input = document.createElement('input');
			input.type = 'hidden';
			input.name = 'twofa_resend';
			form.appendChild(input);
		}
		input.value = '1';

		var previousNoValidate = form.noValidate;
		form.noValidate = true;
		try {
			if (form.requestSubmit) {
				form.requestSubmit();
			} else {
				var submitEvent = document.createEvent('Event');
				submitEvent.initEvent('submit', true, true);
				form.dispatchEvent(submitEvent);
			}
		} finally {
			form.noValidate = previousNoValidate;
		}
	});

	document.addEventListener('DOMContentLoaded', function () {
		var loginForm = document.getElementById('loginform');
		var usernameField = document.getElementById('user_login');
		var passwordField = document.getElementById('user_pass');
		var loginButton = document.getElementById('wp-submit');
		var loginError = document.getElementById('login_error');
		var isTwoFAEnabled = false;
		var requestInFlight = false;
		var resendTimer = null;
		var progressBar = document.getElementsByClassName('wp2fa-progress-bar')[0];

		if (!loginForm || !usernameField || !passwordField || !loginButton) return;
		loginForm.addEventListener('submit', handleSubmit);

		function handleSubmit(event) {
			event.preventDefault();
			if (requestInFlight) return;
			requestInFlight = true;
			showProgressBar();
			disableLoginButton();

			var formData = new FormData(loginForm);
			var isResendRequest = formData.get('twofa_resend') === '1';
			if (isResendRequest) formData.delete('twofa_code');
			clearResendStatus();

			fetch(loginForm.action, {
				method: 'POST',
				body: formData,
				credentials: 'same-origin'
			}).then(function (response) {
				return response.text().then(function (responseText) {
					return {
						text: responseText,
						url: response.url,
						redirected: response.redirected
					};
				});
			}).then(function (responseData) {
				try {
					return JSON.parse(responseData.text);
				} catch (error) {
					return {
						success: false,
						html: responseData.text,
						responseUrl: responseData.url,
						redirected: responseData.redirected
					};
				}
			}).then(function (data) {
				if (data.success && data.data && data.data.twofa_enabled) {
					isTwoFAEnabled = true;
					showTwoFAField(data.data);
					clearLoginError();
					if (isResendRequest) {
						displayResendStatus(data.data.code_sent
							? 'A new sign-in code was sent.'
							: 'Your previous code is still valid.');
					}
					return;
				}

				if (data.html) {
					handleHtmlResponse(data.html, data.responseUrl, data.redirected);
				} else if (data.data && data.data.message) {
					displayError(data.data.message);
				} else {
					displayError('An unknown error occurred');
				}
				if (isTwoFAEnabled) showTwoFAField();
				if (data.data && data.data.resend_after) restartResendCooldown(data.data.resend_after);
			}).catch(function () {
				displayError('An error occurred while processing your request');
				if (isTwoFAEnabled) showTwoFAField();
			}).then(finishRequest, finishRequest);
		}

		function finishRequest() {
			var resendInput = loginForm.querySelector('input[name="twofa_resend"]');
			if (resendInput) resendInput.remove();
			hideProgressBar();
			enableLoginButton();
			requestInFlight = false;
		}

		function handleHtmlResponse(html, responseUrl, redirected) {
			var parser = new DOMParser();
			var doc = parser.parseFromString(html, 'text/html');
			var errorElement = doc.getElementById('login_error');
			if (errorElement) {
				displayError(errorElement.innerText.trim());
			} else if (redirected && responseUrl) {
				window.location.assign(responseUrl);
			} else {
				displayError('An unknown error occurred');
			}
		}

		function showTwoFAField(data) {
			var twofaField = document.getElementById('twofa-code-field');
			if (!twofaField) {
				var template = document.getElementById('twofa-field-template');
				if (!template || !template.content || !template.content.firstElementChild) return;
				twofaField = template.content.firstElementChild.cloneNode(true);
				var passwordContainer = passwordField.closest ? passwordField.closest('.user-pass-wrap') : passwordField.parentNode;
				var insertionPoint = passwordContainer || passwordField.parentNode;
				insertionPoint.parentNode.insertBefore(twofaField, insertionPoint.nextSibling);
			}

			var resendButton = twofaField.querySelector('#twofa-resend');
			var destination = twofaField.querySelector('#twofa-destination');
			var codeField = twofaField.querySelector('#twofa-code');
			if (data && data.twofa_method === 'email_otp') {
				if (codeField) {
					codeField.maxLength = 8;
					codeField.minLength = 8;
				}
				if (resendButton) {
					resendButton.style.display = 'inline-block';
					startResendCooldown(resendButton, Number(data.resend_after) || 0);
				}
				if (destination && data.masked_destination) {
					destination.textContent = 'A sign-in code was sent to ' + data.masked_destination + '.';
				}
			}
			twofaField.style.display = 'block';
			if (codeField) codeField.value = '';
		}

		function restartResendCooldown(seconds) {
			var resendButton = document.getElementById('twofa-resend');
			if (resendButton) startResendCooldown(resendButton, Number(seconds) || 0);
		}

		function startResendCooldown(button, seconds) {
			if (resendTimer) window.clearInterval(resendTimer);
			var remaining = Math.max(0, Math.floor(seconds));
			function render() {
				button.disabled = remaining > 0;
				button.textContent = remaining > 0 ? 'Send a new code (' + remaining + 's)' : 'Send a new code';
			}
			render();
			if (remaining < 1) return;
			resendTimer = window.setInterval(function () {
				remaining -= 1;
				render();
				if (remaining < 1) {
					window.clearInterval(resendTimer);
					resendTimer = null;
				}
			}, 1000);
		}

		function clearLoginError() {
			if (loginError) loginError.style.display = 'none';
		}

		function clearResendStatus() {
			var resendStatus = document.getElementById('twofa-resend-status');
			if (!resendStatus) return;
			resendStatus.textContent = '';
			resendStatus.style.display = 'none';
		}

		function displayResendStatus(message) {
			var resendStatus = document.getElementById('twofa-resend-status');
			if (!resendStatus) return;
			resendStatus.textContent = message;
			resendStatus.style.display = 'block';
		}

		function displayError(message) {
			if (!loginError) {
				loginError = document.createElement('div');
				loginError.id = 'login_error';
				loginForm.parentNode.insertBefore(loginError, loginForm);
			}
			loginError.textContent = message;
			loginError.style.display = 'block';
		}

		function showProgressBar() {
			if (progressBar) progressBar.classList.add('show');
		}

		function hideProgressBar() {
			if (progressBar) progressBar.classList.remove('show');
		}

		function disableLoginButton() {
			loginButton.disabled = true;
			loginButton.value = 'Verifying...';
		}

		function enableLoginButton() {
			loginButton.disabled = false;
			loginButton.value = 'Log In';
		}
	});
}());
