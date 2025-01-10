<div class="email-form">
	<div class="row">
		<div class="col-xs-12 form-container">
			<div class="search-container text-center ">
			<form action="<?php echo esc_url($this->bvinfo->appUrl()); ?>/plugin/signup" style="padding-top:10px; margin: 0px;" onsubmit="document.getElementById('get-started').disabled = true;" method="post" name="signup">
				<input type='hidden' name='bvsrc' value='wpplugin'/>
				<input type='hidden' name='origin' value='wpremote'/>
				<?php
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Already Escaped
					echo $this->siteInfoTags();
				?>
				<input type="text" placeholder="Enter your email address to continue" id="email" name="email" class="d-inline search" required>
				<h5 class="check-box-text"><input type="checkbox" class="check-box" name="consent" value="1" required>
				<label>I agree to WP Remote <a href="https://wpremote.com/tos/" target="_blank" rel="noopener noreferrer">Terms of Service</a> and <a href="https://wpremote.com/privacy/" target="_blank" rel="noopener noreferrer">Privacy Policy</a></label></h5>
				<button id="get-started" type="submit" class="e-mail-button"><span>Get Started</span></button>		
			</form>
		</div>
	</div>
</div>