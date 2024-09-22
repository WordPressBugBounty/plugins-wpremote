<?php
	$heading = "COMPLETE SITE MANAGEMENT";
	$subheading = "Make site management effortless with WP Remote";
	$img_url = plugins_url("/../../img/wpr-features-list.svg", __FILE__);
?>
<section id="list-features">
	<div class="custom-container">
		<div class="heading text-center">
		<h5><?php echo esc_html($heading); ?></h5>
		<h4><?php echo esc_html($subheading); ?></h4>
		</div>
		<div class="row">
			<div class="col-xs-12 d-flex">
				<div class="col-xs-12 col-lg-6 px-3">
					<div>
						<img class="main-image" src="<?php echo esc_url($img_url); ?>"/>
					</div>
				</div>
				<div class="col-xs-12 col-lg-6 d-flex px-3">
					<div id="accordion">
						<div>
							<input type="radio" name="accordion-group" id="option-1" checked />
							<div class="acc-card">
								<label for="option-1">
									<h5>Complete Site Management</h5>
									<h4>Update all your sites in one-click from our fast and flexible dashboard.</h4>
								</label>
								<div class="article">
									<p>Sit back, let WP Remote automatically install updates and never worry about unexpected downtimes.</p>
								</div>
							</div>
						</div>
						<div>
							<input type="radio" name="accordion-group" id="option-2" />		
								<div class="acc-card">
								<label for="option-2">
									<h5>100% Guaranteed Security</h5>
									<h4>Keep your sites 100% safe with comprehensive WordPress security</h4>
								</label>
								<div class="article">
									<p>Are you prepared to handle multiple hacks in the same day? Reusing the same plugins and themes means that one single vulnerability can affect multiple clients.</p>
								</div>		
							</div>
						</div>
						<div>
							<input type="radio" name="accordion-group" id="option-3" />	
							<div class="acc-card">
								<label for="option-3">
									<h5>Integrated Free Staging</h5>
									<h4>Safely test changes and updates with 1-click integrated staging for all your sites.</h4>
								</label>
								<div class="article">
									<p>Test changes and fix bugs by cloning your live website with a free staging environment, powered by BlogVault. Catch errors earlier and make better websites for your clients.</p>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</section>