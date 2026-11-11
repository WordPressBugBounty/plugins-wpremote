/* BlogVault source-link highlighting. No network requests or persisted state. */
(function () {
  'use strict';

  var locationUrl = new URL(window.location.href);
  var prefix = '#bv-blc=';
  if (locationUrl.searchParams.get('bv-blc') !== '1') return;

  var raw = locationUrl.hash.indexOf(prefix) === 0 ? locationUrl.hash.slice(prefix.length) : null;
  locationUrl.searchParams.delete('bv-blc');
  if (raw !== null) locationUrl.hash = '';
  // Preserve page identity, unrelated anchors and router state without navigating.
  window.history.replaceState(window.history.state, '', locationUrl.pathname + locationUrl.search + locationUrl.hash);
  if (!raw) return;

  var MAX_ELEMENTS = 20000;
  var MAX_MATCHES = 10000;
  var MAX_MILLISECONDS = 100;
  var MAX_RESCANS = 10;
  var MAX_SELECTION = 24576;
  var MAX_TARGETS = 1000;
  // While the page is still settling (images, fonts, embeds pushing content down), the first match is kept in view.
  var SETTLE_MILLISECONDS = 10000;
  var targets = new Set();

  function normalized(value, base) {
    if (typeof value !== 'string' || !value || value.length > 8192 || /[\u0000-\u0020\u007f]/.test(value)) return null;
    try {
      var url = base ? new URL(value, base) : new URL(value);
      if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) return null;
      url.hash = '';
      return url.href;
    } catch (error) {
      return null;
    }
  }

  // One or many destinations, pipe separated. The fragment stays in the browser.
  if (raw.length > MAX_SELECTION) return;
  var requested = raw.split('||');
  if (requested.length > MAX_TARGETS) return;
  for (var i = 0; i < requested.length; i++) {
    var value;
    try { value = normalized(decodeURIComponent(requested[i])); } catch (error) { return; }
    if (!value) return;
    targets.add(value);
  }
  if (!targets.size) return;

  function start() {
    if (!document.body || document.querySelector('[data-bv-blc-layer]')) return;
    var matches = [];
    var boxes = [];
    var frame = null;
    var needsScan = false;
    var needsAnchor = false;
    var settling = true;
    var userMoved = false;
    var rescans = 0;
    var layer = document.createElement('div');
    layer.className = 'bv-blc-layer';
    layer.setAttribute('data-bv-blc-layer', '');
    layer.setAttribute('aria-hidden', 'true');
    // Separate overlays work for images and inline links without wrapping site content.
    document.documentElement.appendChild(layer);

    function scan() {
      matches.forEach(function (node) { node.classList.remove('bv-blc-highlight'); });
      matches = [];
      var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
      var node;
      var examined = 0;
      var started = performance.now();
      while ((node = walker.nextNode())) {
        if (++examined > MAX_ELEMENTS || matches.length >= MAX_MATCHES || performance.now() - started > MAX_MILLISECONDS) break;
        var match = false;
        if (node.tagName === 'A') {
          match = targets.has(normalized(node.getAttribute('href'), document.baseURI));
        } else if (node.tagName === 'IMG') {
          match = targets.has(normalized(node.currentSrc, document.baseURI)) || targets.has(normalized(node.getAttribute('src'), document.baseURI));
        }
        if (match) {
          node.classList.add('bv-blc-highlight');
          matches.push(node);
        }
      }
    }

    function render() {
      var count = 0;
      var started = performance.now();
      for (var i = 0; i < matches.length && count < MAX_MATCHES; i++) {
        if (performance.now() - started > MAX_MILLISECONDS) break;
        var rectangles = matches[i].getClientRects();
        for (var j = 0; j < rectangles.length && count < MAX_MATCHES; j++) {
          var rect = rectangles[j];
          if (!rect.width || !rect.height || rect.bottom <= 0 || rect.top >= window.innerHeight || rect.right <= 0 || rect.left >= window.innerWidth) continue;
          if (!boxes[count]) {
            var box = document.createElement('div');
            box.className = 'bv-blc-rectangle';
            var label = document.createElement('span');
            label.className = 'bv-blc-label';
            label.textContent = 'Broken link';
            box.appendChild(label);
            layer.appendChild(box);
            boxes.push(box);
          }
          var current = boxes[count++];
          var style = current.style;
          style.display = 'block';
          style.left = (rect.left - 4) + 'px';
          style.top = (rect.top - 4) + 'px';
          style.width = (rect.width + 8) + 'px';
          style.height = (rect.height + 8) + 'px';
          current.firstChild.style.setProperty('top', Math.max(-20, 2 - rect.top) + 'px', 'important');
          current.firstChild.style.setProperty('left', Math.max(-2, 2 - rect.left) + 'px', 'important');
        }
      }
      for (var k = count; k < boxes.length; k++) boxes[k].style.display = 'none';
    }

    // Keeps the first match in view while the page settles, until the person moves the page themselves.
    function anchor() {
      if (!settling || userMoved || !matches.length) return;
      matches[0].scrollIntoView({ block: 'center', behavior: 'auto' });
    }

    function schedule(rescan, reanchor) {
      needsScan = needsScan || rescan;
      needsAnchor = needsAnchor || reanchor;
      if (frame !== null) return;
      frame = window.requestAnimationFrame(function () {
        frame = null;
        if (needsScan) { needsScan = false; scan(); }
        if (needsAnchor) { needsAnchor = false; anchor(); }
        render();
      });
    }

    scan();
    anchor();
    render();
    ['wheel', 'touchstart', 'keydown', 'mousedown'].forEach(function (type) {
      window.addEventListener(type, function () { userMoved = true; }, { passive: true, capture: true, once: true });
    });
    window.addEventListener('scroll', function () { schedule(false); }, { passive: true, capture: true });
    window.addEventListener('resize', function () { schedule(false); }, { passive: true });
    window.addEventListener('load', function () { schedule(true, true); }, { once: true });
    // Briefly cover late-rendered links/images without a persistent DOM observer.
    var observer = new MutationObserver(function () {
      if (++rescans > MAX_RESCANS) { observer.disconnect(); return; }
      schedule(true, true);
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['href', 'src', 'srcset'] });
    window.setTimeout(function () { observer.disconnect(); }, 5000);
    // Content that grows or shrinks moves the links without a scroll: the boxes follow, and while the page settles the
    // first match stays in view.
    if (typeof window.ResizeObserver === 'function') {
      var resizes = new window.ResizeObserver(function () { schedule(false, true); });
      resizes.observe(document.body);
    }
    window.setTimeout(function () { settling = false; }, SETTLE_MILLISECONDS);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
