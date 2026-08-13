/* Recorded terminal demos.
   The video carries a real `autoplay` attribute, so playback is the browser's
   job and works with JS disabled or still loading. This script only adds the
   niceties: a working pause button, pausing while off screen, and honouring
   people who asked for less motion or are on a metered connection. */
(function () {
  var demos = document.querySelectorAll('.fx-demo');
  if (!demos.length) return;

  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var conn = navigator.connection;
  var thrifty = !!(conn && (conn.saveData || /^([23]g|slow-2g)$/.test(conn.effectiveType || '')));
  var holdBack = reduced || thrifty;

  demos.forEach(function (demo) {
    var video = demo.querySelector('.fx-demo-video');
    var toggle = demo.querySelector('[data-demo-toggle]');
    var label = demo.querySelector('[data-demo-toggle-label]');
    if (!video) return;

    // These visitors opted out of motion or bandwidth: strip autoplay before
    // the browser acts on it and leave them the poster plus a play button.
    if (holdBack) {
      video.removeAttribute('autoplay');
      video.pause();
    }

    function setLabel() {
      if (!label) return;
      var playing = !video.paused;
      label.textContent = playing ? 'Pause' : 'Play';
      toggle.setAttribute('aria-label', (playing ? 'Pause' : 'Play') + ' demo playback');
    }

    if (toggle) {
      toggle.hidden = false;
      toggle.addEventListener('click', function () {
        if (video.paused) video.play().catch(function () {});
        else video.pause();
      });
      video.addEventListener('play', setLabel);
      video.addEventListener('pause', setLabel);
      setLabel();
    }

    // Don't burn cycles on a demo that has scrolled away, but never fight a
    // visitor who pressed play — only auto-resume what we auto-paused.
    if (!('IntersectionObserver' in window)) return;
    var autoPaused = false;

    new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        // Pause only when the demo is genuinely, fully off screen. Anything
        // less certain leaves playback alone — a misreporting observer must
        // never be the reason a visitor sees a frozen frame.
        if (entry.intersectionRatio > 0) {
          if (autoPaused && !holdBack) {
            autoPaused = false;
            video.play().catch(function () {});
          }
        } else if (!video.paused) {
          autoPaused = true;
          video.pause();
        }
      });
    }, { threshold: 0 }).observe(demo);
  });
})();
