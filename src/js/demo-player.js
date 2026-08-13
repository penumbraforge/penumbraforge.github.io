/* Recorded terminal demos.
   Autoplay is a courtesy, not a default: it only starts when the demo is on
   screen, the connection isn't metered, and the visitor hasn't asked for less
   motion. Everything else gets the poster frame, which is a real first frame
   of the recording rather than a placeholder. */
(function () {
  var demos = document.querySelectorAll('.fx-demo');
  if (!demos.length) return;

  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var conn = navigator.connection;
  var thrifty = !!(conn && (conn.saveData || /^([23]g|slow-2g)$/.test(conn.effectiveType || '')));
  var autoplayAllowed = !reduced && !thrifty;

  demos.forEach(function (demo) {
    var video = demo.querySelector('.fx-demo-video');
    var toggle = demo.querySelector('[data-demo-toggle]');
    var label = demo.querySelector('[data-demo-toggle-label]');
    if (!video) return;

    var loaded = false;
    function load() {
      if (loaded) return;
      loaded = true;
      video.preload = 'metadata';
      video.load();
    }

    function setLabel(playing) {
      if (!label) return;
      label.textContent = playing ? 'Pause' : 'Play';
      toggle.setAttribute('aria-label', (playing ? 'Pause' : 'Play') + ' demo playback');
    }

    if (toggle) {
      toggle.hidden = false;
      toggle.addEventListener('click', function () {
        load();
        if (video.paused) {
          video.play().then(function () { setLabel(true); }).catch(function () {});
        } else {
          video.pause();
          setLabel(false);
        }
      });
      setLabel(false);
    }

    // A demo nobody scrolls to should never cost a byte.
    if (!('IntersectionObserver' in window)) {
      if (autoplayAllowed) { load(); video.play().then(function(){ setLabel(true); }).catch(function(){}); }
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          load();
          if (autoplayAllowed) {
            video.play().then(function () { setLabel(true); }).catch(function () {});
          }
        } else if (!video.paused) {
          video.pause();
          setLabel(false);
        }
      });
    }, { threshold: 0.35 });

    observer.observe(demo);
  });
})();
