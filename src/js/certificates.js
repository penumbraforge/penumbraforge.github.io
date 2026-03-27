/**
 * Penumbra Forge — Certificate System
 *
 * Milestone-based completion certificates with hash verification.
 * Checks ProgressStore for completed labs, generates verification
 * hashes via Web Crypto API, and displays branded certificate modals.
 */

(function () {
  'use strict';

  var Labs = window.PenumbraLabs;
  if (!Labs) return;

  /* ════════════════════════════════════════════════════
     Certificate Types
     ════════════════════════════════════════════════════ */

  var CERT_TYPES = {
    'red-fundamentals': {
      title: 'Red Team Fundamentals',
      description: 'Completed all beginner red team labs \u2014 demonstrated proficiency in XSS, JWT manipulation, and IDOR exploitation.',
      requiredLabs: ['red-xss-shopstack', 'red-jwt-devportal', 'red-idor-medconnect'],
      icon: '\u2694\uFE0F'
    },
    'red-advanced': {
      title: 'Red Team Operator',
      description: 'Completed all red team labs including advanced exploitation techniques.',
      requiredLabs: ['red-xss-shopstack', 'red-sqli-vaultbank', 'red-ssrf-cloudsnap', 'red-jwt-devportal', 'red-race-giftrush', 'red-idor-medconnect'],
      icon: '\uD83D\uDDE1\uFE0F'
    },
    'blue-fundamentals': {
      title: 'SOC Analyst',
      description: 'Completed beginner and intermediate blue team labs \u2014 demonstrated proficiency in alert triage, log analysis, and incident investigation.',
      requiredLabs: ['blue-alert-triage', 'blue-investigate-shopstack', 'blue-phishing-analysis', 'blue-log-analysis'],
      icon: '\uD83D\uDEE1\uFE0F'
    },
    'blue-advanced': {
      title: 'Incident Response Practitioner',
      description: 'Completed all blue team labs including advanced containment and SOAR automation.',
      requiredLabs: ['blue-alert-triage', 'blue-investigate-shopstack', 'blue-phishing-analysis', 'blue-log-analysis', 'blue-containment', 'blue-soar-playbook'],
      icon: '\uD83D\uDD30'
    },
    'full-spectrum': {
      title: 'Full Spectrum Operator',
      description: 'Completed all 12 red and blue team labs \u2014 mastered both offensive and defensive security.',
      requiredLabs: [
        'red-xss-shopstack', 'red-sqli-vaultbank', 'red-ssrf-cloudsnap', 'red-jwt-devportal', 'red-race-giftrush', 'red-idor-medconnect',
        'blue-alert-triage', 'blue-investigate-shopstack', 'blue-phishing-analysis', 'blue-log-analysis', 'blue-containment', 'blue-soar-playbook'
      ],
      icon: '\u26A1'
    }
  };

  /* ════════════════════════════════════════════════════
     Hash Generation (Web Crypto API)
     ════════════════════════════════════════════════════ */

  async function generateHash(certType, labIds, earnedAt) {
    var input = certType + '|' + labIds.slice().sort().join(',') + '|' + earnedAt;
    var encoded = new TextEncoder().encode(input);
    var hash = await crypto.subtle.digest('SHA-256', encoded);
    var arr = Array.from(new Uint8Array(hash));
    return arr.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  /* ════════════════════════════════════════════════════
     Certificate Modal DOM
     ════════════════════════════════════════════════════ */

  var _modalEl = null;

  function ensureModal() {
    if (_modalEl) return _modalEl;

    var modal = document.createElement('div');
    modal.className = 'cert-modal';
    modal.id = 'cert-modal';
    modal.innerHTML =
      '<div class="cert-card">' +
        '<div class="cert-icon" id="cert-icon"></div>' +
        '<div class="cert-brand">Penumbra Forge Security Labs</div>' +
        '<div class="cert-title" id="cert-title"></div>' +
        '<div class="cert-desc" id="cert-desc"></div>' +
        '<div class="cert-meta" id="cert-earned"></div>' +
        '<div class="cert-meta" id="cert-labs"></div>' +
        '<div class="cert-hash" id="cert-hash"></div>' +
        '<div class="cert-actions">' +
          '<button class="cert-btn cert-btn-primary" id="cert-copy-hash">Copy Hash</button>' +
          '<button class="cert-btn cert-btn-secondary" id="cert-close">Close</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(modal);

    // Bind events
    document.getElementById('cert-close').addEventListener('click', function () {
      modal.classList.remove('visible');
    });
    modal.addEventListener('click', function (e) {
      if (e.target === modal) modal.classList.remove('visible');
    });
    document.getElementById('cert-copy-hash').addEventListener('click', function () {
      var hash = document.getElementById('cert-hash').textContent;
      navigator.clipboard.writeText(hash);
      this.textContent = 'Copied!';
      var btn = this;
      setTimeout(function () { btn.textContent = 'Copy Hash'; }, 2000);
    });

    _modalEl = modal;
    return modal;
  }

  /* ════════════════════════════════════════════════════
     Certificates API
     ════════════════════════════════════════════════════ */

  var Certificates = {

    /**
     * check() — returns array of earned certificate objects
     * Checks ProgressStore for completed labs, returns certificates
     * the user has earned (whether previously stored or newly detected).
     */
    check: function () {
      var completedLabs = Labs.Progress.getCompletedLabs();
      var earned = [];

      var certTypes = Object.keys(CERT_TYPES);
      for (var i = 0; i < certTypes.length; i++) {
        var certType = certTypes[i];
        var def = CERT_TYPES[certType];

        var allDone = def.requiredLabs.every(function (labId) {
          return completedLabs.indexOf(labId) !== -1;
        });

        if (allDone) {
          earned.push({
            type: certType,
            title: def.title,
            description: def.description,
            icon: def.icon,
            requiredLabs: def.requiredLabs
          });
        }
      }

      return earned;
    },

    /**
     * generate(certType) — generates a certificate with a verification hash
     * Returns { id, type, title, earnedAt, hash, labs, description }
     */
    generate: async function (certType) {
      var def = CERT_TYPES[certType];
      if (!def) return null;

      // Check if already stored
      var existing = Labs.Progress.getCertificates();
      if (existing[certType]) {
        return {
          id: certType,
          type: certType,
          title: def.title,
          earnedAt: existing[certType].earnedAt,
          hash: existing[certType].hash,
          labs: def.requiredLabs,
          description: def.description,
          icon: def.icon
        };
      }

      var earnedAt = new Date().toISOString();
      var hash = await generateHash(certType, def.requiredLabs, earnedAt);

      // Store in ProgressStore
      Labs.Progress.saveCertificate(certType, earnedAt, hash);

      return {
        id: certType,
        type: certType,
        title: def.title,
        earnedAt: earnedAt,
        hash: hash,
        labs: def.requiredLabs,
        description: def.description,
        icon: def.icon
      };
    },

    /**
     * showModal(cert) — displays a certificate modal
     * Renders a branded certificate card with copy/share capabilities.
     */
    showModal: function (cert) {
      var modal = ensureModal();

      document.getElementById('cert-icon').textContent = cert.icon || '\u26A1';
      document.getElementById('cert-title').textContent = cert.title;
      document.getElementById('cert-desc').textContent = cert.description;

      // Format date
      var date = new Date(cert.earnedAt);
      var months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
      document.getElementById('cert-earned').textContent = 'Earned: ' + months[date.getMonth()] + ' ' + date.getDate() + ', ' + date.getFullYear();

      document.getElementById('cert-labs').textContent = 'Labs: ' + cert.labs.length + '/' + cert.labs.length + ' completed';
      document.getElementById('cert-hash').textContent = cert.hash;

      modal.classList.add('visible');
    },

    /**
     * init() — checks for newly earned certificates and shows a toast/modal
     * Call this on lab completion to auto-detect milestones.
     */
    init: async function () {
      var earned = this.check();
      if (earned.length === 0) return;

      var storedCerts = Labs.Progress.getCertificates();
      var self = this;

      for (var i = 0; i < earned.length; i++) {
        var e = earned[i];
        if (!storedCerts[e.type]) {
          // Newly earned — generate and show
          var cert = await self.generate(e.type);
          if (cert) {
            Labs.Toast.show('Certificate earned: ' + cert.title, 'success');
            // Brief delay so the toast is visible before the modal
            (function (c) {
              setTimeout(function () { self.showModal(c); }, 1500);
            })(cert);
            // Only show one new certificate at a time
            break;
          }
        }
      }
    },

    /** Expose cert type definitions for external use */
    types: CERT_TYPES
  };

  /* ════════════════════════════════════════════════════
     Register on namespace (additive)
     ════════════════════════════════════════════════════ */

  Labs.Certificates = Certificates;

})();
