/**
 * Penumbra Forge — Lab Engine Core
 *
 * Config-driven lab orchestrator. Manages objectives, progress,
 * XP, hints, timing, and communication with target app Workers.
 */

(function () {
  'use strict';

  var STORAGE_KEY = 'pf-labs';
  var WORD_LIST = null; // Loaded lazily for Forge Key generation

  /* ════════════════════════════════════════════════════
     Progress Store
     ════════════════════════════════════════════════════ */

  var ProgressStore = {
    _data: null,

    load: function () {
      if (this._data) return this._data;
      try {
        this._data = JSON.parse(localStorage.getItem(STORAGE_KEY)) || this._default();
      } catch (e) {
        this._data = this._default();
      }
      return this._data;
    },

    save: function () {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this._data));
    },

    _default: function () {
      return {
        version: 1,
        profile: { alias: 'Anonymous Operator', level: 1, xp: 0, startedAt: new Date().toISOString() },
        labs: {},
        skills: {},
        forgeKey: null,
      };
    },

    getLabProgress: function (labId) {
      var data = this.load();
      if (!data.labs[labId]) {
        data.labs[labId] = {
          status: 'not_started',
          score: 0,
          xpEarned: 0,
          hintsUsed: [],
          timeElapsed: 0,
          completedAt: null,
          objectivesCompleted: [],
        };
      }
      return data.labs[labId];
    },

    completeObjective: function (labId, objectiveId) {
      var lab = this.getLabProgress(labId);
      if (lab.objectivesCompleted.indexOf(objectiveId) === -1) {
        lab.objectivesCompleted.push(objectiveId);
        if (lab.status === 'not_started') lab.status = 'in_progress';
        this.save();
        return true;
      }
      return false;
    },

    completeLab: function (labId, score, timeElapsed, config) {
      var lab = this.getLabProgress(labId);
      lab.status = 'completed';
      lab.score = score;
      lab.timeElapsed = timeElapsed;
      lab.completedAt = new Date().toISOString();

      // Calculate XP
      var baseXp = config.xpReward || 100;
      var hintPenalty = 0;
      lab.hintsUsed.forEach(function (idx) {
        hintPenalty += (config.hintCost && config.hintCost[idx]) || 0;
      });
      var xp = Math.max(baseXp - hintPenalty, Math.round(baseXp * 0.25));

      // Bonuses
      if (lab.hintsUsed.length === 0) xp = Math.round(xp * 1.25);
      if (config.estimatedTime && timeElapsed < config.estimatedTime * 60) xp = Math.round(xp * 1.15);

      lab.xpEarned = xp;

      // Update profile
      var data = this.load();
      data.profile.xp += xp;
      data.profile.level = XpSystem.levelForXp(data.profile.xp);

      // Mark skills
      if (config.skills) {
        config.skills.forEach(function (s) { data.skills[s] = true; });
      }

      this.save();
      return { xp: xp, totalXp: data.profile.xp, level: data.profile.level };
    },

    useHint: function (labId, hintIndex) {
      var lab = this.getLabProgress(labId);
      if (lab.hintsUsed.indexOf(hintIndex) === -1) {
        lab.hintsUsed.push(hintIndex);
        this.save();
        return true;
      }
      return false;
    },

    getProfile: function () {
      return this.load().profile;
    },

    getSkills: function () {
      return this.load().skills;
    },

    getCompletedLabs: function () {
      var data = this.load();
      return Object.keys(data.labs).filter(function (k) { return data.labs[k].status === 'completed'; });
    },

    getLabCount: function () {
      var data = this.load();
      var completed = 0;
      var inProgress = 0;
      Object.keys(data.labs).forEach(function (k) {
        if (data.labs[k].status === 'completed') completed++;
        else if (data.labs[k].status === 'in_progress') inProgress++;
      });
      return { completed: completed, inProgress: inProgress };
    },

    exportData: function () {
      return JSON.stringify(this.load());
    },

    importData: function (json) {
      try {
        var data = JSON.parse(json);
        if (data.version && data.profile && data.labs) {
          this._data = data;
          this.save();
          return true;
        }
      } catch (e) {}
      return false;
    },
  };

  /* ════════════════════════════════════════════════════
     XP System
     ════════════════════════════════════════════════════ */

  var LEVELS = [
    { level: 1, title: 'Script Kiddie', xp: 0 },
    { level: 2, title: 'Apprentice', xp: 100 },
    { level: 3, title: 'Analyst', xp: 300 },
    { level: 4, title: 'Operator', xp: 600 },
    { level: 5, title: 'Specialist', xp: 1000 },
    { level: 6, title: 'Expert', xp: 1500 },
    { level: 7, title: 'Elite', xp: 2200 },
    { level: 8, title: 'Architect', xp: 3000 },
    { level: 9, title: 'Adversary', xp: 4000 },
    { level: 10, title: 'Shadow', xp: 5000 },
  ];

  var XpSystem = {
    levelForXp: function (xp) {
      for (var i = LEVELS.length - 1; i >= 0; i--) {
        if (xp >= LEVELS[i].xp) return LEVELS[i].level;
      }
      return 1;
    },

    titleForLevel: function (level) {
      var l = LEVELS.find(function (lv) { return lv.level === level; });
      return l ? l.title : 'Unknown';
    },

    xpForLevel: function (level) {
      var l = LEVELS.find(function (lv) { return lv.level === level; });
      return l ? l.xp : 0;
    },

    xpForNextLevel: function (level) {
      var next = LEVELS.find(function (lv) { return lv.level === level + 1; });
      return next ? next.xp : Infinity;
    },

    progressToNextLevel: function (xp) {
      var level = this.levelForXp(xp);
      var current = this.xpForLevel(level);
      var next = this.xpForNextLevel(level);
      if (next === Infinity) return 1;
      return (xp - current) / (next - current);
    },

    levels: LEVELS,
  };

  /* ════════════════════════════════════════════════════
     Forge Key — Generation & Crypto
     ════════════════════════════════════════════════════ */

  // Curated word list — memorable, distinct, no ambiguity
  var FORGE_WORDS = [
    'ember', 'cascade', 'prism', 'forge', 'nexus', 'cipher', 'drift', 'pulse',
    'onyx', 'quartz', 'helix', 'lunar', 'solar', 'venom', 'ghost', 'storm',
    'atlas', 'blade', 'crest', 'delta', 'epoch', 'flare', 'glyph', 'haven',
    'ivory', 'jade', 'karma', 'lumen', 'mirage', 'noble', 'omega', 'phalanx',
    'radix', 'sigma', 'titan', 'umbra', 'vault', 'warden', 'xenon', 'zenith',
    'apex', 'basalt', 'cobalt', 'dusk', 'echo', 'frost', 'granite', 'haze',
    'iron', 'jasper', 'krypton', 'lattice', 'marble', 'neutron', 'obsidian', 'pyrite',
    'reef', 'shard', 'thorn', 'vector', 'wraith', 'zephyr', 'amber', 'binary',
    'chrome', 'depth', 'enigma', 'flux', 'grail', 'horizon', 'index', 'jolt',
    'kernel', 'lynx', 'matrix', 'nova', 'orbit', 'phantom', 'quasar', 'rune',
    'spectre', 'tempest', 'ultra', 'vertex', 'warp', 'xenith', 'yield', 'zero',
    'alloy', 'beacon', 'conduit', 'dynamo', 'ether', 'fulcrum', 'geode', 'hydra',
    'ignite', 'junction', 'kinetic', 'lithium', 'magnet', 'nether', 'oxide', 'plasma',
    'quantum', 'reactor', 'stealth', 'turbo', 'uplink', 'vortex', 'weld', 'xray',
    'arcane', 'breach', 'cortex', 'daemon', 'exalt', 'fiber', 'galvanic', 'helios',
    'inferno', 'jackal', 'keystone', 'lance', 'mantle', 'nebula', 'opal', 'praxis',
  ];

  var ForgeKey = {
    generate: function () {
      var arr = new Uint32Array(3);
      crypto.getRandomValues(arr);
      var w1 = FORGE_WORDS[arr[0] % FORGE_WORDS.length];
      var w2 = FORGE_WORDS[arr[1] % FORGE_WORDS.length];
      var hex = (arr[2] % 65536).toString(16).padStart(4, '0');
      return w1 + '-' + w2 + '-' + hex;
    },

    deriveStorageKey: async function (forgeKey) {
      var parts = forgeKey.split('-');
      var storageInput = parts[0] + '-' + parts[1];
      var encoded = new TextEncoder().encode(storageInput);
      var hash = await crypto.subtle.digest('SHA-256', encoded);
      var arr = Array.from(new Uint8Array(hash));
      return arr.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    },

    deriveEncryptionKey: async function (forgeKey) {
      var encoded = new TextEncoder().encode(forgeKey);
      var keyMaterial = await crypto.subtle.importKey('raw', encoded, 'PBKDF2', false, ['deriveKey']);
      var salt = new TextEncoder().encode('penumbra-forge-labs-v1');
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    },

    encrypt: async function (forgeKey, plaintext) {
      var key = await this.deriveEncryptionKey(forgeKey);
      var iv = crypto.getRandomValues(new Uint8Array(12));
      var encoded = new TextEncoder().encode(plaintext);
      var ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encoded);
      return {
        iv: Array.from(iv).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''),
        ciphertext: Array.from(new Uint8Array(ciphertext)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''),
      };
    },

    decrypt: async function (forgeKey, ivHex, ciphertextHex) {
      var key = await this.deriveEncryptionKey(forgeKey);
      var iv = new Uint8Array(ivHex.match(/.{2}/g).map(function (h) { return parseInt(h, 16); }));
      var ciphertext = new Uint8Array(ciphertextHex.match(/.{2}/g).map(function (h) { return parseInt(h, 16); }));
      var plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
      return new TextDecoder().decode(plaintext);
    },
  };

  /* ════════════════════════════════════════════════════
     Timer System
     ════════════════════════════════════════════════════ */

  var TimerSystem = {
    _startTime: null,
    _elapsed: 0,
    _interval: null,
    _callback: null,

    start: function (callback) {
      this._startTime = Date.now();
      this._elapsed = 0;
      this._callback = callback;
      var self = this;
      this._interval = setInterval(function () {
        self._elapsed = Math.floor((Date.now() - self._startTime) / 1000);
        if (self._callback) self._callback(self._elapsed);
      }, 1000);
    },

    stop: function () {
      if (this._interval) clearInterval(this._interval);
      this._interval = null;
      return this._elapsed;
    },

    getElapsed: function () {
      return this._elapsed;
    },

    format: function (seconds) {
      var m = Math.floor(seconds / 60);
      var s = seconds % 60;
      return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
    },
  };

  /* ════════════════════════════════════════════════════
     Toast System
     ════════════════════════════════════════════════════ */

  var ToastSystem = {
    _el: null,
    _timeout: null,

    init: function () {
      this._el = document.createElement('div');
      this._el.className = 'lab-toast';
      this._el.innerHTML = '<span class="lab-toast-icon"></span><span class="lab-toast-msg"></span>';
      document.body.appendChild(this._el);
    },

    show: function (message, type) {
      if (!this._el) this.init();
      var icon = type === 'success' ? '✓' : type === 'error' ? '✗' : type === 'level' ? '⬆' : 'ℹ';
      this._el.querySelector('.lab-toast-icon').textContent = icon;
      this._el.querySelector('.lab-toast-msg').textContent = message;
      this._el.className = 'lab-toast lab-toast--' + (type || 'info') + ' visible';
      clearTimeout(this._timeout);
      var self = this;
      this._timeout = setTimeout(function () { self._el.classList.remove('visible'); }, 3500);
    },
  };

  /* ════════════════════════════════════════════════════
     Lab Engine — Main Orchestrator
     ════════════════════════════════════════════════════ */

  var LabEngine = {
    config: null,
    _objectiveCallbacks: {},

    init: function (config) {
      this.config = config;
      TimerSystem.start(this._onTick.bind(this));
      return this;
    },

    _onTick: function (elapsed) {
      var timerEl = document.getElementById('lab-timer');
      if (timerEl) timerEl.textContent = TimerSystem.format(elapsed);
    },

    registerObjectiveValidator: function (objectiveId, fn) {
      this._objectiveCallbacks[objectiveId] = fn;
    },

    tryCompleteObjective: function (objectiveId) {
      if (!this.config) return false;

      var progress = ProgressStore.getLabProgress(this.config.id);
      if (progress.objectivesCompleted.indexOf(objectiveId) !== -1) return false;

      var isNew = ProgressStore.completeObjective(this.config.id, objectiveId);
      if (isNew) {
        var obj = this.config.objectives.find(function (o) { return o.id === objectiveId; });
        ToastSystem.show('Step ' + (obj ? obj.step : '?') + ' complete — ' + (obj ? obj.title : objectiveId), 'success');
        this._updateObjectiveUI(objectiveId);

        // Check if all objectives are done
        var allDone = this.config.objectives.every(function (o) {
          return progress.objectivesCompleted.indexOf(o.id) !== -1;
        });

        if (allDone) {
          this._onLabComplete();
        }
      }
      return isNew;
    },

    _updateObjectiveUI: function (objectiveId) {
      var el = document.getElementById('obj-' + objectiveId);
      if (el) {
        el.classList.remove('current');
        el.classList.add('completed');
        var check = el.querySelector('.lab-obj-check');
        if (check) check.textContent = '✓';
      }

      // Advance current marker to next incomplete
      var progress = ProgressStore.getLabProgress(this.config.id);
      this.config.objectives.forEach(function (o) {
        var objEl = document.getElementById('obj-' + o.id);
        if (!objEl) return;
        if (progress.objectivesCompleted.indexOf(o.id) === -1 && !document.querySelector('.lab-objective.current')) {
          objEl.classList.add('current');
        }
      });
    },

    revealHint: function (index) {
      ProgressStore.useHint(this.config.id, index);
      var cost = (this.config.hintCost && this.config.hintCost[index]) || 0;
      ToastSystem.show('Hint revealed (−' + cost + ' XP)', 'info');
    },

    _onLabComplete: function () {
      var elapsed = TimerSystem.stop();
      var score = this._calculateScore();
      var result = ProgressStore.completeLab(this.config.id, score, elapsed, this.config);

      // Show completion overlay
      this._showCompletion(result, elapsed, score);
    },

    _calculateScore: function () {
      var progress = ProgressStore.getLabProgress(this.config.id);
      var base = 100;
      var hintPenalty = progress.hintsUsed.length * 10;
      return Math.max(base - hintPenalty, 25);
    },

    _showCompletion: function (result, elapsed, score) {
      var overlay = document.getElementById('lab-complete-overlay');
      if (!overlay) return;

      var progress = ProgressStore.getLabProgress(this.config.id);

      document.getElementById('complete-time').textContent = TimerSystem.format(elapsed);
      document.getElementById('complete-score').textContent = score;
      document.getElementById('complete-xp').textContent = '+' + result.xp;
      document.getElementById('complete-hints').textContent = progress.hintsUsed.length;
      document.getElementById('complete-level').textContent = 'Level ' + result.level + ' — ' + XpSystem.titleForLevel(result.level);

      overlay.classList.add('visible');

      // Unlock connected blue team lab
      if (this.config.unlocks && this.config.unlocks.length > 0) {
        var unlockEl = document.getElementById('complete-unlock');
        if (unlockEl) {
          unlockEl.style.display = '';
          unlockEl.textContent = 'Blue Team lab unlocked →';
        }
      }
    },

    getProgress: function () {
      return ProgressStore.getLabProgress(this.config.id);
    },

    isObjectiveComplete: function (objectiveId) {
      var progress = ProgressStore.getLabProgress(this.config.id);
      return progress.objectivesCompleted.indexOf(objectiveId) !== -1;
    },
  };

  /* ════════════════════════════════════════════════════
     Server Logs (simulated)
     ════════════════════════════════════════════════════ */

  var ServerLogs = {
    _el: null,

    init: function (containerId) {
      this._el = document.getElementById(containerId);
    },

    add: function (level, message) {
      if (!this._el) return;
      var elapsed = TimerSystem.getElapsed();
      var time = TimerSystem.format(elapsed);
      var levelClass = 'lab-log-level-' + level;
      var entry = document.createElement('div');
      entry.className = 'lab-log-entry';
      entry.innerHTML = '<span class="lab-log-time">[' + time + ']</span> <span class="' + levelClass + '">' + level.toUpperCase() + '</span> <span class="lab-log-msg">' + message + '</span>';
      this._el.appendChild(entry);
      this._el.scrollTop = this._el.scrollHeight;
    },
  };

  /* ════════════════════════════════════════════════════
     Export to global scope
     ════════════════════════════════════════════════════ */

  /* ════════════════════════════════════════════════════
     Sync System — Forge Key cloud sync
     ════════════════════════════════════════════════════ */

  var SYNC_URL = 'https://lab-sync.penumbraforge.workers.dev';

  var SyncSystem = {
    async save(forgeKey) {
      var storageKey = await ForgeKey.deriveStorageKey(forgeKey);
      var plaintext = ProgressStore.exportData();
      var encrypted = await ForgeKey.encrypt(forgeKey, plaintext);

      var resp = await fetch(SYNC_URL + '/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          storageKey: storageKey,
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
        }),
      });

      var data = await resp.json();
      if (data.error) throw new Error(data.error);

      // Save the forge key locally (encrypted reference only)
      var store = ProgressStore.load();
      store.forgeKey = forgeKey;
      ProgressStore.save();

      return true;
    },

    async restore(forgeKey) {
      var storageKey = await ForgeKey.deriveStorageKey(forgeKey);

      var resp = await fetch(SYNC_URL + '/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ storageKey: storageKey }),
      });

      var data = await resp.json();
      if (data.error) throw new Error(data.error);

      var plaintext = await ForgeKey.decrypt(forgeKey, data.iv, data.ciphertext);
      ProgressStore.importData(plaintext);

      // Save the forge key locally
      var store = ProgressStore.load();
      store.forgeKey = forgeKey;
      ProgressStore.save();

      return true;
    },

    getStoredForgeKey: function () {
      var store = ProgressStore.load();
      return store.forgeKey || null;
    },
  };

  /* ════════════════════════════════════════════════════
     Forge Key Modal UI
     ════════════════════════════════════════════════════ */

  var ForgeKeyUI = {
    init: function () {
      this._createModal();
      this._bindEvents();
    },

    _createModal: function () {
      var modal = document.createElement('div');
      modal.id = 'forge-key-modal';
      modal.className = 'fk-modal';
      modal.innerHTML =
        '<div class="fk-card">' +
          '<div class="fk-close" id="fk-close">&times;</div>' +
          '<div id="fk-view-main" class="fk-view">' +
            '<div class="fk-title">Forge Key</div>' +
            '<div class="fk-desc">Your progress is encrypted with your Forge Key. We can\'t see your data. We don\'t know who you are.</div>' +
            '<div class="fk-encrypt-badge">&#x1f512; AES-256-GCM — your key never leaves your browser</div>' +
            '<div class="fk-actions">' +
              '<button class="fk-btn fk-btn-primary" id="fk-btn-new">Generate New Forge Key</button>' +
              '<button class="fk-btn fk-btn-secondary" id="fk-btn-restore">Restore with Existing Key</button>' +
            '</div>' +
            '<div class="fk-stored" id="fk-stored" style="display:none;">' +
              '<div class="fk-stored-label">Current Forge Key</div>' +
              '<div class="fk-stored-key" id="fk-stored-key"></div>' +
              '<button class="fk-btn fk-btn-primary" id="fk-btn-sync-now" style="margin-top:10px;">Sync Now</button>' +
            '</div>' +
          '</div>' +
          '<div id="fk-view-generate" class="fk-view" style="display:none;">' +
            '<div class="fk-title">Your Forge Key</div>' +
            '<div class="fk-key-display" id="fk-generated-key"></div>' +
            '<div class="fk-key-warning">Write this down. It\'s your only way back.<br>We <strong>cannot recover it</strong> — that\'s the point.</div>' +
            '<button class="fk-btn fk-btn-copy" id="fk-btn-copy">Copy Key</button>' +
            '<button class="fk-btn fk-btn-primary" id="fk-btn-save" style="margin-top:8px;">I\'ve Saved It — Encrypt &amp; Sync</button>' +
            '<div class="fk-status" id="fk-save-status"></div>' +
          '</div>' +
          '<div id="fk-view-restore" class="fk-view" style="display:none;">' +
            '<div class="fk-title">Restore Progress</div>' +
            '<div class="fk-desc">Enter your Forge Key to decrypt and restore your progress.</div>' +
            '<input type="text" class="fk-input" id="fk-restore-input" placeholder="ember-cascade-7x9k" autocomplete="off" spellcheck="false">' +
            '<button class="fk-btn fk-btn-primary" id="fk-btn-do-restore" style="margin-top:10px;">Decrypt &amp; Restore</button>' +
            '<button class="fk-btn fk-btn-secondary" id="fk-btn-back" style="margin-top:6px;">Back</button>' +
            '<div class="fk-status" id="fk-restore-status"></div>' +
          '</div>' +
        '</div>';
      document.body.appendChild(modal);
    },

    _bindEvents: function () {
      var self = this;
      var modal = document.getElementById('forge-key-modal');

      document.getElementById('fk-close').addEventListener('click', function () { self.hide(); });
      modal.addEventListener('click', function (e) { if (e.target === modal) self.hide(); });

      document.getElementById('fk-btn-new').addEventListener('click', function () {
        var key = ForgeKey.generate();
        document.getElementById('fk-generated-key').textContent = key;
        self._showView('generate');
      });

      document.getElementById('fk-btn-copy').addEventListener('click', function () {
        var key = document.getElementById('fk-generated-key').textContent;
        navigator.clipboard.writeText(key);
        this.textContent = 'Copied!';
        setTimeout(function () { document.getElementById('fk-btn-copy').textContent = 'Copy Key'; }, 2000);
      });

      document.getElementById('fk-btn-save').addEventListener('click', async function () {
        var key = document.getElementById('fk-generated-key').textContent;
        var status = document.getElementById('fk-save-status');
        status.textContent = 'Encrypting and syncing...';
        status.className = 'fk-status fk-status-info';
        try {
          await SyncSystem.save(key);
          status.textContent = 'Synced! Your progress is encrypted and saved.';
          status.className = 'fk-status fk-status-ok';
          self._updateStoredDisplay();
          setTimeout(function () { self.hide(); }, 2000);
        } catch (err) {
          status.textContent = 'Error: ' + err.message;
          status.className = 'fk-status fk-status-err';
        }
      });

      document.getElementById('fk-btn-restore').addEventListener('click', function () {
        self._showView('restore');
      });

      document.getElementById('fk-btn-back').addEventListener('click', function () {
        self._showView('main');
      });

      document.getElementById('fk-btn-do-restore').addEventListener('click', async function () {
        var key = document.getElementById('fk-restore-input').value.trim();
        var status = document.getElementById('fk-restore-status');
        if (!key) { document.getElementById('fk-restore-input').focus(); return; }

        status.textContent = 'Decrypting...';
        status.className = 'fk-status fk-status-info';
        try {
          await SyncSystem.restore(key);
          status.textContent = 'Restored! Reloading...';
          status.className = 'fk-status fk-status-ok';
          setTimeout(function () { location.reload(); }, 1500);
        } catch (err) {
          status.textContent = err.message === 'No data found for this Forge Key'
            ? 'No progress found for this Forge Key. Check your key and try again.'
            : 'Decryption failed. Wrong key or corrupted data.';
          status.className = 'fk-status fk-status-err';
        }
      });

      // Sync now button
      document.getElementById('fk-btn-sync-now').addEventListener('click', async function () {
        var key = SyncSystem.getStoredForgeKey();
        if (!key) return;
        this.textContent = 'Syncing...';
        try {
          await SyncSystem.save(key);
          this.textContent = 'Synced!';
          setTimeout(function () { document.getElementById('fk-btn-sync-now').textContent = 'Sync Now'; }, 2000);
        } catch (err) {
          this.textContent = 'Error';
          setTimeout(function () { document.getElementById('fk-btn-sync-now').textContent = 'Sync Now'; }, 2000);
        }
      });

      // Restore input enter key
      document.getElementById('fk-restore-input').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') document.getElementById('fk-btn-do-restore').click();
      });
    },

    _showView: function (view) {
      document.getElementById('fk-view-main').style.display = view === 'main' ? '' : 'none';
      document.getElementById('fk-view-generate').style.display = view === 'generate' ? '' : 'none';
      document.getElementById('fk-view-restore').style.display = view === 'restore' ? '' : 'none';
    },

    _updateStoredDisplay: function () {
      var key = SyncSystem.getStoredForgeKey();
      var el = document.getElementById('fk-stored');
      var keyEl = document.getElementById('fk-stored-key');
      if (key) {
        el.style.display = '';
        keyEl.textContent = key;
      } else {
        el.style.display = 'none';
      }
    },

    show: function () {
      this._showView('main');
      this._updateStoredDisplay();
      document.getElementById('forge-key-modal').classList.add('visible');
    },

    hide: function () {
      document.getElementById('forge-key-modal').classList.remove('visible');
    },
  };

  /* ════════════════════════════════════════════════════
     Simulation Bridge
     ════════════════════════════════════════════════════ */

  var SimulationBridge = {
    onStateTransition: function (labId, fromState, toState, action) {
      ProgressStore.completeObjective(labId, toState);
    },
    onLabComplete: function (labId, config, elapsed, scoringData) {
      var scoreResult;
      if (window.PenumbraLabs.Scoring && scoringData) {
        scoreResult = window.PenumbraLabs.Scoring.calculate({
          actionsLog:      scoringData.actionsLog      || [],
          scenario:        config,
          elapsed:         elapsed,
          nudgesShown:     scoringData.nudgesShown     || 0,
          nudgesDismissed: scoringData.nudgesDismissed || 0,
          evidenceFound:   scoringData.evidenceFound   || 0,
          totalEvidence:   scoringData.totalEvidence   || 1
        });
      } else {
        scoreResult = { composite: 100, xp: config.xpReward || 100, technique: 100, efficiency: 100, thoroughness: 100, independence: 100, bonuses: {} };
      }
      var result = ProgressStore.completeLab(labId, scoreResult.composite, elapsed, config);
      result.scoring = scoreResult;
      return result;
    }
  };

  window.PenumbraLabs = {
    Engine: LabEngine,
    Progress: ProgressStore,
    Xp: XpSystem,
    Timer: TimerSystem,
    Toast: ToastSystem,
    ServerLogs: ServerLogs,
    ForgeKey: ForgeKey,
    Sync: SyncSystem,
    ForgeKeyUI: ForgeKeyUI,
    SimulationBridge: SimulationBridge,
  };
})();
