/**
 * Penumbra Forge — Panel System
 *
 * Resizable three-panel layout for the red team workstation.
 * Each panel is independently resizable via drag handles
 * with persistent width storage per lab.
 */

(function () {
  'use strict';

  var PanelSystem = {
    _container: null,
    _panels: {},       // id -> { el, config }
    _handles: [],      // drag handle elements
    _labId: null,

    /**
     * Initialize the panel system.
     *
     * @param {Object} opts
     * @param {HTMLElement} opts.container  - The .ws-workspace element
     * @param {Array} opts.panels - Panel configs: [{id, minWidth, defaultWidth, flex}]
     */
    init: function (opts) {
      this._container = opts.container;
      this._labId = this._container.getAttribute('data-lab-id') || 'default';

      var panelConfigs = opts.panels || [];
      var savedWidths = this._loadWidths();

      for (var i = 0; i < panelConfigs.length; i++) {
        var cfg = panelConfigs[i];
        var el = this._container.querySelector('#' + cfg.id);

        if (!el) {
          el = this._container.querySelector('[data-panel="' + cfg.id + '"]');
        }

        if (!el) continue;

        // Ensure the panel has the base class
        if (!el.classList.contains('ws-panel')) {
          el.classList.add('ws-panel');
        }

        // Apply flex or fixed width
        if (cfg.flex) {
          el.classList.add('ws-panel-flex');
          el.style.width = '';
        } else {
          var width = savedWidths[cfg.id] || cfg.defaultWidth || 300;
          if (cfg.minWidth && width < cfg.minWidth) {
            width = cfg.minWidth;
          }
          el.style.width = width + 'px';
          el.style.flexShrink = '0';
        }

        // Ensure scroll regions exist
        var regions = el.querySelectorAll('.ws-panel-region');
        for (var r = 0; r < regions.length; r++) {
          // Classes already applied via CSS, just confirm they exist
          regions[r].style.overflowY = 'auto';
          regions[r].style.overflowX = 'hidden';
        }

        this._panels[cfg.id] = { el: el, config: cfg, collapsed: false, _prevWidth: null };
      }

      // Find and activate drag handles
      this._initHandles();
    },

    /**
     * Get a panel's DOM element by id.
     * @param {string} id
     * @returns {HTMLElement|null}
     */
    getPanel: function (id) {
      var entry = this._panels[id];
      return entry ? entry.el : null;
    },

    /**
     * Collapse a panel to zero width.
     * @param {string} id
     */
    collapse: function (id) {
      var entry = this._panels[id];
      if (!entry || entry.config.flex || entry.collapsed) return;

      entry._prevWidth = entry.el.offsetWidth;
      entry.el.style.width = '0px';
      entry.el.style.overflow = 'hidden';
      entry.el.classList.add('ws-panel-collapsed');
      entry.collapsed = true;
      this._saveWidths();
    },

    /**
     * Expand a collapsed panel back to its previous width.
     * @param {string} id
     */
    expand: function (id) {
      var entry = this._panels[id];
      if (!entry || entry.config.flex || !entry.collapsed) return;

      var width = entry._prevWidth || entry.config.defaultWidth || 300;
      entry.el.style.width = width + 'px';
      entry.el.style.overflow = '';
      entry.el.classList.remove('ws-panel-collapsed');
      entry.collapsed = false;
      this._saveWidths();
    },

    /* ─── Private ─── */

    /**
     * Find .ws-drag-handle elements in the container and wire up drag logic.
     */
    _initHandles: function () {
      var handles = this._container.querySelectorAll('.ws-drag-handle');
      for (var i = 0; i < handles.length; i++) {
        this._attachDrag(handles[i]);
        this._handles.push(handles[i]);
      }
    },

    /**
     * Attach mousedown -> mousemove -> mouseup drag behavior to a handle.
     * The handle resizes the panel immediately to its left (previousElementSibling).
     */
    _attachDrag: function (handle) {
      var self = this;

      handle.addEventListener('mousedown', function (e) {
        e.preventDefault();

        var leftPanel = handle.previousElementSibling;
        if (!leftPanel) return;

        // Find the config for this panel
        var panelEntry = self._findEntryByEl(leftPanel);
        if (!panelEntry || panelEntry.config.flex) return;

        var startX = e.clientX;
        var startWidth = leftPanel.offsetWidth;
        var minWidth = panelEntry.config.minWidth || 100;

        // Compute max width: container width minus other fixed panels minus handles minus some buffer
        var maxWidth = self._computeMaxWidth(panelEntry.config.id);

        handle.classList.add('dragging');
        document.body.classList.add('ws-dragging');

        function onMouseMove(e) {
          var delta = e.clientX - startX;
          var newWidth = startWidth + delta;

          // Clamp
          if (newWidth < minWidth) newWidth = minWidth;
          if (newWidth > maxWidth) newWidth = maxWidth;

          leftPanel.style.width = newWidth + 'px';
        }

        function onMouseUp() {
          handle.classList.remove('dragging');
          document.body.classList.remove('ws-dragging');

          document.removeEventListener('mousemove', onMouseMove);
          document.removeEventListener('mouseup', onMouseUp);

          self._saveWidths();
        }

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
      });
    },

    /**
     * Find a panel entry by its DOM element.
     */
    _findEntryByEl: function (el) {
      var ids = Object.keys(this._panels);
      for (var i = 0; i < ids.length; i++) {
        if (this._panels[ids[i]].el === el) return this._panels[ids[i]];
      }
      return null;
    },

    /**
     * Compute the maximum allowed width for a given panel,
     * ensuring other fixed panels keep their minWidth and the flex panel has space.
     */
    _computeMaxWidth: function (panelId) {
      var containerWidth = this._container.offsetWidth;
      var handleSpace = this._handles.length * 4;
      var reservedForOthers = 0;

      var ids = Object.keys(this._panels);
      for (var i = 0; i < ids.length; i++) {
        if (ids[i] === panelId) continue;
        var entry = this._panels[ids[i]];
        if (entry.config.flex) {
          // Flex panel needs at least 200px
          reservedForOthers += 200;
        } else {
          reservedForOthers += (entry.config.minWidth || 100);
        }
      }

      return containerWidth - handleSpace - reservedForOthers;
    },

    /**
     * Save current panel widths to localStorage.
     */
    _saveWidths: function () {
      var widths = {};
      var ids = Object.keys(this._panels);
      for (var i = 0; i < ids.length; i++) {
        var entry = this._panels[ids[i]];
        if (!entry.config.flex) {
          widths[ids[i]] = entry.el.offsetWidth;
        }
      }
      try {
        localStorage.setItem('pf-panel-widths-' + this._labId, JSON.stringify(widths));
      } catch (e) {
        // Storage full or unavailable — silently ignore
      }
    },

    /**
     * Load saved panel widths from localStorage.
     * @returns {Object} Map of panel id -> width in px
     */
    _loadWidths: function () {
      try {
        var raw = localStorage.getItem('pf-panel-widths-' + this._labId);
        return raw ? JSON.parse(raw) : {};
      } catch (e) {
        return {};
      }
    }
  };

  // Register on the shared namespace (don't overwrite existing properties)
  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PanelSystem = PanelSystem;
})();
