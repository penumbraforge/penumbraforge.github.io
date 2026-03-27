/**
 * Penumbra Forge — Simulation Engine
 *
 * Config-driven simulation engine that replaces regex-based objective
 * detection. Tracks user actions, manages lab state via a state machine,
 * validates exploit success, and provides contextual nudges for beginners.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     State Machine
     ════════════════════════════════════════════════════ */

  function StateMachine(stateGraph) {
    this._graph = stateGraph;
    this._current = stateGraph.initialState;
  }

  Object.defineProperty(StateMachine.prototype, 'current', {
    get: function () {
      return this._current;
    }
  });

  StateMachine.prototype.transition = function (action) {
    var stateNode = this._graph.states[this._current];
    if (!stateNode || !stateNode.transitions) return null;

    var nextState = stateNode.transitions[action];
    if (nextState && this._graph.states[nextState]) {
      this._current = nextState;
      return this._current;
    }
    return null;
  };

  StateMachine.prototype.isComplete = function () {
    var stateNode = this._graph.states[this._current];
    return !!(stateNode && stateNode.terminal);
  };

  StateMachine.prototype.getAvailableActions = function () {
    var stateNode = this._graph.states[this._current];
    if (!stateNode || !stateNode.transitions) return [];
    return Object.keys(stateNode.transitions);
  };

  StateMachine.prototype.reset = function () {
    this._current = this._graph.initialState;
  };

  /* ════════════════════════════════════════════════════
     Validator
     ════════════════════════════════════════════════════ */

  var Validator = {
    _rules: null,

    init: function (opts) {
      this._rules = opts.validationRules || {};
      return this;
    },

    check: function (actionName, action) {
      var rule = this._rules[actionName];
      if (!rule) return { success: false };

      // Check if the action type matches the rule trigger
      var triggerMatch = false;
      if (rule.trigger === 'terminal_or_repeater') {
        triggerMatch = action.type === 'terminal' || action.type === 'repeater';
      } else if (rule.trigger === 'iframe_message') {
        triggerMatch = action.type === 'iframe_message';
      } else if (rule.trigger === 'browser') {
        triggerMatch = action.type === 'browser';
      }

      if (!triggerMatch) return { success: false };

      // Run the condition function
      var conditionArg = rule.trigger === 'iframe_message' ? action.message : action;
      var passed = false;
      try {
        passed = !!rule.condition(conditionArg);
      } catch (e) {
        passed = false;
      }

      return { success: passed };
    }
  };

  /* ════════════════════════════════════════════════════
     Action Router
     ════════════════════════════════════════════════════ */

  var ActionRouter = {
    _scenario: null,
    _stateMachine: null,
    _validator: null,
    _onStateChange: null,
    _onComplete: null,
    _actionsLog: null,

    init: function (opts) {
      this._scenario = opts.scenario;
      this._stateMachine = opts.stateMachine;
      this._validator = opts.validator;
      this._onStateChange = opts.onStateChange || function () {};
      this._onComplete = opts.onComplete || function () {};
      this._actionsLog = [];
      return this;
    },

    dispatch: function (action) {
      // Log every action for nudge engine and scoring
      this._actionsLog.push({
        action: action,
        timestamp: Date.now()
      });

      // Check all available transitions from current state
      var available = this._stateMachine.getAvailableActions();
      var fromState = this._stateMachine.current;

      for (var i = 0; i < available.length; i++) {
        var actionName = available[i];
        var result = this._validator.check(actionName, action);

        if (result.success) {
          var newState = this._stateMachine.transition(actionName);
          if (newState !== null) {
            this._onStateChange(fromState, newState, action);

            if (this._stateMachine.isComplete()) {
              this._onComplete();
            }
            return;
          }
        }
      }
    },

    getActionsLog: function () {
      return this._actionsLog;
    }
  };

  /* ════════════════════════════════════════════════════
     Nudge Engine
     ════════════════════════════════════════════════════ */

  var NudgeEngine = {
    _nudges: null,
    _userLevel: 1,
    _container: null,
    _getCurrentState: null,
    _lastActionTime: 0,
    _shownNudges: null,
    _disabled: false,
    _interval: null,
    _currentOverlay: null,

    init: function (opts) {
      this._nudges = opts.nudges || {};
      this._userLevel = opts.userLevel || 1;
      this._container = opts.container;
      this._getCurrentState = opts.getCurrentState;
      this._lastActionTime = Date.now();
      this._shownNudges = {};
      this._disabled = false;
      this._currentOverlay = null;

      // Auto-disable for advanced users
      if (this._userLevel >= 7) {
        this._disabled = true;
        return this;
      }

      // Start the tick interval (every 5 seconds)
      var self = this;
      this._interval = setInterval(function () {
        var elapsed = (Date.now() - self._lastActionTime) / 1000;
        self.tick(elapsed);
      }, 5000);

      return this;
    },

    tick: function (elapsed) {
      if (this._disabled) return null;

      var currentState = this._getCurrentState();
      var nudge = this._nudges[currentState];

      if (!nudge) return null;
      if (this._shownNudges[currentState]) return null;

      // Calculate effective delay
      var delay = nudge.delay;
      if (this._userLevel >= 4 && this._userLevel <= 6) {
        delay = delay * 2;
      }

      if (elapsed >= delay) {
        this._shownNudges[currentState] = true;
        this._showNudge(currentState, nudge);
        return nudge;
      }

      return null;
    },

    _showNudge: function (nudgeId, nudge) {
      if (!this._container) return;

      // Remove any existing nudge overlay
      this._removeOverlay();

      var overlay = document.createElement('div');
      overlay.className = 'sim-nudge';
      overlay.setAttribute('data-nudge-id', nudgeId);

      var text = document.createElement('span');
      text.className = 'sim-nudge-text';
      text.textContent = nudge.text;

      var dismiss = document.createElement('button');
      dismiss.className = 'sim-nudge-dismiss';
      dismiss.textContent = 'Got it';
      dismiss.type = 'button';

      var self = this;
      dismiss.addEventListener('click', function () {
        self.dismiss(nudgeId);
      });

      overlay.appendChild(text);
      overlay.appendChild(dismiss);
      this._container.appendChild(overlay);
      this._currentOverlay = overlay;
    },

    _removeOverlay: function () {
      if (this._currentOverlay && this._currentOverlay.parentNode) {
        this._currentOverlay.parentNode.removeChild(this._currentOverlay);
        this._currentOverlay = null;
      }
    },

    dismiss: function (nudgeId) {
      this._shownNudges[nudgeId] = true;
      this._removeOverlay();
    },

    toggle: function () {
      if (this._disabled) {
        this._disabled = false;
        // Restart interval if not running
        if (!this._interval) {
          var self = this;
          this._interval = setInterval(function () {
            var elapsed = (Date.now() - self._lastActionTime) / 1000;
            self.tick(elapsed);
          }, 5000);
        }
      } else {
        this._disabled = true;
        if (this._interval) {
          clearInterval(this._interval);
          this._interval = null;
        }
        this._removeOverlay();
      }
    },

    isEnabled: function () {
      return !this._disabled;
    },

    disable: function () {
      this._disabled = true;
      if (this._interval) {
        clearInterval(this._interval);
        this._interval = null;
      }
      this._removeOverlay();
    },

    /**
     * Reset the last-action timer. Called by the facade when
     * ActionRouter dispatches an action.
     */
    resetTimer: function () {
      this._lastActionTime = Date.now();
    },

    destroy: function () {
      if (this._interval) {
        clearInterval(this._interval);
        this._interval = null;
      }
      this._removeOverlay();
    }
  };

  /* ════════════════════════════════════════════════════
     Simulation Facade
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};

  window.PenumbraLabs.Simulation = {
    /**
     * Initialize a simulation for a lab scenario.
     *
     * @param {Object} config
     * @param {Object} config.scenario        - Scenario definition (stateGraph, validationRules, nudges)
     * @param {Object} config.bridge          - SimulationBridge from lab-engine.js
     * @param {Function} config.onStateChange - Callback(fromState, toState, action)
     * @param {Function} config.onComplete    - Callback when lab is complete
     * @returns {Object} Controller with dispatch, currentState, reset methods
     */
    init: function (config) {
      var scenario = config.scenario;
      var bridge = config.bridge;
      var userOnStateChange = config.onStateChange || function () {};
      var userOnComplete = config.onComplete || function () {};

      // Build the state machine from the scenario graph
      var stateMachine = new StateMachine(scenario.stateGraph);

      // Build the validator from the scenario rules
      var validator = Object.create(Validator);
      validator.init({ validationRules: scenario.validationRules });

      // Build the nudge engine
      var nudgeEngine = Object.create(NudgeEngine);
      nudgeEngine.init({
        nudges: scenario.nudges || {},
        userLevel: scenario.userLevel || 1,
        container: scenario.nudgeContainer || null,
        getCurrentState: function () {
          return stateMachine.current;
        }
      });

      // Build the action router
      var actionRouter = Object.create(ActionRouter);
      actionRouter.init({
        scenario: scenario,
        stateMachine: stateMachine,
        validator: validator,
        onStateChange: function (fromState, toState, action) {
          // Notify the bridge for progress persistence
          if (bridge && bridge.onStateTransition) {
            bridge.onStateTransition(scenario.labId, fromState, toState, action);
          }
          // Notify the caller
          userOnStateChange(fromState, toState, action);
        },
        onComplete: function () {
          // Notify the bridge for lab completion
          if (bridge && bridge.onLabComplete) {
            bridge.onLabComplete(scenario.labId, scenario, 0);
          }
          // Notify the caller
          userOnComplete();
          // Clean up nudge engine
          nudgeEngine.disable();
        }
      });

      // Expose nudge engine reference for scaffolding toggle
      this._nudgeRef = nudgeEngine;

      // Return the controller
      return {
        _nudgeRef: nudgeEngine,
        dispatch: function (action) {
          nudgeEngine.resetTimer();
          actionRouter.dispatch(action);
        },
        currentState: function () {
          return stateMachine.current;
        },
        isComplete: function () {
          return stateMachine.isComplete();
        },
        getAvailableActions: function () {
          return stateMachine.getAvailableActions();
        },
        getActionsLog: function () {
          return actionRouter.getActionsLog();
        },
        reset: function () {
          stateMachine.reset();
          nudgeEngine.destroy();
          nudgeEngine.init({
            nudges: scenario.nudges || {},
            userLevel: scenario.userLevel || 1,
            container: scenario.nudgeContainer || null,
            getCurrentState: function () {
              return stateMachine.current;
            }
          });
        },
        destroy: function () {
          nudgeEngine.destroy();
        }
      };
    }
  };
})();
