'use strict';

// Regex compilation and execution stay off the page's main thread.
// The caller terminates this worker when a sample exceeds its time budget.
var re;
self.onmessage = function (event) {
  var data = event.data;
  if (data.type === 'init') {
    try {
      re = new RegExp(data.pattern, data.flags);
      self.postMessage({ type: 'ready' });
    } catch (error) {
      self.postMessage({ type: 'syntax-error', message: error.message });
    }
    return;
  }
  if (data.type === 'sample') {
    try {
      re.lastIndex = 0;
      var start = performance.now();
      var matched = re.test(data.input);
      self.postMessage({ type: 'sample', duration: performance.now() - start, matched: matched });
    } catch (error) {
      self.postMessage({ type: 'error', message: error.message });
    }
  }
};
