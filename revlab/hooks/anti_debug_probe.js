// Detects anti-analysis behaviour: ptrace self-attach, debugger checks,
// /proc/self/* reads, kill/exit calls. The point is to learn *when* the app
// decides it is being watched, not to defeat it.
// @tags: anti-analysis, dynamic
//
// A "hooked, never called" result is a valid finding: it means this particular
// protection is not active on this device/ABI.

'use strict';

const MAX_EVENTS = 400;
let emitted = 0;

function emit(tag, payload) {
  if (emitted >= MAX_EVENTS) return;
  emitted++;
  send(Object.assign({ tag: tag, ts: Date.now() }, payload || {}));
}

function findExport(name) {
  try {
    if (Module.findGlobalExportByName) {
      const found = Module.findGlobalExportByName(name);
      if (found) return found;
    }
  } catch (e) { /* fall through */ }
  try {
    return Module.findExportByName(null, name);
  } catch (e) {
    return null;
  }
}

function readCString(pointer) {
  try {
    return pointer.isNull() ? '' : pointer.readUtf8String(256);
  } catch (e) {
    return '';
  }
}

(function hookPtrace() {
  const address = findExport('ptrace');
  if (!address) {
    emit('hook-missing', { symbol: 'ptrace' });
    return;
  }
  Interceptor.attach(address, {
    onEnter: function (args) {
      const request = args[0].toInt32();
      // PTRACE_TRACEME (0) is how a process marks itself to be traced by a debugger.
      if (request === 0 || request === 0x4200 /* PTRACE_SEIZE on some ABIs */) {
        emit('ptrace', { request: request, pid: args[1].toInt32() });
      } else {
        emit('ptrace-other', { request: request });
      }
    }
  });
})();

['exit', '_exit', 'abort', 'kill'].forEach(function (name) {
  const address = findExport(name);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter: function (args) {
      emit('process-control', {
        symbol: name,
        first: args[0].toInt32(),
        second: args.length > 1 ? args[1].toInt32() : undefined
      });
    }
  });
});

// Reading its own /proc entries is the cheapest self-check an app can do.
['open', 'openat'].forEach(function (name) {
  const address = findExport(name);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter: function (args) {
      const path = name === 'open' ? readCString(args[0]) : readCString(args[1]);
      if (path.indexOf('/proc/self/') === 0 || path.indexOf('frida') !== -1 ||
          path.indexOf('magisk') !== -1 || path.indexOf('supersu') !== -1) {
        emit('self-check', { path: path, api: name });
      }
    }
  });
});

if (Java.available) {
  Java.perform(function () {
    function wrap(className, method, tag) {
      try {
        const clazz = Java.use(className);
        clazz[method].implementation = function () {
          const result = clazz[method].apply(this, arguments);
          emit(tag, { className: className, method: method, result: String(result) });
          return result;
        };
      } catch (e) { /* not present in this build */ }
    }

    wrap('android.os.Debug', 'isDebuggerConnected', 'debugger-check');
    wrap('android.os.Debug', 'waitingForDebugger', 'debugger-check');
    try {
      const system = Java.use('java.lang.System');
      system.exit.implementation = function (code) {
        emit('system-exit', { code: code });
        return system.exit.apply(this, arguments);
      };
    } catch (e) { /* Java not usable */ }
  });
}
