// Observer for the boring-but-informative surface: file opens, process spawns,
// Java file/process APIs. Answers "what does this app actually touch".
// @tags: observe, io, java
//
// Envelope: every event is send({tag, ...}) -- the host stores tag counts, so a
// hook that is loaded but silent is itself a finding.

'use strict';

const MAX_EVENTS = 500;
let emitted = 0;

function emit(tag, payload) {
  if (emitted >= MAX_EVENTS) {
    if (emitted === MAX_EVENTS) {
      emitted++;
      send({ tag: 'budget-exhausted', limit: MAX_EVENTS });
    }
    return;
  }
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
    return pointer.isNull() ? '' : pointer.readUtf8String(512);
  } catch (e) {
    return '';
  }
}

['open', 'openat'].forEach(function (name) {
  const address = findExport(name);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter: function (args) {
      const path = name === 'open' ? readCString(args[0]) : readCString(args[1]);
      this.path = path;
    },
    onLeave: function (retval) {
      const fd = retval.toInt32();
      if (fd >= 0 && this.path) emit('open', { api: name, path: this.path, fd: fd });
    }
  });
});

(function hookExec() {
  const execve = findExport('execve');
  if (execve) {
    Interceptor.attach(execve, {
      onEnter: function (args) {
        emit('execve', { path: readCString(args[0]) });
      }
    });
  }
  const system = findExport('system');
  if (system) {
    Interceptor.attach(system, {
      onEnter: function (args) {
        emit('system', { command: readCString(args[0]) });
      }
    });
  }
})();

if (Java.available) {
  Java.perform(function () {
    function wrap(className, methods, tag) {
      let clazz = null;
      try {
        clazz = Java.use(className);
      } catch (e) {
        emit('class-missing', { className: className, error: String(e) });
        return;
      }
      methods.forEach(function (signature) {
        try {
          clazz[signature].implementation = function () {
            emit(tag, {
              className: className,
              method: signature,
              arguments: Array.prototype.slice.call(arguments).map(function (value) {
                try { return String(value); } catch (e) { return '<unprintable>'; }
              }).slice(0, 4)
            });
            return clazz[signature].apply(this, arguments);
          };
        } catch (e) { /* overload absent in this build */ }
      });
    }

    wrap('java.lang.Runtime', ['exec'], 'runtime-exec');
    wrap('java.lang.ProcessBuilder', ['start'], 'process-builder');
    wrap('java.io.FileOutputStream', ['<init>'], 'file-output');
    wrap('java.util.zip.ZipFile', ['<init>'], 'zip-open');
  });
}
