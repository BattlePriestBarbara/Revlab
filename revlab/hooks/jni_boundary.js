// Recovers the JNI surface that static analysis cannot see: every
// RegisterNatives call (Java name -> native pointer), plus the moment each
// native library is loaded.
// @tags: jni, natives
//
// Why this hook matters: when a library exports only JNI_OnLoad and binds its
// methods at runtime, the static symbol table has no Java_* entry point at all.
// This hook prints the mapping the app builds for itself.

'use strict';

const MAX_BINDINGS = 300;
let bindings = 0;
let announced = false;

function emit(tag, payload) {
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

function whereIs(address) {
  try {
    const symbol = DebugSymbol.fromAddress(address);
    return symbol && symbol.name ? symbol.toString() : String(address);
  } catch (e) {
    return String(address);
  }
}

// libart exposes RegisterNatives as a C++ method; the name is stable per ABI.
const REGISTER_NATIVE_SYMBOLS = [
  '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
  'RegisterNatives'
];

(function hookRegisterNatives() {
  let address = null;
  for (let i = 0; i < REGISTER_NATIVE_SYMBOLS.length && !address; i++) {
    address = findExport(REGISTER_NATIVE_SYMBOLS[i]);
  }
  if (!address) {
    emit('hook-missing', { symbol: 'RegisterNatives', hint: 'libart layout differs on this device' });
    return;
  }
  emit('hook-installed', { symbol: 'RegisterNatives', address: String(address) });
  Interceptor.attach(address, {
    onEnter: function (args) {
      if (bindings >= MAX_BINDINGS) return;
      const count = args[3].toInt32();
      const methods = args[2];
      if (count <= 0 || count > 512 || methods.isNull()) return;
      const entries = [];
      for (let index = 0; index < count && bindings < MAX_BINDINGS; index++) {
        const entry = methods.add(index * Process.pointerSize * 3);
        const namePointer = entry.readPointer();
        const signaturePointer = entry.add(Process.pointerSize).readPointer();
        const functionPointer = entry.add(Process.pointerSize * 2).readPointer();
        entries.push({
          name: readCString(namePointer),
          signature: readCString(signaturePointer),
          native: whereIs(functionPointer)
        });
        bindings++;
      }
      emit('register-natives', { count: count, methods: entries });
    }
  });
})();

// Library loading: answers "which module holds this binding".
['dlopen', 'android_dlopen_ext'].forEach(function (name) {
  const address = findExport(name);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter: function (args) {
      this.path = readCString(args[0]);
    },
    onLeave: function (retval) {
      if (!retval.isNull() && this.path) {
        emit('library-loaded', { api: name, path: this.path, handle: String(retval) });
      }
    }
  });
});

if (Java.available) {
  Java.perform(function () {
    try {
      const system = Java.use('java.lang.System');
      ['loadLibrary', 'load'].forEach(function (method) {
        system[method].implementation = function (value) {
          emit('java-library-load', { method: method, value: String(value) });
          return system[method].apply(this, arguments);
        };
      });
    } catch (e) { /* nothing to hook */ }

    if (!announced) {
      announced = true;
      try {
        const application = Java.use('android.app.ActivityThread');
        emit('java-ready', { apiLevel: Java.androidVersion });
      } catch (e) { /* fine */ }
    }
  });
}
