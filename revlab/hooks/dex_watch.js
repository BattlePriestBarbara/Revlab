// Watches for DEX data appearing at runtime: native writes whose buffer starts
// with a DEX magic, plus every Java loader that takes a DEX-like input.
// @tags: unpack, dex, dynamic
//
// Deliberately not a dumping framework: it records *that* a DEX-shaped buffer
// passed a fd (and where the fd pointed), and optionally saves the buffer to the
// device. When nothing is found, that too is evidence: it means the loader path
// used here does not produce a plaintext DEX on this device.

'use strict';

const MAX_HITS = 40;
const MAGICS = ['dex\n035', 'dex\n036', 'dex\n037', 'dex\n038', 'dex\n039', 'dex\n040'];
const DUMP_DIR = '/data/local/tmp';
const MAX_DUMP = 8 * 1024 * 1024;

let hits = 0;
let dumped = 0;

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

function magicAt(pointer) {
  try {
    const head = pointer.readUtf8String(8);
    for (let i = 0; i < MAGICS.length; i++) {
      if (head.indexOf(MAGICS[i]) === 0) return MAGICS[i];
    }
  } catch (e) { /* unreadable buffer */ }
  return null;
}

function describeFd(fd) {
  try {
    const target = '/proc/self/fd/' + fd;
    const file = new File(target, 'r');
    const value = file.readText();
    file.close();
    return value;
  } catch (e) {
    return '';
  }
}

function maybeDump(buffer, size, magic, fd) {
  if (dumped >= 5 || size <= 0 || size > MAX_DUMP) return null;
  dumped++;
  const path = DUMP_DIR + '/revlab-dex-' + Process.id + '-' + dumped + '.dex';
  try {
    const handle = new File(path, 'wb');
    handle.write(buffer.readByteArray(size));
    handle.flush();
    handle.close();
    emit('dex-dumped', { path: path, size: size, magic: magic, fd: fd });
    return path;
  } catch (e) {
    emit('dex-dump-failed', { path: path, error: String(e), size: size });
    return null;
  }
}

['write', 'pwrite', 'writev'].forEach(function (name) {
  const address = findExport(name);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter: function (args) {
      if (hits >= MAX_HITS) return;
      const magic = magicAt(args[1]);
      if (!magic) return;
      hits++;
      const size = args[2].toInt32();
      const fd = args[0].toInt32();
      emit('dex-write', {
        api: name,
        magic: magic,
        size: size,
        fd: fd,
        fdTarget: describeFd(fd)
      });
      maybeDump(args[1], size, magic, fd);
    }
  });
});

['open', 'openat', 'mmap'].forEach(function (name) {
  const address = findExport(name);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter: function (args) {
      if (hits >= MAX_HITS) return;
      let path = '';
      try {
        path = name === 'open' ? args[0].readUtf8String(256)
          : name === 'openat' ? args[1].readUtf8String(256) : '';
      } catch (e) { /* not a path argument */ }
      if (path && (path.indexOf('.dex') !== -1 || path.indexOf('.jar') !== -1 ||
                   path.indexOf('/data/data/') === 0 || path.indexOf('/data/app/') === 0)) {
        hits++;
        emit('dex-path', { api: name, path: path });
      }
    }
  });
});

if (Java.available) {
  Java.perform(function () {
    function watch(className, methods, tag) {
      let clazz = null;
      try {
        clazz = Java.use(className);
      } catch (e) {
        emit('loader-missing', { className: className });
        return;
      }
      methods.forEach(function (method) {
        try {
          clazz[method].implementation = function () {
            const args = Array.prototype.slice.call(arguments);
            emit(tag, {
              className: className,
              method: method,
              firstArg: args.length ? String(args[0]).slice(0, 200) : '',
              argCount: args.length
            });
            return clazz[method].apply(this, arguments);
          };
        } catch (e) { /* overload absent */ }
      });
    }

    watch('dalvik.system.DexClassLoader', ['<init>'], 'java-dex-loader');
    watch('dalvik.system.DexFile', ['<init>', 'loadDex'], 'java-dex-file');
    watch('dalvik.system.InMemoryDexClassLoader', ['<init>'], 'java-dex-inmemory');
    watch('dalvik.system.PathClassLoader', ['<init>'], 'java-path-loader');
  });
}
