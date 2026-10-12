// GView web build - storage worker (a plain dedicated Worker: no WebAssembly, no SharedArrayBuffer).
//
// Keeps the files of GView's home folder across visits (GViewCore/src/App/BrowserStorage.cpp decides what to keep;
// gview-storage.js is the page side of this worker):
//   * content : Origin Private File System, one file per stored version: gview/v1/blobs/<uuid>
//   * index   : IndexedDB "gview-storage" -> store "files" { path, blobId, size, mtime, storedAt, origin }
//   * key     : IndexedDB "gview-storage" -> store "keys"  (non-extractable AES-GCM-256 CryptoKey)
//   * secrets : IndexedDB "gview-storage" -> store "secrets" { name, iv, ct } (e.g. the Learning connection string)
//
// Every blob is encrypted in 1 MiB chunks with AES-256-GCM:
//   blob  = "GVS1" || prefix(8) || chunk_0 || chunk_1 || ...      chunk_i = AES-GCM(plain_i) || tag(16)
//   nonce = prefix(8) || uint32_be(i)                               aad     = utf8(blobId) || 0 || uint32_be(i) || last
// Why: GView stores live malware samples. Written in clear into the browser profile, they get quarantined by the
// antivirus of the machine (corrupting the store); encryption also keeps the stored files and secrets unreadable to
// anything that reads the profile from disk. It is NOT a protection against scripts running on the same web origin
// (they could use the key): host GView on an origin of its own.
//
// Writes use OPFS sync access handles (only available in workers) and are serialized across tabs with a Web Lock; the
// other tabs are told about changes through a BroadcastChannel. Requests: { id, op, ... } -> { id, ok, result | error }.
'use strict';

const DB_NAME = 'gview-storage';
const DB_VERSION = 1;
const CHUNK = 1024 * 1024;
const TAG = 16;
const HEADER = 12;
const MAGIC = [0x47, 0x56, 0x53, 0x31]; // "GVS1"
const LOCK = 'gview-storage';
const channel = (typeof BroadcastChannel === 'function') ? new BroadcastChannel('gview-storage') : null;

let db = null;
let key = null;
let blobs = null;

const idb = (req) => new Promise((resolve, reject) => {
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});
const store = (name, mode) => db.transaction(name, mode).objectStore(name);
const withLock = (fn) => (navigator.locks && navigator.locks.request) ? navigator.locks.request(LOCK, fn) : fn();
const utf8 = new TextEncoder();
const utf8d = new TextDecoder();

function nonce(prefix, index) {
  const n = new Uint8Array(12);
  n.set(prefix, 0);
  new DataView(n.buffer).setUint32(8, index >>> 0, false);
  return n;
}

function aad(blobId, index, last) {
  const id = utf8.encode(blobId);
  const a = new Uint8Array(id.length + 6);
  a.set(id, 0);
  const v = new DataView(a.buffer);
  v.setUint8(id.length, 0);
  v.setUint32(id.length + 1, index >>> 0, false);
  v.setUint8(id.length + 5, last ? 1 : 0);
  return a;
}

async function openDb() {
  const req = indexedDB.open(DB_NAME, DB_VERSION);
  req.onupgradeneeded = () => {
    const d = req.result;
    if (!d.objectStoreNames.contains('files')) d.createObjectStore('files', { keyPath: 'path' });
    if (!d.objectStoreNames.contains('keys')) d.createObjectStore('keys');
    if (!d.objectStoreNames.contains('secrets')) d.createObjectStore('secrets', { keyPath: 'name' });
  };
  return idb(req);
}

async function loadKey() {
  // under the lock: two tabs opened at the same time must end up with the same key
  return withLock(async () => {
    let k = await idb(store('keys', 'readonly').get('master'));
    if (!k) {
      k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      await idb(store('keys', 'readwrite').put(k, 'master'));
    }
    return k;
  });
}

async function init() {
  if (!navigator.storage || !navigator.storage.getDirectory) throw new Error('the Origin Private File System is not available');
  db = await openDb();
  key = await loadKey();
  const root = await navigator.storage.getDirectory();
  const gview = await root.getDirectoryHandle('gview', { create: true });
  const v1 = await gview.getDirectoryHandle('v1', { create: true });
  blobs = await v1.getDirectoryHandle('blobs', { create: true });
  const all = await idb(store('files', 'readonly').getAll());
  await removeOrphans(new Set(all.map((e) => e.blobId)));
  const entries = all.map((e) => ({ path: e.path, size: e.size, mtime: e.mtime, storedAt: e.storedAt, origin: e.origin }));
  const secrets = {};
  for (const s of await idb(store('secrets', 'readonly').getAll())) {
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: s.iv, additionalData: utf8.encode('secret\0' + s.name) }, key, s.ct);
      secrets[s.name] = utf8d.decode(plain);
    } catch (e) {
      // unreadable (key replaced by clearing part of the site data): forget it
      await idb(store('secrets', 'readwrite').delete(s.name));
    }
  }
  const persisted = (navigator.storage.persisted) ? await navigator.storage.persisted() : false;
  return { entries, secrets, persisted };
}

// readChunk(i) -> Uint8Array (CHUNK bytes, the last one shorter)
async function writeBlob(size, readChunk) {
  const blobId = crypto.randomUUID();
  const prefix = crypto.getRandomValues(new Uint8Array(8));
  const handle = await blobs.getFileHandle(blobId, { create: true });
  const access = await handle.createSyncAccessHandle();
  try {
    access.truncate(0);
    const header = new Uint8Array(HEADER);
    header.set(MAGIC, 0);
    header.set(prefix, 4);
    access.write(header, { at: 0 });
    let at = HEADER;
    const count = Math.max(1, Math.ceil(size / CHUNK));
    for (let i = 0; i < count; i++) {
      const plain = await readChunk(i);
      const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce(prefix, i), additionalData: aad(blobId, i, i === count - 1) }, key, plain));
      plain.fill(0);
      if (access.write(ct, { at }) !== ct.length) throw new Error('short write');
      at += ct.length;
    }
    access.flush();
  } catch (e) {
    try { access.close(); } catch (e2) { /* already closed */ }
    try { await blobs.removeEntry(blobId); } catch (e3) { /* nothing written */ }
    throw e;
  }
  access.close();
  return blobId;
}

// a write interrupted by the end of the page (blob written, index not updated yet) leaves an unreferenced blob behind
async function removeOrphans(referenced) {
  await withLock(async () => {
    const names = [];
    for await (const name of blobs.keys()) names.push(name);
    for (const name of names) if (!referenced.has(name)) await removeBlob(name);
  });
}

async function removeBlob(blobId) {
  try { await blobs.removeEntry(blobId); } catch (e) { /* already gone */ }
}

async function readBlob(entry) {
  const file = await (await blobs.getFileHandle(entry.blobId)).getFile();
  const header = new Uint8Array(await file.slice(0, HEADER).arrayBuffer());
  for (let i = 0; i < 4; i++) if (header[i] !== MAGIC[i]) throw new Error('not a GView storage blob');
  const prefix = header.slice(4, 12);
  const out = new Uint8Array(entry.size);
  const count = Math.max(1, Math.ceil(entry.size / CHUNK));
  let at = HEADER;
  for (let i = 0; i < count; i++) {
    const plainLen = (i === count - 1) ? entry.size - i * CHUNK : CHUNK;
    const ct = await file.slice(at, at + plainLen + TAG).arrayBuffer();
    if (ct.byteLength !== plainLen + TAG) throw new Error('truncated blob');
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce(prefix, i), additionalData: aad(entry.blobId, i, i === count - 1) }, key, ct));
    out.set(plain, i * CHUNK);
    at += plainLen + TAG;
  }
  return out;
}

async function storeEntry(path, size, mtime, origin, readChunk) {
  return withLock(async () => {
    const blobId = await writeBlob(size, readChunk);
    const old = await idb(store('files', 'readonly').get(path));
    const entry = { path, blobId, size, mtime, storedAt: Date.now(), origin };
    await idb(store('files', 'readwrite').put(entry));
    if (old && old.blobId !== blobId) await removeBlob(old.blobId);
    if (channel) channel.postMessage({ type: 'changed', path });
    return { path, size, mtime, storedAt: entry.storedAt, origin };
  });
}

const ops = {
  init,

  async read({ path }) {
    const entry = await idb(store('files', 'readonly').get(path));
    if (!entry) throw new Error('not stored: ' + path);
    const data = await readBlob(entry);
    return { result: { data, mtime: entry.mtime }, transfer: [data.buffer] };
  },

  // data: Uint8Array (transferred)
  async put({ path, data, mtime, origin }) {
    const result = await storeEntry(path, data.length, mtime, origin,
      async (i) => data.slice(i * CHUNK, Math.min(data.length, (i + 1) * CHUNK)));
    data.fill(0);
    return { result };
  },

  // blob: File / Blob given by the page (read chunk by chunk: a multi-GB file never sits in memory)
  async putBlob({ path, blob, mtime, origin }) {
    const result = await storeEntry(path, blob.size, mtime, origin,
      async (i) => new Uint8Array(await blob.slice(i * CHUNK, Math.min(blob.size, (i + 1) * CHUNK)).arrayBuffer()));
    return { result };
  },

  async remove({ path }) {
    return withLock(async () => {
      const old = await idb(store('files', 'readonly').get(path));
      if (old) {
        await idb(store('files', 'readwrite').delete(path));
        await removeBlob(old.blobId);
        if (channel) channel.postMessage({ type: 'changed', path });
      }
      return { result: !!old };
    });
  },

  async setSecret({ name, value }) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8.encode('secret\0' + name) }, key, utf8.encode(value));
    await idb(store('secrets', 'readwrite').put({ name, iv, ct }));
    return { result: true };
  },

  async removeSecret({ name }) {
    await idb(store('secrets', 'readwrite').delete(name));
    return { result: true };
  },

  // forgets every stored file (the key and the secrets are kept)
  async clear() {
    return withLock(async () => {
      for (const e of await idb(store('files', 'readonly').getAll())) await removeBlob(e.blobId);
      await idb(store('files', 'readwrite').clear());
      if (channel) channel.postMessage({ type: 'changed', path: '' });
      return { result: true };
    });
  },

  async entries() {
    const list = (await idb(store('files', 'readonly').getAll()))
      .map((e) => ({ path: e.path, size: e.size, mtime: e.mtime, storedAt: e.storedAt, origin: e.origin }));
    return { result: list };
  },
};

let ready = null;
self.onmessage = async (event) => {
  const { id, op } = event.data || {};
  try {
    if (op === 'init') {
      ready = ready || init();
      self.postMessage({ id, ok: true, result: await ready });
      return;
    }
    if (!ready) throw new Error('storage not initialized');
    await ready;
    const fn = ops[op];
    if (!fn) throw new Error('unknown operation ' + op);
    const { result, transfer } = await fn(event.data);
    self.postMessage({ id, ok: true, result }, transfer || []);
  } catch (e) {
    const quota = e && (e.name === 'QuotaExceededError');
    self.postMessage({ id, ok: false, error: String((e && e.message) || e), quota });
  }
};
