// GView web build - page side of the persistent storage (see gview-storage-worker.js for the format and
// GViewCore/src/App/BrowserStorage.cpp for what is kept).
//
// globalThis.gviewStorage is used by the WebAssembly module (EM_JS functions of BrowserStorage.cpp):
//   ready                      promise, resolved once the index and the secrets are loaded (never rejects)
//   available                  false: no persistent storage (private window, blocked site data, no OPFS)
//   entries                    Map path -> { path, size, mtime, storedAt, origin, materialized }
//   secrets                    Map name -> string (decrypted, kept in the memory of the page only)
//   restore(FS, home, budget)  copies the newest stored files into the in-memory file system (up to budget bytes)
//   materialize(FS, home, p)   copies one stored file into the in-memory file system
//   put / putBlob / remove / setSecret / removeSecret / clear   (asynchronous, fire and forget for the module)
// The paths are relative to GView's home folder (they never contain "..": built by the C++ side).

const SEP = '/';

export class GViewStorage {
  constructor(onStatus) {
    this.onStatus = onStatus || (() => {});
    this.available = false;
    this.persisted = false;
    this.full = false;
    this.error = '';
    this.entries = new Map();
    this.secrets = new Map();
    this.pending = new Map();
    this.nextId = 1;
    this.queue = Promise.resolve(); // writes are applied in order
    this.stats = { readyMs: 0, restoredFiles: 0, restoredBytes: 0, restoreMs: 0 }; // diagnostics (boot cost)
    const t0 = performance.now();
    this.ready = this.start().then(() => { this.stats.readyMs = Math.round(performance.now() - t0); });
  }

  async start() {
    try {
      if (!globalThis.isSecureContext) throw new Error('the page is not a secure context (use https:// or localhost)');
      if (!navigator.storage || !navigator.storage.getDirectory) throw new Error('the browser has no Origin Private File System');
      this.worker = new Worker(new URL('./gview-storage-worker.js', import.meta.url));
      this.worker.onmessage = (event) => this.onMessage(event.data);
      this.worker.onerror = (event) => { this.fail('storage worker error: ' + (event.message || 'unknown')); };
      const r = await this.call('init');
      for (const e of r.entries) this.entries.set(e.path, Object.assign(e, { materialized: false }));
      for (const [name, value] of Object.entries(r.secrets)) this.secrets.set(name, value);
      this.persisted = !!r.persisted;
      this.available = true;
      this.updateEstimate();
      if (typeof BroadcastChannel === 'function') {
        // another tab stored / removed files: refresh the list shown by "Stored files"
        this.channel = new BroadcastChannel('gview-storage');
        this.channel.onmessage = () => this.refreshEntries();
      }
    } catch (e) {
      this.fail(String((e && e.message) || e));
    }
  }

  fail(message) {
    this.available = false;
    this.error = message;
    this.onStatus('Files are kept in this tab only: ' + message);
  }

  onMessage(msg) {
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    if (msg.ok) p.resolve(msg.result);
    else {
      const err = new Error(msg.error);
      err.quota = !!msg.quota;
      p.reject(err);
    }
  }

  call(op, args = {}, transfer = []) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage(Object.assign({ id, op }, args), transfer);
    });
  }

  // serialized write, errors reported in the status bar (never thrown at the module)
  enqueue(label, fn) {
    this.queue = this.queue.then(fn).then(() => this.updateEstimate()).catch((e) => {
      if (e && e.quota) {
        this.full = true;
        this.onStatus('Browser storage is full: new files are no longer kept (File > Stored files to free space).');
      } else {
        this.onStatus(label + ' failed: ' + ((e && e.message) || e));
      }
    });
    return this.queue;
  }

  async requestPersistence() {
    // "persistent" storage is not evicted under storage pressure (granted by heuristics or after a prompt)
    if (this.persisted || this.persistAsked || !navigator.storage.persist) return;
    this.persistAsked = true;
    try { this.persisted = await navigator.storage.persist(); } catch (e) { /* not granted */ }
  }

  async refreshEntries() {
    if (!this.available) return;
    try {
      const list = await this.call('entries');
      const next = new Map();
      for (const e of list) {
        const old = this.entries.get(e.path);
        next.set(e.path, Object.assign(e, { materialized: !!(old && old.materialized) }));
      }
      this.entries = next;
    } catch (e) { /* keep the previous list */ }
  }

  static parentOf(path) {
    const i = path.lastIndexOf(SEP);
    return i > 0 ? path.slice(0, i) : '';
  }

  async writeToFS(FS, home, path, data, mtime) {
    const abs = home + SEP + path;
    const dir = GViewStorage.parentOf(abs);
    if (dir) FS.mkdirTree(dir);
    FS.writeFile(abs, data);
    FS.utime(abs, mtime, mtime); // the module compares (size, mtime) with the index: keep the stored one
  }

  // newest first, until `budget` bytes are copied; returns the number of files copied
  async restore(FS, home, budget) {
    await this.ready;
    if (!this.available) return 0;
    const t0 = performance.now();
    const list = [...this.entries.values()].sort((a, b) => b.storedAt - a.storedAt);
    let used = 0;
    let count = 0;
    for (const e of list) {
      if (used + e.size > budget) continue;
      try {
        const { data, mtime } = await this.call('read', { path: e.path });
        await this.writeToFS(FS, home, e.path, data, mtime);
        e.materialized = true;
        used += e.size;
        count++;
      } catch (err) {
        this.onStatus('A stored file could not be restored (' + e.path + '): ' + ((err && err.message) || err));
      }
    }
    this.stats.restoredFiles = count;
    this.stats.restoredBytes = used;
    this.stats.restoreMs = Math.round(performance.now() - t0);
    return count;
  }

  async materialize(FS, home, path) {
    await this.ready;
    const e = this.entries.get(path);
    if (!this.available || !e) return false;
    try {
      const { data, mtime } = await this.call('read', { path });
      await this.writeToFS(FS, home, path, data, mtime);
      e.materialized = true;
      return true;
    } catch (err) {
      this.onStatus('Unable to load ' + path + ': ' + ((err && err.message) || err));
      return false;
    }
  }

  // data: Uint8Array owned by the caller from now on (transferred to the worker)
  put(path, data, mtime, origin) {
    if (!this.available || this.full) return false;
    this.entries.set(path, { path, size: data.length, mtime, storedAt: Date.now(), origin, materialized: true });
    this.enqueue('Keeping ' + path, async () => {
      const r = await this.call('put', { path, data, mtime, origin }, [data.buffer]);
      this.entries.set(path, Object.assign(r, { materialized: true }));
      this.requestPersistence();
    });
    return true;
  }

  // file: the File given by the user (drag & drop / file picker) - streamed by the worker, no copy here
  putBlob(path, blob, mtime, origin) {
    if (!this.available || this.full) return false;
    this.entries.set(path, { path, size: blob.size, mtime, storedAt: Date.now(), origin, materialized: true });
    this.enqueue('Keeping ' + path, async () => {
      const r = await this.call('putBlob', { path, blob, mtime, origin });
      this.entries.set(path, Object.assign(r, { materialized: true }));
      this.requestPersistence();
    });
    return true;
  }

  remove(path) {
    if (!this.available) return;
    this.entries.delete(path);
    this.enqueue('Removing ' + path, () => this.call('remove', { path }));
  }

  clear() {
    if (!this.available) return;
    this.entries.clear();
    this.full = false;
    this.enqueue('Clearing the stored files', () => this.call('clear'));
  }

  setSecret(name, value) {
    this.secrets.set(name, value);
    if (this.available) this.enqueue('Keeping a secret', () => this.call('setSecret', { name, value }));
  }

  removeSecret(name) {
    this.secrets.delete(name);
    if (this.available) this.enqueue('Forgetting a secret', () => this.call('removeSecret', { name }));
  }

  // usage / quota of the origin, shown by File > Stored files (refreshed after every write)
  async updateEstimate() {
    try {
      if (!navigator.storage.estimate) return;
      const est = await navigator.storage.estimate();
      this.usage = est.usage || 0;
      this.quota = est.quota || 0;
    } catch (e) { /* unknown */ }
  }
}
