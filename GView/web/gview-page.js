// GView web build - page logic (loaded by GView.html; kept out of the HTML so the Content-Security-Policy of the page
// can forbid inline scripts).
//   * starts the persistent storage (gview-storage.js) before GView, which restores the files of the previous visits
//   * starts GView (GView.mjs) on the AppCUI canvas host (appcui-host.js)
//   * gives the files dropped on the page / picked with "Open files..." to GView and keeps them in the storage
//   * tells GView when the page is hidden (Learning and Evaluation Mode sends its pending telemetry)
//   * one-click launch of Learning and Evaluation Mode (<page>#launch=<code>&server=<url>): redeems the one-time code
//     while GView.wasm downloads, and gives the connection string to GView (GViewCore/src/App/BrowserLaunch.cpp)

import createGViewModule from './GView.mjs';
import { startAppCUI } from './appcui-host.js';
import { GViewStorage } from './gview-storage.js';

// ------------------------------------------------------------------------------------------------ launch link
// The course page sends the student here with a one-time code in the fragment (never sent to the web server). The code
// is exchanged for the connection string at POST <server>/GView/WebLaunch; the connection string itself never appears
// in a URL. Neither is ever written to the console, the status bar, localStorage or sessionStorage.
//
// globalThis.gviewLaunch is read by the module (BrowserLaunch.cpp), which polls it on its frames:
//   state             'none' (no launch link) | 'pending' | 'ok' | 'error' | 'taken' (the module has the result)
//   serverOrigin      origin of the validated `server` parameter (the server the code is redeemed at)
//   connectionString  only while state === 'ok'; emptied when the module takes it
//   error             human readable, only when state === 'error'
//   done              promise, resolved when the state leaves 'pending' (never rejects)
const LAUNCH_CODE = /^[A-Za-z0-9_-]{32,64}$/;
const LAUNCH_TIMEOUT_MS = 30000;
const LAUNCH_AGAIN = ' Open GView again from the course page.';

function isLoopbackHost(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
}

function pageIsServedLocally() {
  // same rule as PageIsServedLocally (GViewCore/src/Security/Learning/LearningHttpFetch.cpp)
  const h = String(location.hostname || '').toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1' || h.endsWith('.localhost');
}

// the `server` parameter: absolute https URL (plain http only to the loopback, from a page served locally), no user
// info, no query, no fragment; returns the URL of the WebLaunch endpoint, or null
function launchEndpoint(server) {
  if (typeof server !== 'string' || server.length === 0 || server.length > 2048) return null;
  if (!/^[\x21-\x7E]+$/.test(server) || /[?#@]/.test(server)) return null;
  let url;
  try { url = new URL(server); } catch (e) { return null; }
  if (url.username || url.password || url.search || url.hash) return null;
  if (url.protocol === 'http:') {
    if (!isLoopbackHost(url.hostname) || !pageIsServedLocally()) return null;
  } else if (url.protocol !== 'https:') {
    return null;
  }
  if (!/^[A-Za-z0-9\/._~-]*$/.test(url.pathname)) return null;
  return { origin: url.origin, endpoint: url.origin + url.pathname.replace(/\/+$/, '') + '/GView/WebLaunch' };
}

// text shown by GView (the 403 message comes from the server): printable ASCII, no '&' (a hotkey marker for AppCUI
// labels), bounded
function displayText(value, max) {
  if (typeof value !== 'string') return '';
  return value.replace(/[^\x20-\x7E]+/g, ' ').replace(/&/g, '+').trim().slice(0, max);
}

async function redeemLaunchCode(launch, endpoint, code) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), LAUNCH_TIMEOUT_MS);
  const versionMeta = document.querySelector('meta[name="gview-version"]');
  try {
    // single use: never retried, whatever happens (a lost answer may already have consumed the code)
    const resp = await fetch(endpoint, {
      method: 'POST', mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error',
      referrerPolicy: 'no-referrer', signal: ctl.signal,
      headers: {
        'Content-Type': 'application/json', 'Accept': 'application/json', 'X-GView-Protocol': '2',
        'X-GView-Client': (versionMeta && versionMeta.content) || 'unknown', 'X-GView-Platform': 'web-wasm32',
      },
      body: JSON.stringify({ code }),
    });
    let body = null;
    try { body = await resp.json(); } catch (e) { /* not JSON */ }
    if (resp.status === 200 && body && body.status === 'ok' && typeof body.connectionString === 'string' &&
        body.connectionString.length > 0 && body.connectionString.length <= 16384) {
      launch.connectionString = body.connectionString;
      launch.state = 'ok';
      return;
    }
    const details = displayText(body && body.details, 160);
    if (resp.status === 401) {
      launch.error = 'This launch link has expired or was already used.' + LAUNCH_AGAIN;
    } else if (resp.status === 403) {
      launch.error = (details || 'This GView page is not allowed by the course server.') + LAUNCH_AGAIN;
    } else if (resp.status === 426) {
      launch.error = 'The course server requires a newer GView version. Reload the page, then open GView again from' +
                     ' the course page.';
    } else if (resp.status === 429) {
      const wait = Number(resp.headers.get('Retry-After'));
      launch.error = 'Too many attempts' + (wait > 0 && wait < 86400 ? ', wait ' + Math.ceil(wait) + ' s' : '') +
                     '. Then open GView again from the course page.';
    } else if (resp.status === 200) {
      launch.error = 'The course server sent an invalid answer.' + LAUNCH_AGAIN;
    } else {
      launch.error = 'The course server could not open this launch link (HTTP ' + resp.status + ').' + LAUNCH_AGAIN;
    }
    launch.state = 'error';
  } catch (e) {
    launch.error = 'The course server could not be reached (network error or timeout).' + LAUNCH_AGAIN;
    launch.state = 'error';
  } finally {
    clearTimeout(timer);
  }
}

function startLaunch() {
  const launch = { state: 'none', serverOrigin: '', connectionString: '', error: '', done: Promise.resolve() };
  let params;
  try { params = new URLSearchParams(location.hash.slice(1)); } catch (e) { return launch; }
  if (!params.has('launch')) return launch;
  // first, whatever the values: a reload, a bookmark or the history never carry the code
  try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { /* sandboxed */ }
  const code = params.get('launch') || '';
  const target = launchEndpoint(params.get('server'));
  if (!LAUNCH_CODE.test(code) || target === null) {
    launch.state = 'error';
    launch.error = 'This launch link is invalid.' + LAUNCH_AGAIN;
    return launch;
  }
  launch.state = 'pending';
  launch.serverOrigin = target.origin;
  // started now, while GView.wasm downloads: the code expires a few minutes after the click on the course page
  launch.done = redeemLaunchCode(launch, target.endpoint, code).then(() => {
    if (window.appcuiHost) window.appcuiHost.wake(); // GView picks the result up on its next frame
  });
  return launch;
}

globalThis.gviewLaunch = startLaunch();
// a launch link opened in a tab where GView already runs only changes the fragment (no new page load): it is not
// redeemed (GView is already started), but the code is removed from the address bar and the history all the same
window.addEventListener('hashchange', () => {
  try {
    if (new URLSearchParams(location.hash.slice(1)).has('launch'))
      history.replaceState(null, '', location.pathname + location.search);
  } catch (e) { /* sandboxed */ }
});

// ------------------------------------------------------------------------------------------------ GView
const canvas = document.getElementById('term');
const status = document.getElementById('status');
const setStatus = (text) => { status.textContent = text; };

setStatus('Starting GView...');
// must exist before the module starts: GView waits for it to restore the files of the previous visits
globalThis.gviewStorage = new GViewStorage(setStatus);

const host = await startAppCUI(createGViewModule, canvas, document.getElementById('term-host'),
                               { fontFamily: '"JuliaMono", monospace', fontSizeCss: 16 });
window.appcuiHost = host; // diagnostics / automation

await globalThis.gviewStorage.ready;
setStatus(globalThis.gviewStorage.available
  ? 'Drop files anywhere on the page. Files under the home folder are kept in this browser (File > Stored files).'
  : 'Drop files anywhere on the page. They stay in this tab only: ' + globalThis.gviewStorage.error);

function readCString(mod, ptr) {
  const heap = mod.HEAPU8; // re-read: replaced when the memory grows
  let end = ptr;
  while (heap[end] !== 0) end++;
  return new TextDecoder().decode(heap.subarray(ptr, end));
}

// Copies a File into GView's in-memory file system (GViewCore/src/App/BrowserHost.cpp); GView opens it on its next
// frame. Buffers are allocated by GView and released by gview_browser_add_file.
async function addFile(file) {
  const mod = host.mod;
  if (!mod || host.exited) return false;
  const data = new Uint8Array(await file.arrayBuffer());
  const name = new TextEncoder().encode(file.name);
  const namePtr = mod._gview_browser_alloc(name.length) >>> 0;
  const dataPtr = data.length ? (mod._gview_browser_alloc(data.length) >>> 0) : 0;
  if (namePtr === 0 || (data.length && dataPtr === 0)) {
    mod._gview_browser_add_file(namePtr, 0, dataPtr, 0); // rejected, but releases whatever was allocated
    return false;
  }
  mod.HEAPU8.set(name, namePtr); // HEAPU8 is re-read after the allocations (memory may have grown)
  if (data.length) mod.HEAPU8.set(data, dataPtr);
  if (mod._gview_browser_add_file(namePtr, name.length, dataPtr, data.length) !== 1) return false;
  // "<path under the home folder>\n<mtime>": the storage worker keeps the File itself (streamed, no extra copy)
  const stored = readCString(mod, mod._gview_browser_last_stored() >>> 0).split('\n');
  if (stored.length === 2 && stored[0]) globalThis.gviewStorage.putBlob(stored[0], file, Number(stored[1]), 'upload');
  return true;
}

async function addFiles(files) {
  let ok = 0, failed = 0;
  for (const file of files) (await addFile(file)) ? ok++ : failed++;
  const kept = globalThis.gviewStorage.available && !globalThis.gviewStorage.full;
  setStatus(`${ok} file(s) opened` + (failed ? `, ${failed} failed (too large or invalid name)` : '') +
            (kept ? ' - kept in this browser (File > Stored files).' : ' - kept in this tab only.'));
  host.wake();
  canvas.focus();
}

const picker = document.getElementById('picker');
document.getElementById('open').addEventListener('click', () => picker.click());
picker.addEventListener('change', () => { addFiles([...picker.files]); picker.value = ''; });

let dragDepth = 0;
window.addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; document.body.classList.add('dragging'); });
window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; document.body.classList.remove('dragging'); } });
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  document.body.classList.remove('dragging');
  if (e.dataTransfer && e.dataTransfer.files.length) addFiles([...e.dataTransfer.files]);
});

// hidden page (tab switch, minimize, close): GView flushes the Learning telemetry on its next frame
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && host.mod && !host.exited) {
    host.mod._gview_browser_page_hidden();
    host.wake();
  }
});
