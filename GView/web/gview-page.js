// GView web build - page logic (loaded by GView.html; kept out of the HTML so the Content-Security-Policy of the page
// can forbid inline scripts).
//   * starts the persistent storage (gview-storage.js) before GView, which restores the files of the previous visits
//   * starts GView (GView.mjs) on the AppCUI canvas host (appcui-host.js)
//   * gives the files dropped on the page / picked with "Open files..." to GView and keeps them in the storage
//   * tells GView when the page is hidden (Learning and Evaluation Mode sends its pending telemetry)

import createGViewModule from './GView.mjs';
import { startAppCUI } from './appcui-host.js';
import { GViewStorage } from './gview-storage.js';

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
