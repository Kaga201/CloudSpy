/**
 * CloudSpy background service worker
 */
import { callGemini } from './gemini-proxy.js';

const STORAGE_KEY = 'cloudspy_state';

function probeMagic(bytes) {
  if (!bytes || bytes.length < 4) return null;
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) return 'exe';
  if (bytes[0] === 0x25 && bytes[1] === 0x50) return 'pdf';
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) return 'zip';
  return null;
}

async function probeFileUrl(url) {
  try {
    const resp = await fetch(url, {
      method: 'GET',
      headers: { Range: 'bytes=0-511' },
      redirect: 'follow'
    });
    if (!resp.ok && resp.status !== 206) return { probed: false };
    const buf = new Uint8Array(await resp.arrayBuffer());
    const actualType = probeMagic(buf);
    const ct = resp.headers.get('content-type') || '';
    return { probed: true, actualType, contentType: ct, size: resp.headers.get('content-length') };
  } catch {
    return { probed: false };
  }
}

async function deepScanFiles(files) {
  const results = [];
  for (const f of files.slice(0, 15)) {
    const probe = f.href ? await probeFileUrl(f.href) : { probed: false };
    let magicMismatch = null;
    if (probe.probed && probe.actualType) {
      const claimed = (f.ext || '').toLowerCase();
      if (claimed === 'pdf' && probe.actualType === 'exe') magicMismatch = 'PDF extension but executable content (MZ header)';
      if (claimed === 'doc' && probe.actualType === 'exe') magicMismatch = 'Document extension but executable content';
      if (['jpg', 'png'].includes(claimed) && probe.actualType === 'exe') magicMismatch = 'Image extension but executable content';
    }
    results.push({ ...f, ...probe, magicMismatch });
  }
  return results;
}

function updateBadge(scan) {
  const pageCount = scan?.findings?.length || 0;
  const fileCount = scan?.pageFiles?.length || 0;
  const count = pageCount + (fileCount > 0 ? 1 : 0);
  chrome.action.setBadgeText({ text: count > 0 ? String(Math.min(count, 99)) : '' });
  chrome.action.setBadgeBackgroundColor({ color: count > 3 ? '#f1495f' : count > 0 ? '#f5a524' : '#34d399' });
}

async function saveScan(scan) {
  const data = await chrome.storage.local.get(STORAGE_KEY);
  const state = data[STORAGE_KEY] || { scans: {}, latestScan: null, history: [] };

  if (scan.pageFiles?.length) {
    scan.pageFiles = await deepScanFiles(scan.pageFiles);
  }

  scan.totalFileSize = scan.pageFiles.reduce((sum, f) => sum + (parseInt(f.size) || 0), 0);
  scan.filesProbed = scan.pageFiles.filter(f => f.probed).length;

  state.latestScan = scan;
  state.scans[scan.hostname] = scan;
  state.history.unshift({ url: scan.url, hostname: scan.hostname, findings: scan.findings.length, files: scan.pageFiles?.length || 0, at: scan.scannedAt });
  state.history = state.history.slice(0, 30);
  await chrome.storage.local.set({ [STORAGE_KEY]: state });
  updateBadge(scan);
  return state;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'PAGE_SCAN') {
    saveScan(msg.payload).then(state => sendResponse({ ok: true, state }));
    return true;
  }

  if (msg.type === 'GET_STATE') {
    chrome.storage.local.get(STORAGE_KEY).then(data => {
      sendResponse(data[STORAGE_KEY] || { scans: {}, latestScan: null, history: [] });
    });
    return true;
  }

  if (msg.type === 'DEEP_SCAN_FILES') {
    deepScanFiles(msg.files || []).then(results => sendResponse({ ok: true, results }));
    return true;
  }

  if (msg.type === 'SCAN_ACTIVE_TAB') {
    chrome.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
      if (!tab?.id || tab.url?.startsWith('chrome://') || tab.url?.startsWith('chrome-extension://')) {
        sendResponse({ ok: false, error: 'Cannot scan this page type' });
        return;
      }
      try {
        const resp = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_SCAN' });
        sendResponse(resp || { ok: true });
      } catch (firstErr) {
        try {
          await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content/page-scanner.js'] });
          const resp = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_SCAN' });
          sendResponse(resp || { ok: true });
        } catch (err) {
          sendResponse({ ok: false, error: err.message || firstErr.message || 'Scan failed' });
        }
      }
    });
    return true;
  }

  if (msg.type === 'OPEN_DASHBOARD') {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'GEMINI_GENERATE') {
    callGemini(msg.payload)
      .then(text => sendResponse({ ok: true, text }))
      .catch(err => sendResponse({ ok: false, status: 0, error: err.message || 'Backend request failed' }));
    return true;
  }

  if (msg.type === 'BACKEND_FETCH') {
    const { url, method = 'GET', body, token } = msg.payload;
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined })
      .then(async r => {
        const data = await r.json().catch(() => ({}));
        sendResponse({ ok: r.ok, status: r.status, data });
      })
      .catch(err => sendResponse({ ok: false, status: 0, error: err.message || 'Backend request failed' }));
    return true;
  }
});

chrome.tabs.onActivated.addListener(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || tab.url.startsWith('chrome')) return;
  try {
    const data = await chrome.storage.local.get(STORAGE_KEY);
    const scan = data[STORAGE_KEY]?.scans?.[new URL(tab.url).hostname];
    if (scan) updateBadge(scan);
  } catch { /* ignore */ }
});

chrome.alarms.create('heartbeat', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'heartbeat') {
    chrome.storage.local.get(STORAGE_KEY).then(data => {
      if (data[STORAGE_KEY]?.latestScan) updateBadge(data[STORAGE_KEY].latestScan);
    });
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    [STORAGE_KEY]: { scans: {}, latestScan: null, history: [], installedAt: Date.now() }
  });
  chrome.action.setBadgeBackgroundColor({ color: '#34d399' });
});
