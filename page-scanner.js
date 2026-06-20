/**
 * CloudSpy Page Scanner — detects page threats and all file links (OneDrive, downloads, etc.)
 */
(function () {
  const FILE_EXT = /\.([a-z0-9]{1,8})(?:\?|#|$)/i;
  const SKIP_EXT = new Set(['html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'css', 'js', 'json', 'xml', 'svg']);

  function detectCloud(url) {
    try {
      const h = new URL(url).hostname;
      if (/onedrive|1drv\.ms/i.test(h)) return 'OneDrive';
      if (/sharepoint/i.test(h)) return 'SharePoint';
      if (/drive\.google|docs\.google/i.test(h)) return 'Google Drive';
      if (/dropbox/i.test(h)) return 'Dropbox';
      if (/box\.com/i.test(h)) return 'Box';
      return null;
    } catch { return null; }
  }

  function addFile(list, seen, raw, source) {
    let href = raw;
    try {
      href = new URL(raw, location.href).href;
    } catch { return; }
    if (seen.has(href)) return;
    seen.add(href);
    const name = decodeURIComponent(href.split('/').pop()?.split('?')[0] || 'unknown').slice(0, 120);
    const extMatch = name.match(FILE_EXT) || href.match(FILE_EXT);
    const ext = extMatch ? extMatch[1].toLowerCase() : 'unknown';
    if (SKIP_EXT.has(ext) && !/download|file|document/i.test(href)) return;
    list.push({
      name,
      ext,
      href,
      source,
      cloudProvider: detectCloud(href)
    });
  }

  const SKIP_HREF = /^(#|javascript:|mailto:|tel:|data:)/i;
  const SKIP_HOST = /^(chrome|chrome-extension|about|blob):/i;

  function addFileByName(list, seen, name, href, source, cloud) {
    const key = href || name;
    if (!key || seen.has(key)) return;
    seen.add(key);
    const extMatch = name.match(/\.([a-z0-9]{2,8})$/i);
    const ext = extMatch ? extMatch[1].toLowerCase() : 'link';
    list.push({ name: name.slice(0, 160), ext, href: href || null, source, cloudProvider: cloud || detectCloud(href || '') });
  }

  function getPerfSizes() {
    const map = new Map();
    try {
      if (typeof performance !== 'undefined' && performance.getEntriesByType) {
        performance.getEntriesByType('resource').forEach(r => {
          const size = r.transferSize || r.encodedBodySize || r.decodedBodySize || 0;
          if (size > 0) map.set(r.name, size);
        });
      }
    } catch {}
    return map;
  }

  function collectFiles() {
    const files = [];
    const seen = new Set();

    // 1. ALL <a href> links — everything except anchors, javascript, mailto
    document.querySelectorAll('a[href]').forEach(a => {
      const raw = a.getAttribute('href') || '';
      if (!raw || SKIP_HREF.test(raw) || SKIP_HOST.test(a.href)) return;
      const href = a.href;
      if (seen.has(href)) return;
      seen.add(href);

      const label = a.getAttribute('title') || a.getAttribute('aria-label') || a.textContent.trim() || '';
      const extMatch = (href + ' ' + label).match(/\.([a-z0-9]{2,8})(\?|#|$| )/i);
      const ext = extMatch ? extMatch[1].toLowerCase() : 'link';

      // Detect Google Docs type
      let cloudProvider = detectCloud(href);
      let detectedExt = ext;
      if (/docs\.google\.com\/spreadsheet/i.test(href)) { detectedExt = 'gsheet'; cloudProvider = 'Google Drive'; }
      else if (/docs\.google\.com\/presentation/i.test(href)) { detectedExt = 'gslides'; cloudProvider = 'Google Drive'; }
      else if (/docs\.google\.com\/document/i.test(href)) { detectedExt = 'gdoc'; cloudProvider = 'Google Drive'; }
      else if (/docs\.google\.com\/forms/i.test(href)) { detectedExt = 'gform'; cloudProvider = 'Google Drive'; }
      else if (/drive\.google\.com\/file/i.test(href)) { cloudProvider = 'Google Drive'; }

      const name = label || decodeURIComponent(href.split('/').pop()?.split('?')[0] || href).slice(0, 160);
      files.push({ name: name.slice(0, 160), ext: detectedExt, href, source: 'link', cloudProvider });
    });

    // 2. Images, iframes, embeds, objects
    document.querySelectorAll('img[src],iframe[src],embed[src],object[data]').forEach(el => {
      const src = el.getAttribute('src') || el.getAttribute('data') || '';
      if (!src || SKIP_HREF.test(src)) return;
      try {
        const href = new URL(src, location.href).href;
        if (seen.has(href)) return;
        seen.add(href);
        const name = src.split('/').pop()?.split('?')[0] || src;
        const ext = name.match(/\.([a-z0-9]{2,8})$/i)?.[1] || el.tagName.toLowerCase();
        files.push({ name: decodeURIComponent(name).slice(0, 160), ext, href, source: el.tagName.toLowerCase(), cloudProvider: detectCloud(href) });
      } catch {}
    });

    // 3. Data attributes with filenames
    document.querySelectorAll('[data-file-name],[data-filename],[data-item-name],[data-name],[data-url],[data-href],[data-src]').forEach(el => {
      const name = el.getAttribute('data-file-name') || el.getAttribute('data-filename') || el.getAttribute('data-item-name') || el.getAttribute('data-name') || '';
      const url = el.getAttribute('data-url') || el.getAttribute('data-href') || el.getAttribute('data-src') || '';
      if (name) addFileByName(files, seen, name, url || null, 'data-attr', null);
      else if (url && !SKIP_HREF.test(url)) addFileByName(files, seen, url.split('/').pop() || url, url, 'data-url', null);
    });

    // 4. Visible text that looks like a filename
    document.querySelectorAll('span,div,p,li,td,th,h1,h2,h3,h4,label,button').forEach(el => {
      if (el.children.length > 3) return;
      const text = el.textContent.trim();
      if (text.length < 4 || text.length > 200) return;
      const m = text.match(/^[\w\s\-_.()[\]]+\.(pdf|docx?|xlsx?|pptx?|odt|ods|csv|txt|zip|rar|7z|exe|msi|png|jpg|jpeg|gif|mp4|mp3|dwg|rvt|psd|ai|svg|xml|json)$/i);
      if (m) addFileByName(files, seen, text, null, 'text', null);
    });

    // 5. title / aria-label on any element
    document.querySelectorAll('[title],[aria-label]').forEach(el => {
      const t = (el.getAttribute('title') || el.getAttribute('aria-label') || '').trim();
      if (t.length < 4 || t.length > 200) return;
      const m = t.match(/[\w\s\-_.()[\]]+\.(pdf|docx?|xlsx?|pptx?|odt|ods|csv|txt|zip|rar|exe|msi|png|jpg|jpeg|mp4|mp3|dwg|psd)/i);
      if (m) addFileByName(files, seen, m[0], null, 'attr', null);
    });

    const perfSizes = getPerfSizes();
    return files.slice(0, 200).map(f => ({
      ...f,
      size: f.href ? (perfSizes.get(f.href) || null) : null
    }));
  }

  function collectPageWeight() {
    let totalBytes = 0;
    let resourceCount = 0;
    try {
      if (typeof performance !== 'undefined' && performance.getEntriesByType) {
        const nav = performance.getEntriesByType('navigation')[0];
        if (nav) totalBytes += nav.transferSize || nav.encodedBodySize || 0;
        performance.getEntriesByType('resource').forEach(r => {
          totalBytes += r.transferSize || r.encodedBodySize || 0;
          resourceCount++;
        });
      }
    } catch {}
    return { totalBytes, resourceCount };
  }

  function scanPage() {
    const url = location.href;
    const isHttps = location.protocol === 'https:';
    const findings = [];
    const pageFiles = collectFiles();
    const { totalBytes: pageWeight, resourceCount } = collectPageWeight();

    if (!isHttps) {
      findings.push({ level: 'critical', code: 'INSECURE_HTTP', message: 'Page served over unencrypted HTTP' });
    }

    document.querySelectorAll('form').forEach((form, i) => {
      const action = form.getAttribute('action') || url;
      if (form.querySelector('input[type="password"]')) {
        if (action.startsWith('http://')) {
          findings.push({ level: 'critical', code: 'LOGIN_HTTP', message: 'Login form submits over HTTP' });
        } else {
          findings.push({ level: 'medium', code: 'LOGIN_FORM', message: 'Password login form detected' });
        }
      }
    });

    pageFiles.forEach(f => {
      if (/\.(exe|bat|cmd|scr|msi|vbs|ps1|hta)(\?|$)/i.test(f.name)) {
        findings.push({ level: 'critical', code: 'FILE_EXECUTABLE', message: `Executable file link: ${f.name}` });
      }
      if (/\.(pdf|docx?|xlsx?)\.(exe|js|bat)/i.test(f.name)) {
        findings.push({ level: 'critical', code: 'FILE_DOUBLE_EXT', message: `Disguised file: ${f.name}` });
      }
      if (f.cloudProvider && /\.(exe|zip|rar|docm|xlsm)/i.test(f.name)) {
        findings.push({ level: 'high', code: 'CLOUD_RISKY', message: `Risky cloud file (${f.cloudProvider}): ${f.name}` });
      }
    });

    if (pageFiles.length > 0) {
      findings.push({ level: 'low', code: 'FILES_FOUND', message: `${pageFiles.length} file(s) detected on page for scanning` });
    }

    const deduped = [];
    const seen = new Set();
    findings.forEach(f => {
      const key = f.code + f.message;
      if (!seen.has(key)) { seen.add(key); deduped.push(f); }
    });

    return {
      url,
      hostname: location.hostname,
      title: document.title,
      isHttps,
      scannedAt: Date.now(),
      findings: deduped,
      pageFiles,
      loginForms: [],
      externalScriptCount: document.querySelectorAll('script[src]').length,
      pageWeight,
      resourceCount,
      riskHints: {
        critical: deduped.filter(f => f.level === 'critical').length,
        high: deduped.filter(f => f.level === 'high').length,
        medium: deduped.filter(f => f.level === 'medium').length,
        low: deduped.filter(f => f.level === 'low').length
      }
    };
  }

  function publish(scan) {
    chrome.runtime.sendMessage({ type: 'PAGE_SCAN', payload: scan }).catch(() => {});
  }

  function run() {
    if (location.protocol === 'chrome-extension:' || location.protocol === 'chrome:') return;
    try {
      publish(scanPage());
    } catch (e) {
      chrome.runtime.sendMessage({ type: 'PAGE_SCAN_ERROR', error: e.message }).catch(() => {});
    }
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'RUN_SCAN') {
      const scan = scanPage();
      publish(scan);
      sendResponse({ ok: true, scan });
    }
    return true;
  });

  run();
  const obs = new MutationObserver(() => {
    clearTimeout(window._csScanT);
    window._csScanT = setTimeout(run, 1500);
  });
  if (document.body) obs.observe(document.body, { childList: true, subtree: true });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') run();
  });
})();
