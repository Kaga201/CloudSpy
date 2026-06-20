function riskLabel(scan) {
  if (!scan?.findings?.length) return { text: 'Low', cls: 'ok' };
  const c = scan.riskHints?.critical || 0;
  const h = scan.riskHints?.high || 0;
  if (c > 0) return { text: 'Critical', cls: 'bad' };
  if (h > 0) return { text: 'High', cls: 'bad' };
  if (scan.findings.length > 2) return { text: 'Medium', cls: 'warn' };
  return { text: 'Low', cls: 'warn' };
}

function render(scan) {
  const tabStatus = document.getElementById('tab-status');
  const findingCount = document.getElementById('finding-count');
  const pageRisk = document.getElementById('page-risk');
  const siteUrl = document.getElementById('site-url');
  const findingsList = document.getElementById('findings-list');

  if (!scan) {
    tabStatus.textContent = 'No scan yet';
    tabStatus.className = 'val warn';
    findingCount.textContent = '0';
    pageRisk.textContent = '—';
    siteUrl.textContent = 'Browse a website, then click Scan This Page';
    findingsList.innerHTML = '';
    return;
  }

  tabStatus.textContent = scan.isHttps ? 'HTTPS ✓' : 'HTTP ⚠ INSECURE';
  tabStatus.className = 'val ' + (scan.isHttps ? 'ok' : 'bad');
  findingCount.textContent = String(scan.findings.length);
  findingCount.className = 'val ' + (scan.findings.length ? 'bad' : 'ok');

  const risk = riskLabel(scan);
  pageRisk.textContent = risk.text;
  pageRisk.className = 'val ' + risk.cls;
  siteUrl.textContent = scan.url;

  findingsList.innerHTML = scan.findings.slice(0, 5).map(f =>
    `<div class="finding ${f.level}">${f.message}</div>`
  ).join('') || '<div class="finding" style="border-color:#34d399">No issues detected on this page</div>';
}

async function loadState() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'GET_STATE' }, resolve);
  });
}

async function refresh() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const state = await loadState();
  let scan = state?.latestScan;

  if (tab?.url && !tab.url.startsWith('chrome')) {
    try {
      const host = new URL(tab.url).hostname;
      scan = state?.scans?.[host] || scan;
    } catch { /* ignore */ }
  }

  if (tab?.url?.startsWith('chrome://') || tab?.url?.startsWith('chrome-extension://')) {
    render(null);
    document.getElementById('site-url').textContent = 'Open a normal website to scan (not chrome:// pages)';
    return;
  }

  render(scan);
}

document.getElementById('btn-scan').addEventListener('click', async () => {
  const btn = document.getElementById('btn-scan');
  btn.textContent = '⏳ Scanning…';
  btn.disabled = true;

  chrome.runtime.sendMessage({ type: 'SCAN_ACTIVE_TAB' }, async (resp) => {
    await new Promise(r => setTimeout(r, 400));
    await refresh();
    if (resp && resp.ok === false) {
      const siteUrl = document.getElementById('site-url');
      if (siteUrl) siteUrl.textContent = resp.error || 'Scan failed';
    }
    btn.textContent = '🔍 Scan This Page';
    btn.disabled = false;
  });
});

document.getElementById('btn-dashboard').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD' });
});

document.querySelectorAll('.test-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    chrome.tabs.create({ url: link.href });
  });
});

refresh();
