import { ROLES, VIEW_ACCESS } from '../core/constants.js';
import { fmtTime, fmtMoney, fmtBytes, tagClass, statusLabel } from '../core/utils.js';

export class UIRenderer {
  constructor(store, app) {
    this.store = store;
    this.app = app;
  }

  renderAll() {
    this.renderOverview();
    this.renderThreats();
    this.renderIAM();
    this.renderMonitoring();
    this.renderAlerts();
    this.renderAI();
    this.renderScanHistory();
    this.renderWebDataStats();
    this.renderRiskBreakdown();
    this.renderAside();
    this.renderChat();
    this.updateBadge();
    this.updateUptime();
  }

  renderPartial(views) {
    const map = {
      overview: () => { this.renderOverview(); this.renderWebDataStats(); this.renderRiskBreakdown(); },
      monitoring: () => this.renderMonitoring(),
      aside: () => this.renderAside(),
      ai: () => { this.renderAI(); this.renderChat(); },
      badge: () => this.updateBadge()
    };
    views.forEach(v => map[v]?.());
  }

  renderOverview() {
    const s = this.store.get();
    const m = this.app.modules;
    const opt = m.optimization;
    const threats = s.threatSurfaces.filter(t => t.status !== 'compliant').length;
    const fileThreats = s.scannedFiles.filter(f => f.verdict !== 'safe').length;
    const totalThreats = threats + fileThreats;
    const waste = Math.round(m.cost.computeWaste());
    const metrics = opt.computeMetrics();

    this.setText('val-threats', `${threats} Finding${threats !== 1 ? 's' : ''}`, threats > 0 ? 'var(--red)' : 'var(--green)');
    this.setText('val-files', `${s.scannedFiles.length} Scanned`, 'var(--cyan)');
    this.setText('val-file-threats', `${fileThreats} Threat${fileThreats !== 1 ? 's' : ''}`, fileThreats > 0 ? 'var(--red)' : 'var(--green)');
    this.setText('val-costs', `${fmtMoney(waste)} / mo`, 'var(--cyan)');
    this.setText('out-anomalies', totalThreats);
    this.setText('out-scans', s.scanCount || 0);
    this.setText('out-security', threats === 0 ? '✓ Secure' : `⚠ ${threats}`);
    this.setText('last-sync', s.lastSync ? fmtTime(s.lastSync) : '—');
    this.setText('twin-updated', `${m.workflow.getDigitalTwinNodes().length} nodes · ${fmtTime()}`);

    const activeThreats = s.scannedFiles.filter(f => f.verdict !== 'safe').length;
    const RISKY_EXT = new Set(['exe','bat','cmd','msi','scr','ps1','hta','vbs','docm','xlsm','zip','rar','7z','iso']);
    const unsafeLinks = s.scannedFiles.filter(f =>
      (f.href || f.url || '').startsWith('http://') ||
      RISKY_EXT.has((f.ext || '').toLowerCase())
    ).length;
    const totalFiles = s.scannedFiles.length;
    const probed = s.scannedFiles.filter(f => f.probed).length;
    const coverage = totalFiles > 0 ? Math.round((probed / totalFiles) * 100) : 0;

    this.setText('opt-threats', activeThreats, activeThreats > 0 ? 'var(--red)' : 'var(--green)');
    this.setText('opt-unsafe', unsafeLinks, unsafeLinks > 0 ? 'var(--amber)' : 'var(--green)');
    this.setText('opt-coverage', `${coverage}%`, coverage >= 80 ? 'var(--green)' : coverage >= 40 ? 'var(--amber)' : 'var(--text-faint)');
    this.setText('opt-security', `${metrics.securityRisk}%`, metrics.securityRisk > 50 ? 'var(--red)' : metrics.securityRisk > 25 ? 'var(--amber)' : 'var(--green)');

    const optRecs = document.getElementById('opt-recs');
    if (optRecs) {
      const engineRecs = s.recommendations.filter(r => !r.applied);
      optRecs.innerHTML = engineRecs.length
        ? engineRecs.map(r => `<div class="rec-card${r.applied ? ' applied' : ''}">
            <div class="rec-title">${r.icon} ${r.title}</div>
            <div class="rec-text">${r.text}</div>
            <div class="rec-actions"><button class="btn-xs" data-action="apply-rec" data-id="${r.id}">Apply Fix</button></div>
          </div>`).join('')
        : '<div style="font-size:12px;color:var(--green);padding:4px 0;">✓ No active issues — environment is clean.</div>';
    }

    this.renderRiskBreakdown();

    const pageScan = s.pageScan;
    const pagePanel = document.getElementById('page-scan-panel');
    const pageTime = document.getElementById('page-scan-time');
    if (pagePanel) {
      if (!pageScan) {
        pagePanel.innerHTML = 'Browse any website — CloudSpy auto-detects and scans every file link (OneDrive, Drive, downloads).';
      } else {
        if (pageTime) pageTime.textContent = fmtTime(new Date(pageScan.scannedAt));
        pagePanel.innerHTML = `<div style="margin-bottom:8px;"><b>${pageScan.hostname}</b> — ${pageScan.pageFiles?.length || 0} file(s), ${pageScan.findings.length} page finding(s)</div>`;
      }
    }

    const twin = document.getElementById('digital-twin');
    if (twin) {
      const nodes = m.workflow.getDigitalTwinNodes();
      twin.style.gridTemplateColumns = nodes.length > 12
        ? 'repeat(auto-fill, minmax(100px, 1fr))'
        : nodes.length > 6
          ? 'repeat(auto-fill, minmax(110px, 1fr))'
          : 'repeat(auto-fill, minmax(130px, 1fr))';
      twin.innerHTML = nodes.map(n =>
        `<div class="twin-node ${n.status}">
          <div class="dot"></div>
          <div class="cat">${n.category}</div>
          <div class="name">${n.name}</div>
          ${n.detail ? `<div class="twin-detail">${n.detail}</div>` : ''}
        </div>`
      ).join('');
    }

    const tl = document.getElementById('risk-timeline');
    if (tl) {
      tl.innerHTML = s.riskTimeline.length
        ? s.riskTimeline.map(e => `<div class="risk-event ${e.level}"><span class="risk-time">${e.time}</span><span>${e.text}</span></div>`).join('')
        : '<div class="empty-state">No risk events yet — engine is monitoring.</div>';
    }
  }

  renderThreats() {
    const tbody = document.getElementById('threat-tbody');
    if (!tbody) return;
    tbody.innerHTML = this.store.get().threatSurfaces.map(t =>
      `<tr><td>${t.surface}</td><td><span class="tag ${tagClass(t.status)}">${statusLabel(t.status)}</span></td><td>${t.impact}</td><td>${fmtTime(new Date(t.checked))}</td></tr>`
    ).join('');
  }

  renderIAM() {
    const s = this.store.get();
    const stats = this.app.modules.iam.getStats();
    this.setText('iam-total', stats.total);
    this.setText('iam-mfa-ok', stats.mfaOk);
    this.setText('iam-mfa-miss', stats.mfaMissing);

    const tbody = document.getElementById('iam-tbody');
    if (!tbody) return;
    tbody.innerHTML = s.users.map(u =>
      `<tr>
        <td>${u.email}</td>
        <td><span class="tag tag-blue">${u.role}</span></td>
        <td><span class="tag ${u.mfa ? 'tag-green' : 'tag-red'}">${u.mfa ? 'Enforced' : 'Missing MFA'}</span></td>
        <td>${fmtTime(new Date(u.lastLogin))}</td>
        <td>${u.logins24h}</td>
        <td>${!u.mfa ? `<button class="btn-xs" data-action="enforce-mfa" data-id="${u.id}">Force MFA</button>` : '—'}</td>
      </tr>`
    ).join('');
  }

  renderMonitoring() {
    const s = this.store.get();
    const totalThreats = this.app.modules.optimization.getThreatCount();
    this.setText('mon-events', s.scanCount || 0);
    this.setText('mon-anomalies', totalThreats);
    const duration = s.lastScanDurationMs || 0;
    this.setText('mon-interval', duration >= 1000 ? `${(duration / 1000).toFixed(1)}s` : `${duration}ms`);
  }

  renderAlerts() {
    const active = this.app.modules.alerts.getActive();
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;
    if (!active.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No active alerts — all clear.</td></tr>';
      return;
    }
    tbody.innerHTML = active.map(a =>
      `<tr>
        <td>${fmtTime(new Date(a.time))}</td>
        <td><span class="tag tag-blue">${a.cat}</span></td>
        <td>${a.desc}</td>
        <td><span class="tag ${tagClass(a.priority)}">${statusLabel(a.priority)}</span></td>
        <td><button class="btn-xs" data-action="ack-alert" data-id="${a.id}">Ack</button></td>
      </tr>`
    ).join('');
  }

  renderAI() {
    const s = this.store.get();
    this.setText('ai-file-count', s.scannedFiles.length);
    this.setText('ai-threat-count', s.scannedFiles.filter(f => f.verdict !== 'safe').length);
    this.setText('ai-anomaly-count', s.anomalyEvents.length);

    const fileBody = document.getElementById('file-threat-tbody');
    if (fileBody) {
      if (!s.scannedFiles.length) {
        fileBody.innerHTML = '<tr><td colspan="7" class="empty-state">No files detected yet. Visit OneDrive, Google Drive, or any download page.</td></tr>';
      } else {
        fileBody.innerHTML = s.scannedFiles.map(f => {
          const vClass = f.verdict === 'malicious' ? 'tag-red' : f.verdict === 'suspicious' ? 'tag-amber' : 'tag-green';
          const link = f.href || f.url;
          const fileName = link
            ? `<a href="${link}" target="_blank" rel="noopener" title="${link}" style="color:var(--cyan);text-decoration:none;font-family:var(--mono);font-size:11px;" onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${f.name}</a>`
            : `<span title="No URL available" style="font-family:var(--mono);font-size:11px;">${f.name}</span>`;
          const threatBadges = (f.threats || []).length
            ? f.threats.map(t => `<span class="tag ${t.level === 'critical' ? 'tag-red' : t.level === 'high' ? 'tag-amber' : 'tag-blue'}" title="${t.message}" style="margin:1px;font-size:10px;">${t.code}</span>`).join('')
            : '<span style="color:var(--green);font-size:11px;">✓ Clean</span>';
          const source = f.cloudProvider
            ? `<span class="tag tag-blue" style="font-size:10px;">${f.cloudProvider}</span>`
            : (f.source || '—');
          return `<tr>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${fileName}</td>
            <td><span class="tag" style="font-size:10px;">.${f.ext || '?'}</span></td>
            <td>${source}</td>
            <td><span class="tag ${vClass}">${f.verdict.toUpperCase()}</span></td>
            <td style="max-width:200px;">${threatBadges}</td>
            <td style="font-size:10px;color:var(--text-dim);">${f.probed ? `<span title="${f.magicMismatch || ''}">${f.actualType || 'OK'}</span>` : '—'}</td>
          </tr>`;
        }).join('');
      }
    }

    const anomalyFeed = document.getElementById('anomaly-feed');
    if (anomalyFeed) {
      const events = this.app.modules.anomaly.getRecent(15);
      anomalyFeed.innerHTML = events.length
        ? events.map(e => `<div class="anomaly-item ${e.severity}"><span class="anomaly-time">${e.time}</span><span>${e.detail}</span></div>`).join('')
        : '<div class="empty-state" style="padding:16px;">No anomalies detected. AI engine is watching.</div>';
    }
  }

  renderChat() {
    const box = document.getElementById('chat-messages');
    if (!box) return;
    box.innerHTML = this.store.get().chatHistory.map(m => {
      const label = m.pending
        ? '<span class="chat-source pending">Thinking…</span>'
        : m.role === 'assistant' && m.source === 'gemini'
          ? '<span class="chat-source gemini">Gemini</span>'
          : m.role === 'assistant' && m.source === 'local'
            ? '<span class="chat-source local">Local</span>'
            : '';
      const bubbleClass = m.pending ? 'chat-bubble pending' : 'chat-bubble';
      return `<div class="chat-msg ${m.role}${m.pending ? ' pending' : ''}"><div class="${bubbleClass}">${m.text.replace(/\n/g, '<br>')}</div><div class="chat-time">${m.time}${label}</div></div>`;
    }).join('');
    box.scrollTop = box.scrollHeight;
  }

  renderScanHistory() {
    const tbody = document.getElementById('scanhistory-tbody');
    if (!tbody) return;
    const files = this.store.get().scannedFiles;
    if (!files.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted)">No scans yet — browse a page with files then click Scan All Files.</td></tr>';
      return;
    }
    tbody.innerHTML = files.map(f => {
      const time = f.scannedAt ? new Date(f.scannedAt).toLocaleString() : '—';
      const threatCount = (f.threats || []).length;
      const verdictClass = f.verdict === 'malicious' ? 'critical' : f.verdict === 'suspicious' ? 'warning' : 'compliant';
      const provider = f.cloudProvider ? `<span class="tag tag-blue">${f.cloudProvider}</span>` : '—';
      return `<tr>
        <td style="font-size:11px;color:var(--muted)">${time}</td>
        <td style="font-family:var(--mono);font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${f.name}">${f.name}</td>
        <td><span class="tag">.${f.ext || '?'}</span></td>
        <td>${provider}</td>
        <td><span style="color:${threatCount > 0 ? 'var(--red)' : 'var(--green)'}">${threatCount} threat${threatCount !== 1 ? 's' : ''}</span></td>
        <td><span class="tag ${tagClass(verdictClass)}">${f.verdict}</span></td>
      </tr>`;
    }).join('');
  }

  renderCost() {
    const s = this.store.get();
    const cost = this.app.modules.cost;
    const monthly = cost.getMonthlySpend();
    const waste = Math.round(cost.computeWaste());
    this.setText('cost-monthly', fmtMoney(monthly));
    this.setText('cost-waste', fmtMoney(waste));
    this.setText('cost-optimized', fmtMoney(Math.max(0, monthly - waste)));

    const tbody = document.getElementById('cost-tbody');
    if (!tbody) return;
    tbody.innerHTML = s.vms.map(v => {
      const { issue, savings } = cost.getResourceAnalysis(v);
      const vmCost = v.cost ?? v.costMonthly ?? 0;
      const isIdle = v.idle ?? v.isIdle;
      const isOversized = v.oversized ?? v.isOversized;
      return `<tr>
        <td>${v.name}</td>
        <td>VM</td>
        <td>${issue}</td>
        <td>${fmtMoney(vmCost)}/mo</td>
        <td style="color:var(--amber)">${savings ? fmtMoney(savings) : '—'}</td>
        <td>${isIdle || isOversized ? `<button class="btn-xs" data-action="shutdown-vm" data-id="${v.id}">Optimize</button>` : '—'}</td>
      </tr>`;
    }).join('');

    this.renderResourceUsage();
  }

  renderResourceUsage() {
    const RISKY_EXT = new Set([
      'exe','bat','cmd','com','scr','msi','dll','vbs','vbe','jse','wsf','ps1','hta','apk','app',
      'docm','xlsm','pptm','dotm','xltm',
      'zip','rar','7z','tar','gz','iso'
    ]);

    const files = this.store.get().scannedFiles;
    const toMB = bytes => (Number(bytes) / (1024 * 1024)).toFixed(2);

    const totalBytes = files.reduce((sum, f) => sum + (Number(f.fileSize) || 0), 0);
    const cloudFiles = files.filter(f => f.cloudProvider);
    const cloudBytes = cloudFiles.reduce((sum, f) => sum + (Number(f.fileSize) || 0), 0);
    const riskyFiles = files.filter(f => f.ext && RISKY_EXT.has(f.ext.toLowerCase()));

    this.setText('ru-total-size', totalBytes > 0 ? `${toMB(totalBytes)} MB` : `${files.length} files`);
    this.setText('ru-risky-count', riskyFiles.length, riskyFiles.length > 0 ? 'var(--red)' : 'var(--green)');
    this.setText('ru-cloud-est', cloudBytes > 0 ? `${toMB(cloudBytes)} MB` : `${cloudFiles.length} files`);

    const metaEl = document.getElementById('ru-meta');
    if (metaEl) metaEl.textContent = `${files.length} file${files.length !== 1 ? 's' : ''} · ${cloudFiles.length} cloud`;

    const extCount = {};
    riskyFiles.forEach(f => {
      const ext = f.ext?.toLowerCase() || '?';
      extCount[ext] = (extCount[ext] || 0) + 1;
    });
    const extList = document.getElementById('ru-risky-ext-list');
    if (extList) {
      extList.innerHTML = Object.keys(extCount).length
        ? Object.entries(extCount).sort((a, b) => b[1] - a[1])
            .map(([ext, n]) => `<span class="tag tag-red" style="margin:3px;font-size:11px;">.${ext} <b>(${n})</b></span>`).join('')
        : '<span style="color:var(--text-faint);font-size:12px;">No risky file types detected</span>';
    }

    const suspicious = files
      .filter(f => f.verdict !== 'safe' || (f.ext && RISKY_EXT.has(f.ext?.toLowerCase())))
      .sort((a, b) => (Number(b.fileSize) || 0) - (Number(a.fileSize) || 0))
      .slice(0, 25);

    const stbody = document.getElementById('ru-suspicious-tbody');
    if (!stbody) return;
    if (!suspicious.length) {
      stbody.innerHTML = '<tr><td colspan="6" class="empty-state">No suspicious or risky files detected.</td></tr>';
      return;
    }
    stbody.innerHTML = suspicious.map(f => {
      const sizeMB = f.fileSize ? `${toMB(f.fileSize)} MB` : '—';
      const vClass = f.verdict === 'malicious' ? 'tag-red' : f.verdict === 'suspicious' ? 'tag-amber' : 'tag-blue';
      const extClass = f.ext && RISKY_EXT.has(f.ext.toLowerCase()) ? 'tag-red' : '';
      const provider = f.cloudProvider ? `<span class="tag tag-blue" style="font-size:10px;">${f.cloudProvider}</span>` : '—';
      const scoreColor = f.riskScore >= 40 ? 'var(--red)' : f.riskScore >= 15 ? 'var(--amber)' : 'var(--green)';
      return `<tr>
        <td style="font-family:var(--mono);font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${f.name}">${f.name}</td>
        <td><span class="tag ${extClass}">.${f.ext || '?'}</span></td>
        <td style="font-family:var(--mono);font-size:11px;">${sizeMB}</td>
        <td>${provider}</td>
        <td><span class="tag ${vClass}">${(f.verdict || 'unknown').toUpperCase()}</span></td>
        <td style="font-family:var(--mono);font-size:11px;color:${scoreColor};">${f.riskScore ?? '—'}</td>
      </tr>`;
    }).join('');
  }

  renderRiskBreakdown() {
    const s = this.store.get();
    const score = s.riskScore || 0;

    const scoreEl = document.getElementById('rb-score-val');
    const bar = document.getElementById('rb-bar');
    const label = document.getElementById('rb-label');
    const factorsEl = document.getElementById('rb-factors');
    if (!scoreEl) return;

    const color = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--amber)' : 'var(--green)';
    scoreEl.textContent = score;
    scoreEl.style.color = color;
    if (bar) { bar.style.width = `${score}%`; bar.style.background = color; }
    if (label) label.textContent = score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MODERATE RISK' : 'LOW RISK';

    if (!factorsEl) return;

    const critSurfaces  = s.threatSurfaces.filter(t => t.status === 'critical');
    const warnSurfaces  = s.threatSurfaces.filter(t => t.status === 'warning');
    const weakIam       = s.users.filter(u => !u.mfa);
    const publicBuckets = s.storage.filter(b => b.public || b.isPublic);
    const malicious     = s.scannedFiles.filter(f => f.verdict === 'malicious');
    const suspicious    = s.scannedFiles.filter(f => f.verdict === 'suspicious');
    const critAnomalies = s.anomalyEvents.filter(a => a.severity === 'critical');
    const scan          = s.pageScan;
    const pageRisk      = scan?.riskHints
      ? (scan.riskHints.critical * 6 + scan.riskHints.high * 4 + scan.riskHints.medium * 1)
      : 0;

    const factors = [
      { label: 'Critical Threat Surfaces', count: critSurfaces.length, pts: critSurfaces.length * 12, color: 'var(--red)',   detail: critSurfaces.map(t => t.surface || t.surfaceName).join(' · ') },
      { label: 'Warning Surfaces',          count: warnSurfaces.length, pts: warnSurfaces.length * 6,  color: 'var(--amber)', detail: warnSurfaces.map(t => t.surface || t.surfaceName).join(' · ') },
      { label: 'Accounts Missing MFA',      count: weakIam.length,       pts: weakIam.length * 5,       color: 'var(--amber)', detail: weakIam.map(u => u.email).join(' · ') },
      { label: 'Public Storage Buckets',    count: publicBuckets.length,  pts: publicBuckets.length * 8, color: 'var(--red)',   detail: publicBuckets.map(b => b.name).join(' · ') },
      { label: 'Malicious Files',           count: malicious.length,      pts: malicious.length * 8,     color: 'var(--red)',   detail: malicious.slice(0, 3).map(f => f.name).join(' · ') },
      { label: 'Suspicious Files',          count: suspicious.length,     pts: suspicious.length * 4,    color: 'var(--amber)', detail: suspicious.slice(0, 3).map(f => f.name).join(' · ') },
      { label: 'Critical Anomaly Events',   count: critAnomalies.length,  pts: critAnomalies.length * 5, color: 'var(--red)',   detail: '' },
      { label: 'Page Risk Signals',         count: null,                  pts: pageRisk,                 color: 'var(--amber)', detail: scan ? scan.hostname : '' },
    ].filter(f => f.pts > 0);

    if (!factors.length) {
      factorsEl.innerHTML = '<div class="empty-state" style="padding:8px 0;">No active risk factors detected — environment is clean.</div>';
      return;
    }

    const maxPts = Math.max(...factors.map(f => f.pts));
    factorsEl.innerHTML = factors.map(f => `
      <div>
        <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px;">
          <span style="font-size:12.5px;">${f.label}${f.count !== null ? ` <span style="font-family:var(--mono);font-size:10px;color:var(--text-faint);">(${f.count})</span>` : ''}</span>
          <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:${f.color};flex:none;margin-left:8px;">+${f.pts} pts</span>
        </div>
        <div style="height:5px;background:var(--line);border-radius:3px;overflow:hidden;margin-bottom:3px;">
          <div style="height:100%;width:${Math.round((f.pts / maxPts) * 100)}%;background:${f.color};border-radius:3px;"></div>
        </div>
        ${f.detail ? `<div style="font-size:10px;color:var(--text-faint);font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${f.detail}">${f.detail}</div>` : ''}
      </div>`).join('');
  }

  renderWebDataStats() {
    const s = this.store.get();
    const stats = s.webDataStats;
    if (!stats) return;

    this.setText('wds-pages', stats.totalPagesScanned);
    this.setText('wds-links', stats.totalLinksFound);
    this.setText('wds-bytes', fmtBytes(stats.totalBytesScanned), 'var(--amber)');
    this.setText('wds-probed', stats.totalFilesProbed);

    const meta = document.getElementById('wds-meta');
    if (meta) {
      meta.textContent = stats.totalPagesScanned
        ? `${stats.totalPagesScanned} page${stats.totalPagesScanned !== 1 ? 's' : ''} · ${fmtBytes(stats.totalBytesScanned)} total data`
        : 'No pages scanned yet — browse any page';
    }

    const histTbody = document.getElementById('wds-history-tbody');
    if (histTbody) {
      if (!stats.history.length) {
        histTbody.innerHTML = '<tr><td colspan="5" class="empty-state">Browse any page — CloudSpy will auto-record its data footprint here.</td></tr>';
      } else {
        histTbody.innerHTML = stats.history.map(h => `<tr>
          <td style="font-family:var(--mono);font-size:12px;">${h.hostname}</td>
          <td>${h.links}</td>
          <td style="color:var(--amber);font-family:var(--mono);font-size:12px;">${fmtBytes(h.pageWeight)}</td>
          <td>${h.filesProbed}</td>
          <td style="font-family:var(--mono);font-size:11px;color:var(--text-faint)">${fmtTime(new Date(h.scannedAt))}</td>
        </tr>`).join('');
      }
    }

    const linksTbody = document.getElementById('wds-links-tbody');
    const filesMeta = document.getElementById('wds-files-meta');

    const allFiles = s.scannedFiles.length
      ? s.scannedFiles
      : (s.pageScan?.pageFiles || []);

    if (filesMeta) {
      filesMeta.textContent = allFiles.length
        ? `${allFiles.length} link${allFiles.length !== 1 ? 's' : ''} · ${fmtBytes(allFiles.reduce((sum, f) => sum + (f.fileSize || parseInt(f.size) || 0), 0))} total`
        : '—';
    }

    if (!linksTbody) return;
    if (!allFiles.length) {
      linksTbody.innerHTML = '<tr><td colspan="6" class="empty-state">No links scanned yet — visit a page to populate this table.</td></tr>';
      return;
    }

    linksTbody.innerHTML = allFiles.map(f => {
      const sizeBytes = f.fileSize || parseInt(f.size) || 0;
      const sizeLabel = sizeBytes
        ? `<span style="color:var(--amber);font-family:var(--mono);font-size:11px;font-weight:600;">${fmtBytes(sizeBytes)}</span>`
        : `<span style="color:var(--text-faint);font-size:11px;">not loaded</span>`;
      const providerLabel = f.cloudProvider
        ? `<span class="tag tag-blue" style="font-size:10px;">${f.cloudProvider}</span>`
        : `<span style="color:var(--text-faint);font-size:11px;">web</span>`;
      const verdict = f.verdict || 'unknown';
      const vClass = verdict === 'malicious' ? 'tag-red' : verdict === 'suspicious' ? 'tag-amber' : verdict === 'safe' ? 'tag-green' : 'tag-blue';
      const href = f.href || f.url;
      let urlCell = '<span style="color:var(--text-faint);font-size:11px;">—</span>';
      if (href) {
        try {
          urlCell = `<a href="${href}" target="_blank" rel="noopener" style="color:var(--cyan);font-family:var(--mono);font-size:10px;" title="${href}">${new URL(href).hostname}</a>`;
        } catch {
          urlCell = `<span style="font-family:var(--mono);font-size:10px;color:var(--text-faint);">${href.slice(0, 40)}</span>`;
        }
      }
      return `<tr>
        <td style="font-family:var(--mono);font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${f.name}">${f.name}</td>
        <td><span class="tag" style="font-size:10px;">.${f.ext || '?'}</span></td>
        <td>${providerLabel}</td>
        <td>${sizeLabel}</td>
        <td><span class="tag ${vClass}" style="font-size:10px;">${verdict.toUpperCase()}</span></td>
        <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;">${urlCell}</td>
      </tr>`;
    }).join('');
  }

  renderAside() {
    const s = this.store.get();
    const metrics = this.app.modules.optimization.computeMetrics();
    const el = document.getElementById('aside-opt-summary');
    if (el) {
      el.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;">
          <div><span style="color:var(--text-faint);">Cost</span><br><b style="color:var(--green)">${fmtMoney(metrics.costSaving)}/mo</b></div>
          <div><span style="color:var(--text-faint);">Energy</span><br><b style="color:var(--cyan)">${metrics.energySaving} kWh</b></div>
          <div><span style="color:var(--text-faint);">Carbon</span><br><b style="color:var(--green)">${metrics.carbonReduction} kg</b></div>
          <div><span style="color:var(--text-faint);">Risk</span><br><b style="color:${metrics.securityRisk > 50 ? 'var(--red)' : 'var(--amber)'}">${metrics.securityRisk}%</b></div>
        </div>
        <div style="font-size:11px;margin-top:10px;color:var(--text-dim);">
          <b>Scans:</b> ${s.scanCount || 0} · <b>Threats:</b> ${metrics.threatCount}
        </div>`;
    }
  }

  appendLog(entry) {
    const html = `<div class="term-row" style="color:${entry.color || 'inherit'}"><span class="t-time">[${entry.time}]</span><span>[${entry.tag}] ${entry.msg}</span></div>`;
    ['terminal-stream', 'aside-feed'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.insertAdjacentHTML('afterbegin', html);
        while (el.children.length > 40) el.lastChild.remove();
      }
    });
  }

  addRiskEvent(event) {
    const s = this.store.get();
    s.riskTimeline.unshift(event);
    if (s.riskTimeline.length > 8) s.riskTimeline.pop();
  }

  updateBadge() {
    const n = this.app.modules.alerts.getActiveCount();
    const badge = document.getElementById('alert-badge');
    if (badge) {
      badge.textContent = n;
      badge.style.display = n ? 'inline' : 'none';
    }
  }

  updateUptime() {
    const s = Math.floor((Date.now() - this.store.get().startTime) / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    this.setText('uptime', `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`);
  }

  setRole(role) {
    const r = ROLES[role];
    const chip = document.getElementById('role-chip');
    if (chip) chip.textContent = r.chip;
    this.setText('role-name', r.name);
    this.setText('role-label', r.label);

    document.querySelectorAll('.nav-item[data-target]').forEach(item => {
      const view = item.dataset.target;
      const allowed = VIEW_ACCESS[view];
      const visible = allowed.includes('all') || allowed.includes(role) || role === 'security';
      item.style.display = visible ? '' : 'none';
    });
  }

  setText(id, val, color) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val;
    if (color) el.style.color = color;
  }

  bindNavigation() {
    document.querySelectorAll('.nav-item[data-target]').forEach(item => {
      item.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        item.classList.add('active');
        document.getElementById(item.dataset.target)?.classList.add('active');
        const title = document.getElementById('page-title');
        if (title) {
          title.innerText = item.innerText.replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/gu, '').replace(/\d+/g, '').trim();
        }
      });
    });
  }

  bindActions() {
    document.body.addEventListener('click', e => {
      const btn = e.target.closest('[data-action]');
      if (!btn) return;
      const { action, id } = btn.dataset;
      const handlers = {
        'enforce-mfa': () => this.app.enforceMfa(id),
        'quarantine-file': () => this.app.quarantineFile(id),
        'shutdown-vm': () => this.app.shutdownVm(id),
        'ack-alert': () => this.app.ackAlert(id),
        'apply-rec': () => this.app.applyRecommendation(id)
      };
      handlers[action]?.();
    });
  }
}
