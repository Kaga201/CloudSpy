import { StateStore } from './core/StateStore.js';
import { EventBus } from './core/EventBus.js';
import { ROLES, MONITOR_INTERVAL_MS, SYNC_INTERVAL_MS } from './core/constants.js';
import { fmtTime, sleep } from './core/utils.js';
import { ExtensionBridge } from './core/ExtensionBridge.js';

import { ThreatScanner } from './modules/ThreatScanner.js';
import { IdentityAccessManager } from './modules/IdentityAccessManager.js';
import { CostAnalyzer } from './modules/CostAnalyzer.js';
import { FileThreatScanner } from './modules/FileThreatScanner.js';
import { AnomalyDetector } from './modules/AnomalyDetector.js';
import { AIEngine } from './modules/AIEngine.js';
import { AIRiskEngine } from './modules/AIRiskEngine.js';
import { RecommendationEngine } from './modules/RecommendationEngine.js';
import { AlertCenter } from './modules/AlertCenter.js';
import { AuditLogger } from './modules/AuditLogger.js';
import { ContinuousMonitor } from './modules/ContinuousMonitor.js';
import { WorkflowMapper } from './modules/WorkflowMapper.js';
import { PageIntel } from './modules/PageIntel.js';
import { SmartOptimization } from './modules/SmartOptimization.js';

import { ToastManager } from './ui/ToastManager.js';
import { UIRenderer } from './ui/UIRenderer.js';
import { backendAPI } from './core/BackendAPI.js';

export class CloudSpyApp {
  constructor() {
    this.store = new StateStore();
    this.bus = new EventBus();
    this.toast = new ToastManager();

    this.modules = {
      fileScanner: new FileThreatScanner(this.store),
      pageIntel: null,
      threatScanner: null,
      iam: new IdentityAccessManager(this.store),
      cost: new CostAnalyzer(this.store),
      anomaly: new AnomalyDetector(this.store),
      ai: null,
      riskEngine: null,
      recommendations: null,
      alerts: new AlertCenter(this.store),
      audit: new AuditLogger(this.store),
      workflow: new WorkflowMapper(this.store),
      optimization: null,
      monitor: null
    };

    this.modules.pageIntel = new PageIntel(this.store, this.modules.fileScanner);
    this.modules.threatScanner = new ThreatScanner(this.store, this.modules.pageIntel);
    this.modules.riskEngine = new AIRiskEngine(this.store, this.modules.threatScanner, this.modules.iam);
    this.modules.recommendations = new RecommendationEngine(this.store, this.modules.iam);
    this.modules.ai = new AIEngine(this.store, this.modules);
    this.modules.optimization = new SmartOptimization(this.store, this.modules.cost);
    this.modules.monitor = new ContinuousMonitor(this.store, this.bus, {
      ...this.modules,
      threatScanner: this.modules.threatScanner,
      riskEngine: this.modules.riskEngine
    });

    this.ui = new UIRenderer(this.store, this);
    this.extension = new ExtensionBridge(this);
    this._intervals = [];
  }

  async start() {
    this._bindLoginScreen();

    const backendOnline = await backendAPI.isAvailable();
    if (!backendOnline) {
      const errEl = document.getElementById('login-error');
      if (errEl) {
        errEl.textContent = 'Backend is not running. Open VS Code terminal in backend folder and run: npm run dev';
        errEl.style.display = 'block';
      }
    }

    const loggedIn = await this._waitForLogin();
    if (!loggedIn) return;

    this._bootstrap();
    this.ui.bindNavigation();
    this.ui.bindActions();
    this._bindControls();
    this._bindEvents();

    await this.extension.init();
    await this._initBackend();

    const role = this.store.get().role || 'security';
    this.ui.setRole(role);
    this.ui.renderAll();

    this.modules.monitor.start(MONITOR_INTERVAL_MS);
    this._intervals.push(setInterval(() => this.ui.updateUptime(), 1000));
    this._intervals.push(setInterval(() => this._periodicSync(), SYNC_INTERVAL_MS));
    this._intervals.push(setInterval(() => {
      this.modules.ai.runAnalysis();
      this.ui.renderPartial(['ai', 'aside']);
    }, 20000));

    this.modules.ai.seedWelcome(() => this.ui.renderChat());
    this.log('SYSTEM', 'CloudSpy AI engine online — file threat scanner ready.');
    this.log('AI', 'Anomaly detection + chatbot assistant active.', 'var(--green)');
    const mode = ExtensionBridge.isExtension() ? 'Chrome extension' : 'Web console';
    this.toast.show(`CloudSpy ${mode} online`, 'success');
  }

  stop() {
    this.modules.monitor.stop();
    this._intervals.forEach(clearInterval);
    this._intervals = [];
  }

  _bootstrap() {
    const m = this.modules;
    m.threatScanner.refresh();
    m.riskEngine.computeScore();
    m.alerts.rebuild();
    m.recommendations.rebuild();
    m.audit.log('system', 'CloudSpy Engine', 'Platform bootstrap', 'success');
  }

  _bindControls() {
    document.getElementById('btn-scan')?.addEventListener('click', () => this.runFullScan());
    document.getElementById('btn-threat-scan')?.addEventListener('click', () => this.runFullScan());
    document.getElementById('btn-scan-files')?.addEventListener('click', () => this.scanAllFiles());
    document.getElementById('btn-clear-alerts')?.addEventListener('click', () => this.ackAllAlerts());
    document.getElementById('btn-export-scanhistory')?.addEventListener('click', () => this.exportScanHistory());
    document.getElementById('btn-apply-optimization')?.addEventListener('click', () => this.applySmartOptimization());
    document.getElementById('role-select')?.addEventListener('change', e => this.setRole(e.target.value));
    document.getElementById('btn-chat-send')?.addEventListener('click', () => this.sendChat());
    document.getElementById('chat-input')?.addEventListener('keydown', e => {
      if (e.key === 'Enter') this.sendChat();
    });
  }

  _bindEvents() {
    this.bus.on('log', ({ tag, msg, color }) => this.log(tag, msg, color));
    this.bus.on('toast', ({ msg, type }) => this.toast.show(msg, type));
    this.bus.on('risk:event', ({ level, text }) => {
      this.ui.addRiskEvent({ time: fmtTime(), level, text });
      this.modules.alerts.rebuild();
    });
    this.bus.on('render:partial', views => this.ui.renderPartial(views));
  }

  _periodicSync() {
    this.modules.threatScanner.refresh();
    this.modules.riskEngine.computeScore();
    this.ui.renderPartial(['overview', 'aside', 'ai']);
    this._syncAuditToBackend();
  }

  _bindLoginScreen() {
    const overlay = document.getElementById('login-overlay');
    const btnLogin = document.getElementById('btn-login');
    const emailInput = document.getElementById('login-email');
    const passInput = document.getElementById('login-password');
    const errEl = document.getElementById('login-error');

    const doLogin = async () => {
      const email = emailInput?.value.trim();
      const password = passInput?.value.trim();
      if (!email || !password) return;
      if (btnLogin) { btnLogin.disabled = true; btnLogin.textContent = 'Signing in…'; }
      if (errEl) errEl.style.display = 'none';
      try {
        const data = await backendAPI.login(email, password);
        this.store.patch({ role: data.role });
        this._showUserInfo(data.email, data.role);
        if (overlay) overlay.style.display = 'none';
        this._loginResolve?.(true);
      } catch (err) {
        if (errEl) { errEl.textContent = err.message; errEl.style.display = 'block'; }
        if (btnLogin) { btnLogin.disabled = false; btnLogin.textContent = 'Sign In'; }
      }
    };

    btnLogin?.addEventListener('click', doLogin);
    passInput?.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

    // Logout
    document.getElementById('btn-logout')?.addEventListener('click', () => {
      backendAPI.clearToken().finally(() => location.reload());
    });
  }

  async _waitForLogin() {
    // Check if token already stored — skip login screen
    const existing = await backendAPI._getToken();
    if (existing) {
      try {
        const me = await backendAPI.get('/api/v1/auth/me');
        this.store.patch({ role: me.role });
        this._showUserInfo(me.email, me.role);
        document.getElementById('login-overlay').style.display = 'none';
        return true;
      } catch {
        // Token expired — fall through to show login screen
        await backendAPI.clearToken();
      }
    }
    return new Promise(resolve => {
      this._loginResolve = resolve;
    });
  }

  _showUserInfo(email, role) {
    const roleNames = { security: 'Security Lead', engineer: 'Engineer', contractor: 'Contractor', finance: 'Finance' };
    const userInfo = document.getElementById('user-info');
    const emailEl = document.getElementById('user-email');
    const chipEl = document.getElementById('user-role-chip');
    if (userInfo) userInfo.style.display = 'flex';
    if (emailEl) emailEl.textContent = email;
    if (chipEl) chipEl.textContent = roleNames[role] || role;
  }

  async _initBackend() {
    try {
      const online = await backendAPI.isAvailable();
      if (!online) return;

      const state = await backendAPI.get('/api/v1/state');
      const s = this.store.get();

      if (state.users?.length) {
        s.users = state.users.map(u => ({
          ...u,
          lastLogin: u.lastLogin ?? Date.now()
        }));
      }
      if (state.vms?.length) {
        s.vms = state.vms.map(v => ({
          id: v.id,
          name: v.name,
          cpu: v.cpuPercent ?? v.cpu ?? 0,
          idle: v.isIdle ?? v.idle ?? false,
          kwh: v.kwhMonthly ?? v.kwh ?? 0,
          cost: v.costMonthly ?? v.cost ?? 0,
          oversized: v.isOversized ?? v.oversized ?? false
        }));
      }
      if (state.storage?.length) {
        s.storage = state.storage.map(b => ({
          id: b.id,
          name: b.name,
          public: b.isPublic ?? b.public ?? false,
          encrypted: b.isEncrypted ?? b.encrypted ?? true
        }));
      }
      if (state.threatSurfaces?.length) {
        s.threatSurfaces = state.threatSurfaces.map(t => ({
          id: t.id,
          surface: t.surfaceName ?? t.surface,
          status: t.status,
          impact: t.impact,
          checked: t.checkedAt ?? t.checked ?? Date.now()
        }));
      }
      if (state.anomalyEvents?.length) s.anomalyEvents = state.anomalyEvents;
      if (state.workflow?.length) {
        s.workflow = state.workflow.map(w => ({
          phase: w.phase,
          title: w.title,
          desc: w.description ?? w.desc,
          role: w.requiredRole ?? w.role,
          status: w.status,
          energy: w.energyEstimate ?? w.energy,
          cost: w.costEstimate ?? w.cost
        }));
      }
      if (state.scannedFiles?.length) s.scannedFiles = state.scannedFiles;

      this.modules.threatScanner.refresh();
      this.modules.riskEngine.computeScore();
      this.modules.alerts.rebuild();
      this.modules.recommendations.rebuild();

      this.log('SYSTEM', 'Backend connected — state loaded from database.', 'var(--green)');
    } catch (err) {
      console.warn('[CloudSpy] Backend init failed, using local state:', err.message);
    }
  }

  async _syncAuditToBackend() {
    try {
      const online = await backendAPI.isAvailable();
      if (!online) return;
      const s = this.store.get();
      const entries = (s.audit || []).slice(0, 20);
      if (!entries.length) return;
      await backendAPI.post('/api/v1/state/sync', { auditEntries: entries });
    } catch {
      // silent — sync is best-effort
    }
  }

  _refreshAll() {
    this.modules.threatScanner.refresh();
    this.modules.riskEngine.computeScore();
    this.modules.alerts.rebuild();
    this.modules.recommendations.rebuild();
    this.ui.renderAll();
  }

  log(tag, msg, color) {
    const entry = { time: fmtTime(), tag, msg, color };
    this.store.get().logs.unshift(entry);
    if (this.store.get().logs.length > 100) this.store.get().logs.pop();
    this.ui.appendLog(entry);
  }

  setRole(role) {
    this.store.patch({ role });
    this.ui.setRole(role);
    const label = ROLES[role]?.name || role;
    this.log('IAM', `Role perspective switched to: ${label}`, 'var(--cyan)');
    this.toast.show(`Viewing as ${label}`, 'success');
  }

  async sendChat() {
    const input = document.getElementById('chat-input');
    const btn = document.getElementById('btn-chat-send');
    if (!input?.value.trim()) return;

    const msg = input.value.trim();
    input.value = '';
    if (btn) { btn.disabled = true; btn.textContent = '…'; }

    const s = this.store.get();
    s.chatHistory.push({ role: 'user', text: msg, time: fmtTime() });
    s.chatHistory.push({ role: 'assistant', text: 'Thinking…', time: fmtTime(), pending: true });
    this.ui.renderChat();

    try {
      s.chatHistory.pop();
      const response = await this.modules.ai.completeReply(msg);
      s.chatHistory.push(response);
      if (s.chatHistory.length > 40) s.chatHistory.splice(0, s.chatHistory.length - 40);
    } catch {
      s.chatHistory.pop();
      s.chatHistory.push({
        role: 'assistant',
        text: 'Sorry, I could not reach Gemini right now. Please try again.',
        time: fmtTime(),
        source: 'local'
      });
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Send'; }
      this.ui.renderChat();
    }
  }

  async scanAllFiles() {
    if (ExtensionBridge.isExtension()) {
      await this.extension.scanActiveTab();
      await sleep(600);
    }

    const scan = this.store.get().pageScan;
    const files = scan?.pageFiles || [];
    if (!files.length) {
      this.toast.show('No files found on page — try OneDrive, Google Drive, or a download page', 'warning');
      return;
    }

    this.modules.fileScanner.scanAll(files.map(f => ({
      ...f,
      cloudProvider: f.cloudProvider || this.modules.fileScanner.detectCloudProvider(f.href || '')
    })));
    this.modules.ai.runAnalysis();
    const scanStart = performance.now();
    this.modules.threatScanner.refresh();
    this.store.patch({
      scanCount: (this.store.get().scanCount || 0) + 1,
      lastScanDurationMs: Math.round(performance.now() - scanStart)
    });
    this.modules.riskEngine.computeScore();
    this.modules.alerts.rebuild();

    const n = this.modules.fileScanner.getThreatCount();
    this.log('FILE-SCAN', `Deep scan: ${files.length} file(s), ${n} threat(s) flagged.`, n ? 'var(--red)' : 'var(--green)');
    this.toast.show(`Scanned ${files.length} files — ${n} threat(s)`, n ? 'warning' : 'success');
    this.ui.renderAll();
  }

  async runFullScan() {
    const s = this.store.get();
    if (s.scanning) return;

    s.scanning = true;
    const btn = document.getElementById('btn-scan');
    const progress = document.getElementById('scan-progress');
    const bar = document.getElementById('scan-bar');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Scanning…'; }
    progress?.classList.add('active');

    try {
      const steps = [
        'Initializing threat surface enumeration…',
        'Scanning cloud configuration arrays…',
        'Probing open port matrix…',
        'Evaluating IAM policy graph…',
        'Auditing blob storage ACLs…',
        'Discovering files on active page…',
        'Running per-file threat analysis…',
        'AI anomaly detection inference…',
        'Computing cost optimization deltas…',
        'Digital twin sync complete.'
      ];

      for (let i = 0; i < steps.length; i++) {
        if (bar) bar.style.width = `${((i + 1) / steps.length) * 100}%`;
        this.log('SCAN', steps[i], 'var(--cyan)');
        await sleep(350);
      }

      if (ExtensionBridge.isExtension()) {
        await this.extension.scanActiveTab();
        await sleep(400);
      }

      await this.scanAllFiles();

      this.modules.threatScanner.refresh();
      this.store.get().threatSurfaces.forEach(t => { t.checked = Date.now(); });
      this.modules.riskEngine.computeScore();
      this.modules.ai.runAnalysis();
      this.modules.alerts.rebuild();
      this.store.patch({ lastSync: new Date(), scanCount: (this.store.get().scanCount || 0) + 1 });

      this.modules.audit.log('scan', 'CloudSpy Scanner', 'Full ecosystem baseline scan', 'complete');
      this.ui.addRiskEvent({
        time: fmtTime(),
        level: s.riskScore > 50 ? 'high' : 'medium',
        text: `Full scan complete — risk index ${s.riskScore}`
      });
      this.log('SCAN', `Scan finalized. Risk score: ${s.riskScore}/100.`, s.riskScore > 50 ? 'var(--amber)' : 'var(--green)');
      this.toast.show('Full ecosystem scan complete', s.riskScore > 60 ? 'warning' : 'success');
      this.ui.renderAll();
    } catch (err) {
      console.error('[CloudSpy] Scan error:', err);
      this.toast.show('Scan encountered an error', 'warning');
    } finally {
      s.scanning = false;
      progress?.classList.remove('active');
      if (bar) bar.style.width = '0';
      if (btn) { btn.disabled = false; btn.textContent = '🔄 Execute Scan'; }
    }
  }

  applySmartOptimization() {
    const result = this.modules.optimization.apply(this.modules);
    if (result.actions.length) {
      this.log('OPTIMIZATION', result.actions.join(' · '), 'var(--green)');
      this.toast.show(`Optimization applied — ${result.actions.length} action(s)`, 'success');
    } else {
      this.toast.show('Environment already optimized — no actions needed', 'success');
    }
    this._refreshAll();
  }

  applyRecommendation(recId) {
    const rec = this.modules.recommendations.apply(recId);
    if (!rec) return;

    const m = this.modules;
    const s = this.store.get();

    switch (rec.action) {
      case 'enable_mfa':
        m.iam.enableMfaGlobally();
        m.audit.log('policy', 'CloudSpy Automation', 'Global MFA enforcement', 'success');
        this.log('AUTOMATION', 'MFA mandated for all identities.', 'var(--green)');
        this.toast.show('MFA enforcement applied to all users', 'success');
        break;
      case 'restrict_storage':
        s.storage.forEach(b => { b.public = false; b.encrypted = true; });
        m.audit.log('policy', 'CloudSpy Automation', 'Storage public access blocked', 'success');
        this.toast.show('Exposed storage buckets secured', 'success');
        break;
      case 'quarantine_files':
        s.scannedFiles.forEach(f => { if (f.verdict !== 'safe') f.quarantined = true; });
        m.audit.log('file', 'CloudSpy AI', 'Threat files quarantined', 'success');
        this.toast.show('Threat files marked for quarantine', 'success');
        break;
      case 'resize_vm': {
        const saved = m.cost.rightSizeVms();
        s.totalSavings += saved;
        m.audit.log('compute', 'CloudSpy Automation', 'VMs right-sized', 'success');
        this.toast.show('Oversized VMs right-sized', 'success');
        break;
      }
      case 'restrict_contractor':
        m.iam.constrainContractors();
        m.audit.log('iam', 'CloudSpy Automation', 'Contractor access constrained', 'success');
        this.toast.show('Contractor access policies tightened', 'success');
        break;
    }

    m.recommendations.markApplied(recId);
    s.appliedActions.add(recId);
    this.ui.addRiskEvent({ time: fmtTime(), level: 'low', text: `Recommendation applied: ${rec.title}` });
    this._refreshAll();
  }

  enforceMfa(userId) {
    const user = this.modules.iam.enforceMfa(userId);
    if (!user) return;
    this.modules.audit.log('iam', user.email, 'MFA enrollment forced', 'success');
    this.toast.show(`MFA enabled for ${user.email}`, 'success');
    this._refreshAll();
  }

  quarantineFile(fileId) {
    const file = this.store.get().scannedFiles.find(f => f.id === fileId);
    if (!file) return;
    file.quarantined = true;
    this.modules.audit.log('file', 'CloudSpy AI', file.name, 'quarantined');
    this.toast.show(`${file.name} quarantined`, 'success');
    this.ui.renderAI();
  }

  shutdownVm(vmId) {
    const idx = this.store.get().vms.findIndex(v => v.id === vmId);
    if (idx < 0) return;
    const vm = this.store.get().vms.splice(idx, 1)[0];
    this.store.get().totalSavings += Math.round(vm.cost * 0.85);
    this.modules.audit.log('compute', 'Manual Action', vm.name, 'deprovisioned');
    this.toast.show(`VM ${vm.name} deprovisioned`, 'success');
    this._refreshAll();
  }

  ackAlert(alertId) {
    this.modules.alerts.acknowledge(alertId);
    this.ui.renderAlerts();
    this.ui.updateBadge();
  }

  ackAllAlerts() {
    this.modules.alerts.acknowledgeAll();
    this.toast.show('All alerts acknowledged', 'success');
    this.ui.renderAlerts();
    this.ui.updateBadge();
  }

  exportScanHistory() {
    const files = this.store.get().scannedFiles;
    if (!files.length) { this.toast.show('No scan data to export', 'warning'); return; }
    const rows = [['Time', 'File Name', 'Extension', 'Cloud Provider', 'Threats', 'Verdict', 'Risk Score']];
    files.forEach(f => rows.push([
      f.scannedAt ? new Date(f.scannedAt).toLocaleString() : '',
      f.name, f.ext || '', f.cloudProvider || '',
      (f.threats || []).length, f.verdict, f.riskScore
    ]));
    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })),
      download: `scan-history-${Date.now()}.csv`
    });
    a.click();
    this.toast.show('Scan history exported', 'success');
  }
}