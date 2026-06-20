/**
 * Connects CloudSpy dashboard to Chrome extension APIs (storage, tab scans, badge).
 */
export class ExtensionBridge {
  static isExtension() {
    return typeof chrome !== 'undefined' && !!chrome.runtime?.id;
  }

  constructor(app) {
    this.app = app;
  }

  async init() {
    if (!ExtensionBridge.isExtension()) return false;

    await this._loadStoredScans();
    this._listen();

    this.app.log('EXTENSION', 'Chrome extension bridge connected.', 'var(--green)');
    return true;
  }

  async _loadStoredScans() {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'GET_STATE' }, state => {
        if (state?.latestScan) this._onPageScan(state.latestScan);
        if (state?.history?.length) {
          state.history.slice(0, 5).forEach(h => {
            this.app.modules.audit.log('page_scan', h.hostname, h.url, `${h.findings} findings`);
          });
        }
        resolve(state);
      });
    });
  }

  _onPageScan(scan) {
    if (!scan) return;
    this.app.modules.pageIntel.ingest(scan);
    this.app.modules.ai.runAnalysis();
    this.app.modules.threatScanner.refresh();
    this.app.modules.riskEngine.computeScore();
    this.app.modules.alerts.rebuild();
    this.app.modules.recommendations.rebuild();
    this.app.log('PAGE-SCAN', `${scan.hostname}: ${scan.findings.length} finding(s)`, scan.findings.length ? 'var(--amber)' : 'var(--green)');
    this.app.ui.renderAll();
  }

  _listen() {
    if (chrome.storage?.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local' || !changes.cloudspy_state?.newValue?.latestScan) return;
        this._onPageScan(changes.cloudspy_state.newValue.latestScan);
      });
    }
  }

  scanActiveTab() {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'SCAN_ACTIVE_TAB' }, resolve);
    });
  }

  openDashboard() {
    chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD' });
  }
}
