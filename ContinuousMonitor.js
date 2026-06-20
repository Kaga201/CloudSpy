export class ContinuousMonitor {
  constructor(store, bus, modules) {
    this.store = store;
    this.bus = bus;
    this.modules = modules;
    this._timer = null;
  }

  start(intervalMs) {
    this.stop();
    this._timer = setInterval(() => this.tick(), intervalMs);
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  tick() {
    const s = this.store.get();
    const roll = Math.random();
    const { iam, anomaly, ai, audit, alerts, recommendations, threatScanner, riskEngine } = this.modules;

    if (roll < 0.15) {
      const user = iam.trackLogin(s.users[Math.floor(Math.random() * s.users.length)]);
      this.bus.emit('log', { tag: 'IAM', msg: `Login tracked: ${user.email} (${user.role})` });
      audit.log('login', user.email, 'Console / API Gateway', 'success');
    } else if (roll < 0.28 && s.scannedFiles.length) {
      const file = s.scannedFiles[Math.floor(Math.random() * s.scannedFiles.length)];
      if (file.verdict !== 'safe') {
        anomaly.record('file_access', `Repeated access attempt on flagged file: ${file.name}`, 'high');
        this.bus.emit('log', { tag: 'AI', msg: `Anomaly: suspicious access to ${file.name}`, color: 'var(--red)' });
      }
    } else if (roll < 0.38) {
      anomaly.record('behavior', 'Off-hours configuration mutation pattern detected', 'medium');
      this.bus.emit('log', { tag: 'ANOMALY', msg: 'Off-hours config mutation pattern detected.', color: 'var(--amber)' });
      this.bus.emit('risk:event', { level: 'medium', text: 'Anomalous behavior during non-business hours' });
    } else if (roll < 0.45) {
      ai.runAnalysis();
      this.bus.emit('log', { tag: 'AI', msg: 'Anomaly detection cycle completed.' });
    } else if (roll < 0.52) {
      this.bus.emit('log', { tag: 'SURVEILLANCE', msg: 'Periodic baseline rule validation passed.' });
    } else {
      this.bus.emit('log', { tag: 'SURVEILLANCE', msg: 'Background network traffic stream processed.' });
    }

    const scanStart = performance.now();
    threatScanner.refresh();
    riskEngine.computeScore();
    s.lastScanDurationMs = Math.round(performance.now() - scanStart);
    s.scanCount = (s.scanCount || 0) + 1;
    s.lastSync = new Date();

    if (s.scanCount % 5 === 0) alerts.rebuild();
    if (s.scanCount % 5 === 0) recommendations.rebuild();

    this.bus.emit('render:partial', ['overview', 'monitoring', 'aside', 'ai', 'badge']);
  }
}
