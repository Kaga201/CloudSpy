import { uid, fmtTime } from '../core/utils.js';

export class AnomalyDetector {
  constructor(store) {
    this.store = store;
    this._baseline = { loginRate: 5, fileAccessRate: 3, riskScore: 50 };
  }

  record(type, detail, severity = 'medium') {
    const s = this.store.get();
    const event = {
      id: uid(),
      time: fmtTime(),
      type,
      detail,
      severity,
      timestamp: Date.now()
    };
    s.anomalyEvents.unshift(event);
    if (s.anomalyEvents.length > 50) s.anomalyEvents.pop();
    s.anomaliesDetected++;
    return event;
  }

  analyzeState() {
    const s = this.store.get();
    const events = [];
    const recent = (type) => s.anomalyEvents.some(e => e.type === type && Date.now() - e.timestamp < 300000);

    const hour = new Date().getHours();
    if ((hour < 6 || hour > 22) && !recent('off_hours')) {
      events.push(this.record('off_hours', 'Activity detected outside business hours (22:00–06:00)', 'medium'));
    }

    const noMfa = s.users.filter(u => !u.mfa).length;
    if (noMfa >= 2 && !recent('iam_drift')) {
      events.push(this.record('iam_drift', `${noMfa} accounts missing MFA — identity posture degraded`, 'high'));
    }

    const threatFiles = s.scannedFiles.filter(f => f.verdict === 'malicious').length;
    if (threatFiles > 0 && !recent('malware_signal')) {
      events.push(this.record('malware_signal', `${threatFiles} malicious file(s) detected on scanned pages`, 'critical'));
    }

    const suspiciousFiles = s.scannedFiles.filter(f => f.verdict === 'suspicious').length;
    if (suspiciousFiles >= 2 && !recent('file_cluster')) {
      events.push(this.record('file_cluster', `Cluster of ${suspiciousFiles} suspicious downloads on page`, 'high'));
    }

    if (s.riskScore > this._baseline.riskScore + 20 && !recent('risk_spike')) {
      events.push(this.record('risk_spike', `Risk score jumped to ${s.riskScore}/100 (baseline ${this._baseline.riskScore})`, 'high'));
    }

    const publicBuckets = s.storage.filter(b => b.public).length;
    if (publicBuckets && !recent('storage_exposure')) {
      events.push(this.record('storage_exposure', `${publicBuckets} storage bucket(s) publicly accessible`, 'critical'));
    }

    return events;
  }

  getRecent(limit = 12) {
    return this.store.get().anomalyEvents.slice(0, limit);
  }

  getCount() {
    return this.store.get().anomaliesDetected;
  }
}
