export class AIRiskEngine {
  constructor(store, threatScanner, iam) {
    this.store = store;
    this.threatScanner = threatScanner;
    this.iam = iam;
  }

  computeScore() {
    const s = this.store.get();
    let score = 10;
    score += s.threatSurfaces.filter(t => t.status === 'critical').length * 12;
    score += s.threatSurfaces.filter(t => t.status === 'warning').length * 6;
    score += this.iam.getWeakCount() * 5;
    score += s.storage.filter(b => b.public).length * 8;
    score += s.scannedFiles.filter(f => f.verdict === 'malicious').length * 8;
    score += s.scannedFiles.filter(f => f.verdict === 'suspicious').length * 4;
    score += s.anomalyEvents.filter(a => a.severity === 'critical').length * 5;
    const scan = s.pageScan;
    if (scan?.riskHints) {
      score += scan.riskHints.critical * 6;
      score += scan.riskHints.high * 4;
      score += scan.riskHints.medium * 1;
    }
    score = Math.min(100, Math.max(0, score));
    this.store.patch({ riskScore: score });
    return score;
  }

  getBehaviorProfile() {
    const s = this.store.get();
    const behaviors = [];
    if (s.users.some(u => !u.mfa)) behaviors.push('Weak identity posture detected');
    if (s.storage.some(b => b.public)) behaviors.push('Public storage exposure active');
    if (s.anomaliesDetected > 0) behaviors.push(`${s.anomaliesDetected} anomaly signal(s) in AI graph`);
    const bad = s.scannedFiles.filter(f => f.verdict !== 'safe').length;
    if (bad) behaviors.push(`${bad} file threat(s) pending review`);
    return behaviors.length ? behaviors.join('. ') + '.' : 'Environment within normal operating parameters.';
  }

  detectAnomaly() {
    this.store.get().anomaliesDetected++;
    return true;
  }
}
