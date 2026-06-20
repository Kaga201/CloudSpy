export class SmartOptimization {
  constructor(store, cost) {
    this.store = store;
    this.cost = cost;
  }

  getThreatCount() {
    const s = this.store.get();
    const surfaceThreats = s.threatSurfaces.filter(t => t.status !== 'compliant').length;
    const fileThreats = s.scannedFiles.filter(f => f.verdict !== 'safe').length;
    return surfaceThreats + fileThreats;
  }

  computeMetrics() {
    const s = this.store.get();
    const vms = s.vms || [];
    const waste = this.cost.computeWaste();

    let energySaving = 0;
    vms.forEach(v => {
      const kwh = v.kwh ?? v.kwhMonthly ?? 0;
      if (v.idle ?? v.isIdle) energySaving += Math.round(kwh * 0.85);
      if (v.oversized ?? v.isOversized) energySaving += Math.round(kwh * 0.35);
    });

    const carbonReduction = Math.round(energySaving * 0.42);
    const threatCount = this.getThreatCount();
    const securityRisk = Math.min(100, Math.max(0, threatCount * 12 + s.users.filter(u => !u.mfa).length * 8));

    return {
      costSaving: Math.round(waste),
      energySaving,
      carbonReduction,
      securityRisk,
      threatCount
    };
  }

  getRecommendations(threatCount) {
    const recs = [];
    if (threatCount >= 5) {
      recs.push({ icon: '🔴', title: 'Critical — Immediate lockdown', text: `${threatCount} active threats detected. Quarantine files, restrict storage, and enforce MFA now.` });
    } else if (threatCount >= 3) {
      recs.push({ icon: '⚠️', title: 'High priority remediation', text: `${threatCount} threats found — run full scan and apply automated fixes within 24h.` });
    } else if (threatCount >= 1) {
      recs.push({ icon: '🛡️', title: 'Targeted mitigation', text: `${threatCount} threat(s) detected — review surfaces and quarantine flagged files.` });
    } else {
      recs.push({ icon: '✓', title: 'Posture healthy', text: 'No active threats — maintain continuous monitoring and cost optimization.' });
    }
    return recs;
  }

  apply(modules) {
    const s = this.store.get();
    let actions = [];

    const publicBuckets = s.storage.filter(b => b.public);
    if (publicBuckets.length) {
      s.storage.forEach(b => { b.public = false; b.encrypted = true; });
      actions.push(`${publicBuckets.length} bucket(s) secured`);
    }

    const noMfa = s.users.filter(u => !u.mfa);
    if (noMfa.length) {
      modules.iam.enableMfaGlobally();
      actions.push(`MFA enforced on ${noMfa.length} account(s)`);
    }

    const threatFiles = s.scannedFiles.filter(f => f.verdict !== 'safe' && !f.quarantined);
    if (threatFiles.length) {
      threatFiles.forEach(f => { f.quarantined = true; });
      actions.push(`${threatFiles.length} file(s) quarantined`);
    }

    const vmSaved = modules.cost.rightSizeVms();
    if (vmSaved) actions.push(`VMs right-sized — $${vmSaved}/mo saved`);

    let idleSaved = 0;
    const idleVms = s.vms.filter(v => v.idle ?? v.isIdle);
    idleVms.forEach(v => {
      const cost = v.cost ?? v.costMonthly ?? 0;
      idleSaved += Math.round(cost * 0.85);
      v.idle = false;
      v.isIdle = false;
      v.cpu = Math.max(v.cpu ?? v.cpuPercent ?? 0, 15);
    });
    if (idleSaved) actions.push(`${idleVms.length} idle VM(s) optimized — $${idleSaved}/mo recovered`);

    s.totalSavings += vmSaved + idleSaved;
    modules.audit.log('optimization', 'Smart Optimization Center', actions.join('; ') || 'No changes needed', 'success');

    return { actions, saved: vmSaved + idleSaved };
  }
}
