export class RecommendationEngine {
  constructor(store, iam) {
    this.store = store;
    this.iam = iam;
  }

  rebuild() {
    const s = this.store.get();
    const recs = [];
    const activeThreats = s.threatSurfaces.filter(t => t.status !== 'compliant').length;
    const fileThreats = s.scannedFiles.filter(f => f.verdict !== 'safe').length;
    const totalThreats = activeThreats + fileThreats;

    if (totalThreats >= 5) {
      recs.push({
        id: 'rec-lockdown', icon: '🔴', title: 'Emergency Lockdown Protocol',
        text: `${totalThreats} active threats — quarantine files, lock storage, enforce MFA immediately.`,
        action: 'quarantine_files', applied: false
      });
    } else if (totalThreats >= 3) {
      recs.push({
        id: 'rec-threat-review', icon: '⚠️', title: 'High-Priority Threat Review',
        text: `${totalThreats} threats detected across surfaces and files — schedule remediation within 24h.`,
        action: 'restrict_storage', applied: false
      });
    } else if (totalThreats >= 1) {
      recs.push({
        id: 'rec-threat-mitigate', icon: '🛡️', title: 'Targeted Threat Mitigation',
        text: `${totalThreats} threat(s) found — review flagged surfaces and quarantine suspicious files.`,
        action: 'quarantine_files', applied: false
      });
    }

    const noMfa = s.users.filter(u => !u.mfa);

    if (noMfa.length) {
      recs.push({
        id: 'rec-mfa', icon: '🛑', title: 'Enable MFA Globally',
        text: `Mandate MFA for ${noMfa.length} account(s).`,
        action: 'enable_mfa', applied: false
      });
    }
    const publicBuckets = s.storage.filter(b => b.public);
    if (publicBuckets.length) {
      recs.push({
        id: 'rec-storage', icon: '🔒', title: 'Restrict Exposed Storage',
        text: `Block public access on: ${publicBuckets.map(b => b.name).join(', ')}.`,
        action: 'restrict_storage', applied: false
      });
    }
    const threatFiles = s.scannedFiles.filter(f => f.verdict !== 'safe' && !f.quarantined);
    if (threatFiles.length) {
      recs.push({
        id: 'rec-quarantine', icon: '🦠', title: 'Quarantine Threat Files',
        text: `${threatFiles.length} suspicious/malicious file(s) detected — quarantine immediately.`,
        action: 'quarantine_files', applied: false
      });
    }
    this.store.patch({ recommendations: recs });
    return recs;
  }

  apply(recId) {
    return this.store.get().recommendations.find(r => r.id === recId && !r.applied) || null;
  }

  markApplied(recId) {
    const rec = this.store.get().recommendations.find(r => r.id === recId);
    if (rec) rec.applied = true;
    return rec;
  }
}
