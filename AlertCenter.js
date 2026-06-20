import { uid } from '../core/utils.js';

export class AlertCenter {
  constructor(store) {
    this.store = store;
  }

  _threatCount() {
    const s = this.store.get();
    return s.threatSurfaces.filter(t => t.status !== 'compliant').length
      + s.scannedFiles.filter(f => f.verdict !== 'safe').length;
  }

  rebuild() {
    const s = this.store.get();
    const prevAcked = new Set(
      s.alerts.filter(a => a.ack).map(a => `${a.cat}:${a.desc}`)
    );
    const alerts = [];

    s.threatSurfaces.filter(t => t.status === 'critical').forEach(t => {
      alerts.push(this._create('security', `${t.surface || t.surfaceName}: ${t.impact}`, 'critical', prevAcked));
    });
    s.threatSurfaces.filter(t => t.status === 'warning').forEach(t => {
      alerts.push(this._create('security', `${t.surface || t.surfaceName}: ${t.impact}`, 'medium', prevAcked));
    });
    s.scannedFiles.filter(f => f.verdict === 'malicious').forEach(f => {
      alerts.push(this._create('file', `Malicious file: ${f.name} — ${f.threats?.[0]?.message || 'threat detected'}`, 'critical', prevAcked));
    });
    s.scannedFiles.filter(f => f.verdict === 'suspicious').forEach(f => {
      alerts.push(this._create('file', `Suspicious file: ${f.name}`, 'high', prevAcked));
    });
    s.vms.filter(v => v.oversized || v.isOversized).forEach(v => {
      const cost = v.cost || v.costMonthly || 0;
      alerts.push(this._create('cost', `Oversized VM "${v.name}" — est. $${Math.round(cost * 0.4)}/mo excess`, 'medium', prevAcked));
    });
    s.users.filter(u => !u.mfa).forEach(u => {
      alerts.push(this._create('security', `User ${u.email} missing MFA enforcement`, 'high', prevAcked));
    });

    const threatLimit = Math.max(0, this._threatCount());
    s.anomalyEvents.slice(0, threatLimit).forEach(a => {
      alerts.push(this._create('anomaly', a.detail, a.severity === 'critical' ? 'critical' : a.severity === 'high' ? 'high' : 'medium', prevAcked));
    });

    this.store.patch({ alerts });
    return alerts;
  }

  _create(cat, desc, priority, prevAcked) {
    const key = `${cat}:${desc}`;
    return { id: uid(), cat, desc, priority, time: Date.now(), ack: prevAcked.has(key) };
  }

  acknowledge(alertId) {
    const alert = this.store.get().alerts.find(a => a.id === alertId);
    if (alert) alert.ack = true;
    return alert;
  }

  acknowledgeAll() {
    this.store.get().alerts.forEach(a => { a.ack = true; });
  }

  getActiveCount() {
    return this.store.get().alerts.filter(a => !a.ack).length;
  }

  getActive() {
    return this.store.get().alerts.filter(a => !a.ack);
  }
}
