import { uid, fmtDate } from '../core/utils.js';

export class AuditLogger {
  constructor(store) {
    this.store = store;
  }

  log(type, actor, resource, outcome) {
    const entry = { id: uid(), time: fmtDate(), type, actor, resource, outcome };
    const audit = this.store.get().audit;
    audit.unshift(entry);
    if (audit.length > 50) audit.pop();
    return entry;
  }

  exportCsv() {
    const header = 'Timestamp,Event Type,Actor,Resource,Outcome\n';
    const rows = this.store.get().audit
      .map(a => [a.time, a.type, a.actor, a.resource, a.outcome].join(','))
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'cloudspy-audit-' + new Date().toISOString().slice(0, 10) + '.csv';
    link.click();
  }
}
