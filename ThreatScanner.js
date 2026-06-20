export class ThreatScanner {
  constructor(store, pageIntel = null) {
    this.store = store;
    this.pageIntel = pageIntel;
  }

  scan() {
    const s = this.store.get();
    const openPorts = s.vms.some(v => (v.name || '').includes('staging')) ? 'Port 22, 443 exposed' : 'Closed';
    const weakIam = s.users.filter(u => !u.mfa).length;
    const exposedStorage = s.storage.filter(b => b.public || b.isPublic).length;

    return [
      {
        id: 'ts1', surface: 'Cloud Config Array',
        status: exposedStorage === 0 && weakIam === 0 ? 'compliant' : 'warning',
        impact: 'Configuration drift & policy violations',
        checked: Date.now()
      },
      {
        id: 'ts2', surface: 'Open System Ports',
        status: openPorts !== 'Closed' ? 'critical' : 'compliant',
        impact: openPorts !== 'Closed' ? `External exploitation risk via ${openPorts}` : 'No open attack surface',
        checked: Date.now()
      },
      {
        id: 'ts3', surface: 'Global IAM Matrix',
        status: weakIam > 0 ? 'warning' : 'compliant',
        impact: weakIam > 0 ? `${weakIam} accounts with weak MFA posture` : 'All identities hardened',
        checked: Date.now()
      },
      {
        id: 'ts4', surface: 'Exposed Blob Storage',
        status: exposedStorage > 0 ? 'critical' : 'compliant',
        impact: exposedStorage > 0 ? `${exposedStorage} bucket(s) with public read access` : 'Storage access controlled',
        checked: Date.now()
      }
    ];
  }

  refresh() {
    const base = this.scan();
    const surfaces = this.pageIntel ? this.pageIntel.getThreatSurfaces(base) : base;
    this.store.patch({ threatSurfaces: surfaces });
    return this.store.get().threatSurfaces;
  }

  getFindingsCount() {
    return this.store.get().threatSurfaces.filter(t => t.status !== 'compliant').length;
  }
}
