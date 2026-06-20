const FILE_GROUPS = [
  { name: 'Executables', exts: ['exe','bat','cmd','com','msi','scr','ps1','hta','vbs'], baseStatus: 'crit' },
  { name: 'Macro Docs',  exts: ['docm','xlsm','pptm','dotm','xltm'],                   baseStatus: 'crit' },
  { name: 'Archives',    exts: ['zip','rar','7z','tar','gz','iso'],                      baseStatus: 'warn' },
  { name: 'Documents',   exts: ['pdf','docx','doc','xlsx','xls','pptx','csv','txt','odt'], baseStatus: 'healthy' },
  { name: 'Media',       exts: ['jpg','jpeg','png','gif','mp4','mp3','svg','webp'],      baseStatus: 'healthy' }
];

export class WorkflowMapper {
  constructor(store) {
    this.store = store;
  }

  getPhases() {
    return this.store.get().workflow;
  }

  _fmtBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024, sizes = ['B','KB','MB','GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  getDigitalTwinNodes() {
    const s = this.store.get();
    const nodes = [];

    // 1. Pages actually visited & scanned by the extension
    const history = s.webDataStats?.history || [];
    const seenHosts = new Set();
    history.slice(0, 8).forEach(h => {
      if (seenHosts.has(h.hostname)) return;
      seenHosts.add(h.hostname);
      const pageFiles = s.scannedFiles.filter(f => {
        try { return new URL(f.href || f.url || '').hostname === h.hostname; } catch { return false; }
      });
      const malicious = pageFiles.filter(f => f.verdict === 'malicious').length;
      const suspicious = pageFiles.filter(f => f.verdict === 'suspicious').length;
      nodes.push({
        name: h.hostname,
        category: 'Page',
        status: malicious > 0 ? 'crit' : suspicious > 0 ? 'warn' : 'healthy',
        detail: `${h.links} links · ${this._fmtBytes(h.pageWeight)}${malicious ? ` · ${malicious} malicious` : suspicious ? ` · ${suspicious} suspicious` : ' · clean'}`
      });
    });

    // 2. Cloud providers found across all scanned files
    const providerMap = {};
    s.scannedFiles.forEach(f => {
      if (!f.cloudProvider) return;
      if (!providerMap[f.cloudProvider]) providerMap[f.cloudProvider] = { total: 0, threats: 0 };
      providerMap[f.cloudProvider].total++;
      if (f.verdict !== 'safe') providerMap[f.cloudProvider].threats++;
    });
    Object.entries(providerMap).forEach(([name, p]) => {
      nodes.push({
        name,
        category: 'Cloud',
        status: p.threats > 0 ? 'crit' : 'healthy',
        detail: `${p.total} file(s) · ${p.threats} threat(s)`
      });
    });

    // 3. File type clusters from real scanned files
    FILE_GROUPS.forEach(g => {
      const matches = s.scannedFiles.filter(f => g.exts.includes((f.ext || '').toLowerCase()));
      if (!matches.length) return;
      const threats = matches.filter(f => f.verdict !== 'safe').length;
      nodes.push({
        name: `${g.name} (${matches.length})`,
        category: 'Files',
        status: threats > 0 ? (g.baseStatus === 'crit' ? 'crit' : 'warn') : g.baseStatus,
        detail: `${matches.length} file(s)${threats ? ` · ${threats} threat(s)` : ' · clean'}`
      });
    });

    // 4. Active threat surfaces from real ThreatScanner
    s.threatSurfaces.filter(t => t.status !== 'compliant').forEach(t => {
      nodes.push({
        name: (t.surfaceName || t.surface || 'Surface').replace(/^Browser Tab — /, ''),
        category: 'Threat',
        status: t.status === 'critical' ? 'crit' : 'warn',
        detail: t.impact?.slice(0, 50) || t.status
      });
    });

    // 5. IAM — real when backend is connected
    const users = s.users || [];
    if (users.length) {
      const noMfa = users.filter(u => !u.mfa).length;
      nodes.push({
        name: `Identity (${users.length})`,
        category: 'IAM',
        status: noMfa > 2 ? 'crit' : noMfa > 0 ? 'warn' : 'healthy',
        detail: noMfa ? `${noMfa} accounts missing MFA` : 'All MFA enforced'
      });
    }

    // 6. Storage buckets — real when backend is connected
    (s.storage || []).forEach(b => {
      const pub = b.public || b.isPublic;
      const enc = b.encrypted || b.isEncrypted;
      nodes.push({
        name: b.name,
        category: 'Storage',
        status: pub ? 'crit' : !enc ? 'warn' : 'healthy',
        detail: pub ? 'Public — exposed' : enc ? 'Private · Encrypted' : 'Private · Unencrypted'
      });
    });

    if (!nodes.length) {
      nodes.push({ name: 'Awaiting scan', category: 'System', status: 'warn', detail: 'Browse a page or click Execute Scan' });
    }

    return nodes;
  }
}
