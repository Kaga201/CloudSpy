import { uid } from '../core/utils.js';

export class PageIntel {
  constructor(store, fileScanner) {
    this.store = store;
    this.fileScanner = fileScanner;
    this.latestScan = null;
  }

  ingest(scan) {
    if (!scan) return;
    this.latestScan = scan;
    const s = this.store.get();
    s.pageScan = scan;

    const rawFiles = scan.pageFiles || scan.constructionFiles || [];
    const metas = rawFiles.map(f => ({
      name: f.name,
      ext: f.ext,
      href: f.href || f.url,
      source: f.source || 'page',
      cloudProvider: f.cloudProvider || this.fileScanner.detectCloudProvider(f.href || ''),
      probed: f.probed,
      actualType: f.actualType,
      magicMismatch: f.magicMismatch,
      contentType: f.contentType,
      fileSize: f.size ? parseInt(f.size) : undefined
    }));

    if (metas.length) {
      s.scannedFiles = this.fileScanner.scanAll(metas);
    }

    if (scan.findings?.length) {
      const critical = scan.findings.filter(f => f.level === 'critical' || f.level === 'high').length;
      if (critical) s.anomaliesDetected += critical;
    }

    const stats = s.webDataStats;
    const pageWeight = scan.pageWeight || 0;
    const fileBytes = scan.totalFileSize || 0;
    const filesProbed = scan.filesProbed || rawFiles.filter(f => f.probed).length;

    stats.totalBytesScanned += pageWeight + fileBytes;
    stats.totalLinksFound += rawFiles.length;
    stats.totalFilesProbed += filesProbed;
    stats.totalPagesScanned += 1;
    stats.history.unshift({
      hostname: scan.hostname,
      links: rawFiles.length,
      pageWeight,
      fileBytes,
      filesProbed,
      scannedAt: scan.scannedAt || Date.now()
    });
    if (stats.history.length > 20) stats.history = stats.history.slice(0, 20);
  }

  getThreatSurfaces(baseSurfaces) {
    const scan = this.latestScan || this.store.get().pageScan;
    if (!scan) return baseSurfaces;

    const extra = [];

    if (!scan.isHttps) {
      extra.push({
        id: 'page-http', surface: 'Browser Tab — Transport Security',
        status: 'critical', impact: `Unencrypted HTTP page: ${scan.hostname}`, checked: scan.scannedAt || Date.now()
      });
    }

    const malicious = this.store.get().scannedFiles.filter(f => f.verdict === 'malicious');
    if (malicious.length) {
      extra.push({
        id: 'page-files-mal', surface: 'Browser Tab — Malicious Files',
        status: 'critical', impact: `${malicious.length} malicious file(s) on page`, checked: Date.now()
      });
    }

    const suspicious = this.store.get().scannedFiles.filter(f => f.verdict === 'suspicious');
    if (suspicious.length) {
      extra.push({
        id: 'page-files-susp', surface: 'Browser Tab — Suspicious Files',
        status: 'warning', impact: `${suspicious.length} suspicious file(s) require review`, checked: Date.now()
      });
    }

    const fileCount = scan.pageFiles?.length || 0;
    if (fileCount && !malicious.length && !suspicious.length) {
      extra.push({
        id: 'page-files-ok', surface: 'Browser Tab — File Scan',
        status: 'compliant', impact: `${fileCount} file(s) scanned — no threats`, checked: scan.scannedAt || Date.now()
      });
    }

    const mixed = scan.findings?.filter(f => f.code?.startsWith('MIXED'));
    if (mixed?.length) {
      extra.push({
        id: 'page-mixed', surface: 'Browser Tab — Mixed Content',
        status: 'warning', impact: `${mixed.length} mixed HTTP/HTTPS issue(s)`, checked: scan.scannedAt || Date.now()
      });
    }

    return [...extra, ...baseSurfaces.filter(t => !t.id?.startsWith('page-'))];
  }
}
