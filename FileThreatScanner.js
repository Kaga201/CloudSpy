import { uid } from '../core/utils.js';

const EXECUTABLE_EXT = new Set(['exe', 'bat', 'cmd', 'com', 'scr', 'msi', 'dll', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'ps1', 'hta', 'apk', 'app']);
const MACRO_EXT = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm']);
const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'tar', 'gz', 'iso']);
const CLOUD_HOSTS = ['onedrive.live.com', '1drv.ms', 'sharepoint.com', 'drive.google.com', 'docs.google.com', 'dropbox.com', 'box.com', 'icloud.com'];

const MAGIC = {
  exe: [0x4d, 0x5a],
  pdf: [0x25, 0x50, 0x44, 0x46],
  zip: [0x50, 0x4b]
};

export class FileThreatScanner {
  constructor(store) {
    this.store = store;
  }

  analyze(meta) {
    const threats = [];
    const name = (meta.name || '').toLowerCase();
    const url = (meta.href || meta.url || '').toLowerCase();
    const ext = this._ext(name) || meta.ext || this._ext(url);

    if (this._doubleExtension(name)) {
      threats.push({ code: 'DOUBLE_EXT', level: 'critical', message: 'Double extension disguise detected' });
    }
    if (ext && EXECUTABLE_EXT.has(ext)) {
      threats.push({ code: 'EXECUTABLE', level: 'critical', message: `Executable file type (.${ext})` });
    }
    if (ext && MACRO_EXT.has(ext)) {
      threats.push({ code: 'MACRO', level: 'high', message: `Macro-enabled document (.${ext})` });
    }
    if (url.startsWith('http://') && ext && EXECUTABLE_EXT.has(ext)) {
      threats.push({ code: 'HTTP_DOWNLOAD', level: 'critical', message: 'Executable served over unencrypted HTTP' });
    }
    if (name.includes('password') || name.includes('credential') || name.includes('secret')) {
      threats.push({ code: 'SENSITIVE_NAME', level: 'medium', message: 'Filename suggests sensitive credentials' });
    }
    if (/^[a-f0-9]{32,}\./i.test(name)) {
      threats.push({ code: 'RANDOM_NAME', level: 'medium', message: 'Suspicious random hash filename' });
    }
    if (meta.cloudProvider) {
      threats.push({ code: 'CLOUD_FILE', level: 'low', message: `Cloud-hosted file (${meta.cloudProvider})` });
    }
    if (meta.magicMismatch) {
      threats.push({ code: 'MAGIC_MISMATCH', level: 'critical', message: meta.magicMismatch });
    }
    if (meta.probed && meta.actualType && ext && meta.actualType !== ext) {
      threats.push({ code: 'TYPE_SPOOF', level: 'critical', message: `File masquerading as .${ext} but is .${meta.actualType}` });
    }

    const riskScore = threats.reduce((s, t) => {
      if (t.level === 'critical') return s + 40;
      if (t.level === 'high') return s + 25;
      if (t.level === 'medium') return s + 10;
      return s + 3;
    }, 0);

    const verdict = riskScore >= 40 ? 'malicious' : riskScore >= 15 ? 'suspicious' : 'safe';

    return { ...meta, id: meta.id || uid(), ext, threats, riskScore, verdict, scannedAt: Date.now() };
  }

  scanAll(fileMetas) {
    const results = fileMetas.map(f => this.analyze(f));
    this.store.patch({ scannedFiles: results });
    return results;
  }

  mergeProbeResult(file, probe) {
    return this.analyze({ ...file, ...probe });
  }

  detectCloudProvider(url) {
    try {
      const host = new URL(url).hostname.replace(/^www\./, '');
      if (host.includes('onedrive') || host === '1drv.ms') return 'OneDrive';
      if (host.includes('sharepoint')) return 'SharePoint';
      if (host.includes('drive.google') || host.includes('docs.google')) return 'Google Drive';
      if (host.includes('dropbox')) return 'Dropbox';
      if (host.includes('box.com')) return 'Box';
      return CLOUD_HOSTS.some(h => host.includes(h.split('.')[0])) ? host : null;
    } catch {
      return null;
    }
  }

  static probeBytes(bytes) {
    if (!bytes || bytes.length < 4) return null;
    if (bytes[0] === MAGIC.exe[0] && bytes[1] === MAGIC.exe[1]) return 'exe';
    if (bytes[0] === MAGIC.pdf[0] && bytes[1] === MAGIC.pdf[1]) return 'pdf';
    if (bytes[0] === MAGIC.zip[0] && bytes[1] === MAGIC.zip[1]) return 'zip';
    return null;
  }

  _ext(name) {
    const m = name.match(/\.([a-z0-9]{1,8})(?:\?|$)/i);
    return m ? m[1].toLowerCase() : null;
  }

  _doubleExtension(name) {
    return /\.(pdf|doc|docx|jpg|png|txt|xlsx)\.(exe|js|bat|cmd|scr|msi|vbs|ps1)$/i.test(name);
  }

  getThreatCount() {
    return this.store.get().scannedFiles.filter(f => f.verdict !== 'safe').length;
  }
}
