export function uid() {
  return Math.random().toString(36).slice(2, 10);
}

export function fmtTime(d = new Date()) {
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

export function fmtDate(d = new Date()) {
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

export function fmtMoney(n) {
  return '$' + n.toLocaleString('en-US', { maximumFractionDigits: 0 });
}

export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function tagClass(status) {
  if (status === 'critical' || status === 'high') return 'tag-red';
  if (status === 'warning' || status === 'medium') return 'tag-amber';
  if (status === 'compliant' || status === 'low' || status === 'success') return 'tag-green';
  return 'tag-blue';
}

export function fmtBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function statusLabel(s) {
  const map = {
    critical: 'CRITICAL', warning: 'WARNING', compliant: 'Compliant',
    high: 'HIGH', medium: 'MEDIUM', low: 'LOW'
  };
  return map[s] || s;
}
