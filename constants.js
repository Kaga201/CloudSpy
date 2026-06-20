export const ROLES = {
  security: { chip: 'HQ', name: 'Security Lead', label: 'ROLE: SECURITY LEAD' },
  engineer: { chip: 'EN', name: 'Site Engineer', label: 'ROLE: ENGINEER' },
  contractor: { chip: 'CT', name: 'Contractor', label: 'ROLE: CONTRACTOR' },
  finance: { chip: 'FN', name: 'Finance Analyst', label: 'ROLE: FINANCE' }
};

export const VIEW_ACCESS = {
  'view-overview': ['all'],
  'view-threat': ['all', 'security'],
  'view-iam': ['all', 'security'],
  'view-monitoring': ['all', 'security'],
  'view-alerts': ['all', 'security', 'engineer', 'finance'],
  'view-ai': ['all', 'security', 'engineer', 'contractor', 'finance'],
  'view-scanhistory': ['all', 'security'],
  'view-webdata': ['all'],
};

export const MONITOR_INTERVAL_MS = 4000;
export const SYNC_INTERVAL_MS = 15000;
