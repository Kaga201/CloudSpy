import { uid } from './utils.js';

export class StateStore {
  constructor() {
    this.data = this._createInitialState();
  }

  get() {
    return this.data;
  }

  patch(partial) {
    Object.assign(this.data, partial);
  }

  _createInitialState() {
    return {
      startTime: Date.now(),
      role: 'security',
      scanning: false,
      scanCount: 0,
      lastScanDurationMs: 0,
      anomaliesDetected: 0,
      lastSync: null,
      riskScore: 68,
      totalSavings: 0,
      pageScan: null,
      scannedFiles: [],
      chatHistory: [],
      anomalyEvents: [],
      users: [
        { id: 'u1', email: 'nazri@firm.internal', role: 'engineer', mfa: true, lastLogin: Date.now() - 3600000, logins24h: 4 },
        { id: 'u2', email: 'vendor.sub@ext-link.net', role: 'contractor', mfa: false, lastLogin: Date.now() - 7200000, logins24h: 2 },
        { id: 'u3', email: 'accounts-billing@firm.internal', role: 'finance', mfa: true, lastLogin: Date.now() - 1800000, logins24h: 6 },
        { id: 'u4', email: 'bim.lead@firm.internal', role: 'engineer', mfa: true, lastLogin: Date.now() - 900000, logins24h: 8 },
        { id: 'u5', email: 'temp.cad@contractor.io', role: 'contractor', mfa: false, lastLogin: Date.now() - 86400000, logins24h: 1 }
      ],
      vms: [
        { id: 'vm1', name: 'compute-node-bim-render-01', cpu: 3, idle: true, kwh: 420, cost: 380 },
        { id: 'vm2', name: 'compute-node-data-store-02', cpu: 45, idle: false, kwh: 180, cost: 220 },
        { id: 'vm3', name: 'vm-workspace-unassigned-cad', cpu: 8, idle: true, kwh: 310, cost: 420, oversized: true },
        { id: 'vm4', name: 'staging-api-gateway-03', cpu: 22, idle: false, kwh: 95, cost: 110 },
        { id: 'vm5', name: 'abandoned-staging-db-cluster', cpu: 1, idle: true, kwh: 520, cost: 1000 }
      ],
      storage: [
        { id: 's1', name: 'proj-blueprints-prod', public: false, encrypted: true },
        { id: 's2', name: 'tender-docs-leaked-bucket', public: true, encrypted: false },
        { id: 's3', name: 'bim-archive-internal', public: false, encrypted: true }
      ],
      workflow: [
        { phase: 1, title: 'BIM Structural Phase Mapping', desc: 'Planning & Engineering — LOD 300 models under review', role: 'engineer', status: 'active', energy: 85, cost: 4200 },
        { phase: 2, title: 'Engineering Verification', desc: 'Clash detection & structural sign-off in progress', role: 'engineer', status: 'pending', energy: 60, cost: 2800 },
        { phase: 3, title: 'Contractor Handoff', desc: 'Contractor verification handshake pending MFA gate', role: 'contractor', status: 'pending', energy: 40, cost: 1500 },
        { phase: 4, title: 'Tender & Procurement', desc: 'Commercial docs sealed — finance review queue', role: 'finance', status: 'pending', energy: 25, cost: 900 },
        { phase: 5, title: 'Construction Execution', desc: 'Field deployment & IoT sensor integration', role: 'engineer', status: 'pending', energy: 70, cost: 6100 }
      ],
      webDataStats: {
        totalBytesScanned: 0,
        totalLinksFound: 0,
        totalFilesProbed: 0,
        totalPagesScanned: 0,
        history: []
      },
      threatSurfaces: [],
      alerts: [],
      audit: [],
      recommendations: [],
      logs: [],
      riskTimeline: [],
      appliedActions: new Set()
    };
  }
}
