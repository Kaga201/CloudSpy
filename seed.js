require('./config/env');
const bcrypt = require('bcryptjs');
const prisma = require('./lib/prisma');

async function main() {
  console.log('Seeding CloudSpy database...');

  // Users
  const passwordHash = await bcrypt.hash('admin123', 10);
  const contractorHash = await bcrypt.hash('contractor123', 10);

  await prisma.user.deleteMany();
  await prisma.user.createMany({
    data: [
      { email: 'security@cloudspy.com', password: passwordHash, role: 'security', mfa: true, lastLogin: BigInt(Date.now()), logins24h: 3 },
      { email: 'engineer@cloudspy.com', password: await bcrypt.hash('engineer123', 10), role: 'engineer', mfa: true, lastLogin: BigInt(Date.now() - 3600000), logins24h: 5 },
      { email: 'contractor@cloudspy.com', password: contractorHash, role: 'contractor', mfa: false, lastLogin: BigInt(Date.now() - 7200000), logins24h: 2 },
      { email: 'finance@cloudspy.com', password: await bcrypt.hash('finance123', 10), role: 'finance', mfa: false, lastLogin: BigInt(Date.now() - 86400000), logins24h: 1 },
    ],
  });
  console.log('  Users seeded');

  // Virtual Machines
  await prisma.virtualMachine.deleteMany();
  await prisma.virtualMachine.createMany({
    data: [
      { name: 'prod-web-01', cpuPercent: 78, isIdle: false, kwhMonthly: 145, costMonthly: 312, isOversized: false },
      { name: 'prod-db-01', cpuPercent: 62, isIdle: false, kwhMonthly: 210, costMonthly: 480, isOversized: false },
      { name: 'staging-app-02', cpuPercent: 4, isIdle: true, kwhMonthly: 88, costMonthly: 195, isOversized: true },
      { name: 'dev-worker-03', cpuPercent: 7, isIdle: true, kwhMonthly: 66, costMonthly: 144, isOversized: true },
      { name: 'analytics-batch', cpuPercent: 31, isIdle: false, kwhMonthly: 120, costMonthly: 265, isOversized: false },
    ],
  });
  console.log('  VMs seeded');

  // Storage Buckets
  await prisma.storageBucket.deleteMany();
  await prisma.storageBucket.createMany({
    data: [
      { name: 'cloudspy-assets', isPublic: false, isEncrypted: true },
      { name: 'cloudspy-backups', isPublic: false, isEncrypted: true },
      { name: 'project-media-public', isPublic: true, isEncrypted: false },
      { name: 'temp-uploads', isPublic: false, isEncrypted: false },
    ],
  });
  console.log('  Storage buckets seeded');

  // Threat Surfaces
  await prisma.threatSurface.deleteMany();
  const now = BigInt(Date.now());
  await prisma.threatSurface.createMany({
    data: [
      { surfaceName: 'Cloud Config Array', status: 'warning', impact: 'Configuration drift & policy violations — public bucket detected', checkedAt: now },
      { surfaceName: 'Open System Ports', status: 'critical', impact: 'External exploitation risk — Port 22, 443 exposed on staging-app-02', checkedAt: now },
      { surfaceName: 'Global IAM Matrix', status: 'critical', impact: 'Weak MFA posture — 3 users missing MFA enforcement', checkedAt: now },
      { surfaceName: 'Exposed Blob Storage', status: 'critical', impact: 'Public read access on project-media-public bucket', checkedAt: now },
    ],
  });
  console.log('  Threat surfaces seeded');

  // Workflow Phases
  await prisma.workflowPhase.deleteMany();
  await prisma.workflowPhase.createMany({
    data: [
      { phase: 1, title: 'Site Preparation', description: 'Land clearing, foundation work', requiredRole: 'engineer', status: 'completed', energyEstimate: 2400, costEstimate: 18000 },
      { phase: 2, title: 'Structural Build', description: 'Frame, walls, roof installation', requiredRole: 'engineer', status: 'active', energyEstimate: 4800, costEstimate: 62000 },
      { phase: 3, title: 'MEP Installation', description: 'Mechanical, electrical, plumbing', requiredRole: 'contractor', status: 'pending', energyEstimate: 3200, costEstimate: 41000 },
      { phase: 4, title: 'Interior Fit-Out', description: 'Finishes, fixtures, equipment', requiredRole: 'contractor', status: 'pending', energyEstimate: 1800, costEstimate: 28000 },
      { phase: 5, title: 'Commissioning', description: 'Testing, handover, sign-off', requiredRole: 'security', status: 'pending', energyEstimate: 600, costEstimate: 9000 },
    ],
  });
  console.log('  Workflow phases seeded');

  // Recommendations
  await prisma.recommendation.deleteMany();
  await prisma.recommendation.createMany({
    data: [
      { id: 'rec-mfa', icon: '🔐', title: 'Enforce MFA on all accounts', description: 'Enable multi-factor authentication for contractor and finance users', action: 'enable_mfa', isApplied: false },
      { id: 'rec-storage', icon: '🪣', title: 'Restrict public bucket access', description: 'Remove public access from project-media-public bucket', action: 'restrict_storage', isApplied: false },
      { id: 'rec-resize', icon: '📉', title: 'Right-size idle VMs', description: 'staging-app-02 and dev-worker-03 are oversized — downgrade instance tier', action: 'resize_vm', isApplied: false },
      { id: 'rec-contractor', icon: '🔒', title: 'Limit contractor access', description: 'Restrict contractor role to workflow and AI tabs only', action: 'restrict_contractor', isApplied: false },
      { id: 'rec-quarantine', icon: '🚨', title: 'Quarantine flagged files', description: 'Remove or isolate files detected as suspicious/malicious', action: 'quarantine_files', isApplied: false },
    ],
  });
  console.log('  Recommendations seeded');

  // Alerts
  await prisma.alert.deleteMany();
  await prisma.alert.createMany({
    data: [
      { id: 'alert-1', category: 'security', description: 'Public blob storage detected: project-media-public', priority: 'critical', acknowledged: false, createdAt: BigInt(Date.now() - 600000) },
      { id: 'alert-2', category: 'security', description: '3 users missing MFA — IAM posture degraded', priority: 'high', acknowledged: false, createdAt: BigInt(Date.now() - 1200000) },
      { id: 'alert-3', category: 'cost', description: 'staging-app-02 idle for >72h — estimated waste $195/mo', priority: 'medium', acknowledged: false, createdAt: BigInt(Date.now() - 3600000) },
      { id: 'alert-4', category: 'cost', description: 'dev-worker-03 idle for >48h — estimated waste $144/mo', priority: 'low', acknowledged: true, createdAt: BigInt(Date.now() - 7200000) },
    ],
  });
  console.log('  Alerts seeded');

  // Audit Logs
  await prisma.auditLog.deleteMany();
  const fmtTime = (offset) => {
    const d = new Date(Date.now() - offset);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  };
  await prisma.auditLog.createMany({
    data: [
      { timestamp: fmtTime(0), eventType: 'system', actor: 'System', resource: 'CloudSpy Backend', outcome: 'Database seeded successfully' },
      { timestamp: fmtTime(300000), eventType: 'scan', actor: 'security@cloudspy.com', resource: 'Threat Surfaces', outcome: 'Scan completed — 3 critical findings' },
      { timestamp: fmtTime(600000), eventType: 'iam', actor: 'security@cloudspy.com', resource: 'contractor@cloudspy.com', outcome: 'MFA enforcement flagged' },
      { timestamp: fmtTime(900000), eventType: 'policy', actor: 'security@cloudspy.com', resource: 'project-media-public', outcome: 'Public access flag raised' },
      { timestamp: fmtTime(1800000), eventType: 'login', actor: 'engineer@cloudspy.com', resource: 'Dashboard', outcome: 'Login successful' },
    ],
  });
  console.log('  Audit logs seeded');

  // Initial risk snapshot
  await prisma.riskSnapshot.create({ data: { score: 72 } });
  console.log('  Risk snapshot seeded');

  console.log('\nSeed complete.');
}

main()
  .catch(e => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
