const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

// Full state snapshot for extension initialization
router.get('/', auth, allow('all'), async (req, res) => {
  const [users, vms, buckets, threatSurfaces, alerts, anomalies, recommendations, workflow, files, riskSnapshot] =
    await Promise.all([
      prisma.user.findMany({ select: { id: true, email: true, role: true, mfa: true, lastLogin: true, logins24h: true } }),
      prisma.virtualMachine.findMany(),
      prisma.storageBucket.findMany(),
      prisma.threatSurface.findMany(),
      prisma.alert.findMany({ orderBy: [{ acknowledged: 'asc' }, { createdAt: 'desc' }], take: 50 }),
      prisma.anomalyEvent.findMany({ orderBy: { createdAt: 'desc' }, take: 15 }),
      prisma.recommendation.findMany({ orderBy: { createdAt: 'asc' } }),
      prisma.workflowPhase.findMany({ orderBy: { phase: 'asc' } }),
      prisma.scannedFile.findMany({ include: { threats: true }, orderBy: { createdAt: 'desc' }, take: 50 }),
      prisma.riskSnapshot.findFirst({ orderBy: { createdAt: 'desc' } }),
    ]);

  res.json({
    users: users.map(u => ({ ...u, lastLogin: u.lastLogin ? Number(u.lastLogin) : null })),
    vms,
    storage: buckets,
    threatSurfaces: threatSurfaces.map(s => ({ ...s, checkedAt: s.checkedAt ? Number(s.checkedAt) : null })),
    alerts: alerts.map(a => ({ ...a, createdAt: Number(a.createdAt) })),
    anomalyEvents: anomalies.map(e => ({ ...e, detectedAt: e.detectedAt ? Number(e.detectedAt) : null })),
    recommendations,
    workflow,
    scannedFiles: files.map(f => ({
      ...f,
      scannedAt: f.scannedAt ? Number(f.scannedAt) : null,
      fileSize: f.fileSize ? Number(f.fileSize) : null,
    })),
    riskScore: riskSnapshot ? riskSnapshot.score : 20,
  });
});

// Sync telemetry from extension (audit logs, anomalies, etc.)
router.post('/sync', auth, allow('all'), async (req, res) => {
  const { auditEntries = [], anomalyEntries = [], alertEntries = [] } = req.body;

  const ops = [];

  if (auditEntries.length > 0) {
    ops.push(prisma.auditLog.createMany({
      data: auditEntries.map(e => ({
        id: e.id,
        timestamp: e.time || new Date().toISOString().replace('T', ' ').slice(0, 19),
        eventType: e.type,
        actor: e.actor || req.user.email,
        resource: e.resource || null,
        outcome: e.outcome || null,
      })),
      skipDuplicates: true,
    }));
  }

  if (anomalyEntries.length > 0) {
    ops.push(prisma.anomalyEvent.createMany({
      data: anomalyEntries.map(e => ({
        id: e.id,
        type: e.type,
        detail: e.detail,
        severity: e.severity || 'medium',
        detectedAt: e.timestamp ? BigInt(e.timestamp) : null,
      })),
      skipDuplicates: true,
    }));
  }

  if (alertEntries.length > 0) {
    ops.push(prisma.alert.createMany({
      data: alertEntries.map(a => ({
        id: a.id,
        category: a.cat,
        description: a.desc,
        priority: a.priority,
        acknowledged: a.ack || false,
        createdAt: BigInt(a.time || Date.now()),
      })),
      skipDuplicates: true,
    }));
  }

  await Promise.all(ops);
  res.json({ ok: true });
});

module.exports = router;
