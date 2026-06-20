const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('all'), async (req, res) => {
  const surfaces = await prisma.threatSurface.findMany({ orderBy: { surfaceName: 'asc' } });
  res.json(surfaces.map(s => ({ ...s, checkedAt: s.checkedAt ? Number(s.checkedAt) : null })));
});

// Re-evaluate threat surfaces based on current DB state
router.post('/refresh', auth, allow('security', 'engineer'), async (req, res) => {
  const [users, vms, buckets] = await Promise.all([
    prisma.user.findMany({ select: { mfa: true } }),
    prisma.virtualMachine.findMany({ select: { name: true } }),
    prisma.storageBucket.findMany({ select: { isPublic: true } }),
  ]);

  const mfaMissing = users.filter(u => !u.mfa).length;
  const hasPublicBucket = buckets.some(b => b.isPublic);
  const hasStagingVm = vms.some(v => v.name.toLowerCase().includes('staging'));
  const now = BigInt(Date.now());

  const surfaces = [
    {
      surfaceName: 'Cloud Config Array',
      status: hasPublicBucket || mfaMissing > 0 ? 'warning' : 'compliant',
      impact: 'Configuration drift & policy violations',
      checkedAt: now,
    },
    {
      surfaceName: 'Open System Ports',
      status: hasStagingVm ? 'critical' : 'compliant',
      impact: 'External exploitation risk (Port 22, 443 exposed)',
      checkedAt: now,
    },
    {
      surfaceName: 'Global IAM Matrix',
      status: mfaMissing >= 2 ? 'critical' : mfaMissing === 1 ? 'warning' : 'compliant',
      impact: `Weak MFA posture — ${mfaMissing} user(s) missing MFA`,
      checkedAt: now,
    },
    {
      surfaceName: 'Exposed Blob Storage',
      status: hasPublicBucket ? 'critical' : 'compliant',
      impact: 'Public read access on cloud storage bucket',
      checkedAt: now,
    },
  ];

  await prisma.threatSurface.deleteMany();
  const created = await Promise.all(surfaces.map(s => prisma.threatSurface.create({ data: s })));
  res.json(created.map(s => ({ ...s, checkedAt: s.checkedAt ? Number(s.checkedAt) : null })));
});

router.get('/:id', auth, allow('all'), async (req, res) => {
  const surface = await prisma.threatSurface.findUnique({ where: { id: req.params.id } });
  if (!surface) return res.status(404).json({ error: 'Not found' });
  res.json({ ...surface, checkedAt: surface.checkedAt ? Number(surface.checkedAt) : null });
});

module.exports = router;
