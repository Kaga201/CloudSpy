const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

// Compute and return current risk score based on live DB state
router.get('/score', auth, allow('all'), async (req, res) => {
  const [users, buckets, files, anomalies] = await Promise.all([
    prisma.user.findMany({ select: { mfa: true } }),
    prisma.storageBucket.findMany({ select: { isPublic: true } }),
    prisma.scannedFile.findMany({ select: { verdict: true } }),
    prisma.anomalyEvent.findMany({ orderBy: { createdAt: 'desc' }, take: 10, select: { severity: true } }),
  ]);

  let score = 20;
  const mfaMissing = users.filter(u => !u.mfa).length;
  score += mfaMissing * 8;
  if (buckets.some(b => b.isPublic)) score += 20;
  const malicious = files.filter(f => f.verdict === 'malicious').length;
  const suspicious = files.filter(f => f.verdict === 'suspicious').length;
  score += malicious * 10 + suspicious * 4;
  const criticalAnomalies = anomalies.filter(a => a.severity === 'critical').length;
  score += criticalAnomalies * 5;
  score = Math.min(100, score);

  // Persist snapshot
  await prisma.riskSnapshot.create({ data: { score } });

  res.json({ score });
});

router.get('/timeline', auth, allow('all'), async (req, res) => {
  const limit = parseInt(req.query.limit || '20', 10);
  const timeline = await prisma.riskSnapshot.findMany({
    orderBy: { createdAt: 'desc' },
    take: limit,
  });
  res.json(timeline.reverse());
});

module.exports = router;
