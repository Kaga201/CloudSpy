const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('all'), async (req, res) => {
  const limit = parseInt(req.query.limit || '50', 10);
  const events = await prisma.anomalyEvent.findMany({
    orderBy: { createdAt: 'desc' },
    take: limit,
  });
  res.json(events.map(e => ({ ...e, detectedAt: e.detectedAt ? Number(e.detectedAt) : null })));
});

router.post('/', auth, allow('security', 'engineer'), async (req, res) => {
  const { type, detail, severity } = req.body;
  if (!type || !detail) return res.status(400).json({ error: 'type and detail required' });
  const event = await prisma.anomalyEvent.create({
    data: { type, detail, severity: severity || 'medium', detectedAt: BigInt(Date.now()) },
  });
  res.status(201).json({ ...event, detectedAt: event.detectedAt ? Number(event.detectedAt) : null });
});

module.exports = router;
