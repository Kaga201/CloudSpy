const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('security'), async (req, res) => {
  const page = parseInt(req.query.page || '1', 10);
  const limit = parseInt(req.query.limit || '50', 10);
  const skip = (page - 1) * limit;
  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({ orderBy: { createdAt: 'desc' }, skip, take: limit }),
    prisma.auditLog.count(),
  ]);
  res.json({ logs, total, page, pages: Math.ceil(total / limit) });
});

router.post('/', auth, allow('all'), async (req, res) => {
  const { timestamp, eventType, actor, resource, outcome } = req.body;
  if (!eventType) return res.status(400).json({ error: 'eventType required' });
  const log = await prisma.auditLog.create({
    data: {
      timestamp: timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19),
      eventType,
      actor: actor || req.user.email,
      resource: resource || null,
      outcome: outcome || null,
    },
  });
  res.status(201).json(log);
});

// Bulk create audit entries (from extension sync)
router.post('/bulk', auth, allow('all'), async (req, res) => {
  const { entries } = req.body;
  if (!Array.isArray(entries)) return res.status(400).json({ error: 'entries array required' });
  const created = await prisma.auditLog.createMany({ data: entries, skipDuplicates: true });
  res.status(201).json({ created: created.count });
});

router.get('/export/csv', auth, allow('security'), async (req, res) => {
  const logs = await prisma.auditLog.findMany({ orderBy: { createdAt: 'desc' } });
  const header = 'ID,Timestamp,EventType,Actor,Resource,Outcome\n';
  const rows = logs.map(l =>
    [l.id, l.timestamp, l.eventType, l.actor || '', l.resource || '', l.outcome || '']
      .map(v => `"${String(v).replace(/"/g, '""')}"`)
      .join(',')
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="cloudspy-audit.csv"');
  res.send(header + rows);
});

module.exports = router;
