const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('all'), async (req, res) => {
  const { category, priority, ack } = req.query;
  const where = {};
  if (category) where.category = category;
  if (priority) where.priority = priority;
  if (ack !== undefined) where.acknowledged = ack === 'true';
  const alerts = await prisma.alert.findMany({
    where,
    orderBy: [{ acknowledged: 'asc' }, { createdAt: 'desc' }],
  });
  res.json(alerts.map(a => ({ ...a, createdAt: Number(a.createdAt) })));
});

router.post('/', auth, allow('security', 'engineer'), async (req, res) => {
  const { category, description, priority } = req.body;
  if (!category || !description || !priority) {
    return res.status(400).json({ error: 'category, description, priority required' });
  }
  const alert = await prisma.alert.create({
    data: { category, description, priority, createdAt: BigInt(Date.now()) },
  });
  res.status(201).json({ ...alert, createdAt: Number(alert.createdAt) });
});

router.post('/:id/acknowledge', auth, allow('all'), async (req, res) => {
  const alert = await prisma.alert.update({
    where: { id: req.params.id },
    data: { acknowledged: true },
  });
  res.json({ ...alert, createdAt: Number(alert.createdAt) });
});

router.post('/acknowledge-all', auth, allow('all'), async (req, res) => {
  const { count } = await prisma.alert.updateMany({ data: { acknowledged: true } });
  res.json({ acknowledged: count });
});

module.exports = router;
