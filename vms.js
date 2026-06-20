const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('all'), async (req, res) => {
  const vms = await prisma.virtualMachine.findMany({ orderBy: { name: 'asc' } });
  res.json(vms);
});

router.post('/', auth, allow('security'), async (req, res) => {
  const { name, cpuPercent, isIdle, kwhMonthly, costMonthly, isOversized } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const vm = await prisma.virtualMachine.create({
    data: { name, cpuPercent: cpuPercent || 0, isIdle: isIdle || false, kwhMonthly: kwhMonthly || 0, costMonthly: costMonthly || 0, isOversized: isOversized || false },
  });
  res.status(201).json(vm);
});

router.get('/:id', auth, allow('all'), async (req, res) => {
  const vm = await prisma.virtualMachine.findUnique({ where: { id: req.params.id } });
  if (!vm) return res.status(404).json({ error: 'Not found' });
  res.json(vm);
});

router.patch('/:id', auth, allow('security'), async (req, res) => {
  const { name, cpuPercent, isIdle, kwhMonthly, costMonthly, isOversized } = req.body;
  const vm = await prisma.virtualMachine.update({
    where: { id: req.params.id },
    data: { name, cpuPercent, isIdle, kwhMonthly, costMonthly, isOversized },
  });
  res.json(vm);
});

router.delete('/:id', auth, allow('security'), async (req, res) => {
  await prisma.virtualMachine.delete({ where: { id: req.params.id } });
  res.status(204).end();
});

module.exports = router;
