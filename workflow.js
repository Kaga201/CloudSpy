const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/phases', auth, allow('all'), async (req, res) => {
  const phases = await prisma.workflowPhase.findMany({ orderBy: { phase: 'asc' } });
  res.json(phases);
});

router.patch('/phases/:phase', auth, allow('security', 'engineer', 'contractor'), async (req, res) => {
  const phase = parseInt(req.params.phase, 10);
  const { status, energyEstimate, costEstimate } = req.body;
  const updated = await prisma.workflowPhase.update({
    where: { phase },
    data: { status, energyEstimate, costEstimate },
  });
  res.json(updated);
});

module.exports = router;
