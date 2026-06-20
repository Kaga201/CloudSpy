const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('all'), async (req, res) => {
  const recs = await prisma.recommendation.findMany({ orderBy: { createdAt: 'asc' } });
  res.json(recs);
});

router.post('/:id/apply', auth, allow('security'), async (req, res) => {
  const rec = await prisma.recommendation.update({
    where: { id: req.params.id },
    data: { isApplied: true },
  });
  res.json(rec);
});

module.exports = router;
