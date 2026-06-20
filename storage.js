const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('all'), async (req, res) => {
  const buckets = await prisma.storageBucket.findMany({ orderBy: { name: 'asc' } });
  res.json(buckets);
});

router.post('/', auth, allow('security'), async (req, res) => {
  const { name, isPublic, isEncrypted } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const bucket = await prisma.storageBucket.create({
    data: { name, isPublic: isPublic || false, isEncrypted: isEncrypted !== false },
  });
  res.status(201).json(bucket);
});

router.get('/:id', auth, allow('all'), async (req, res) => {
  const bucket = await prisma.storageBucket.findUnique({ where: { id: req.params.id } });
  if (!bucket) return res.status(404).json({ error: 'Not found' });
  res.json(bucket);
});

router.patch('/:id', auth, allow('security'), async (req, res) => {
  const { isPublic, isEncrypted } = req.body;
  const bucket = await prisma.storageBucket.update({
    where: { id: req.params.id },
    data: { isPublic, isEncrypted },
  });
  res.json(bucket);
});

module.exports = router;
