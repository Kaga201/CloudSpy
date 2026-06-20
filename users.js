const express = require('express');
const bcrypt = require('bcryptjs');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

router.get('/', auth, allow('all'), async (req, res) => {
  const users = await prisma.user.findMany({
    select: { id: true, email: true, role: true, mfa: true, lastLogin: true, logins24h: true },
    orderBy: { email: 'asc' },
  });
  res.json(users);
});

router.post('/', auth, allow('security'), async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const hash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { email, password: hash, role: role || 'engineer' },
    select: { id: true, email: true, role: true, mfa: true },
  });
  res.status(201).json(user);
});

router.get('/:id', auth, allow('all'), async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.params.id },
    select: { id: true, email: true, role: true, mfa: true, lastLogin: true, logins24h: true },
  });
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

router.patch('/:id', auth, allow('security'), async (req, res) => {
  const { role, mfa } = req.body;
  const data = {};
  if (role !== undefined) data.role = role;
  if (mfa !== undefined) data.mfa = mfa;
  const user = await prisma.user.update({
    where: { id: req.params.id },
    data,
    select: { id: true, email: true, role: true, mfa: true },
  });
  res.json(user);
});

router.post('/:id/mfa', auth, allow('security'), async (req, res) => {
  const user = await prisma.user.update({
    where: { id: req.params.id },
    data: { mfa: true },
    select: { id: true, email: true, mfa: true },
  });
  res.json(user);
});

module.exports = router;
