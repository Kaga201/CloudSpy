const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('../lib/prisma');
const { JWT_SECRET } = require('../config/env');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

router.post('/login', async (req, res, next) => {
  try {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const now = Date.now();
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLogin: now, logins24h: { increment: 1 } },
  });
  const token = jwt.sign(
    { userId: user.id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
  res.json({ token, role: user.role, email: user.email });
  } catch (err) { next(err); }
});

router.get('/me', authMiddleware, async (req, res, next) => {
  try {
  const user = await prisma.user.findUnique({
    where: { id: req.user.userId },
    select: { id: true, email: true, role: true, mfa: true, lastLogin: true, logins24h: true },
  });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    ...user,
    lastLogin: user.lastLogin ? Number(user.lastLogin) : null,
  });
  } catch (err) { next(err); }
});

module.exports = router;
