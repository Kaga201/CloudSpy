const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');
const gemini = require('../services/gemini');

const router = express.Router();

router.post('/chat', auth, allow('all'), async (req, res) => {
  const { userMessage, history = [] } = req.body;
  if (!userMessage) return res.status(400).json({ error: 'userMessage required' });

  // Gather live telemetry for system instruction
  const [users, buckets, files, anomalies, threats] = await Promise.all([
    prisma.user.findMany({ select: { mfa: true } }),
    prisma.storageBucket.findMany({ select: { isPublic: true } }),
    prisma.scannedFile.findMany({ select: { verdict: true } }),
    prisma.anomalyEvent.findMany({ orderBy: { createdAt: 'desc' }, take: 5, select: { type: true, severity: true } }),
    prisma.threatSurface.findMany({ select: { surfaceName: true, status: true } }),
  ]);

  const mfaOk = users.filter(u => u.mfa).length;
  const mfaMissing = users.length - mfaOk;
  const flagged = files.filter(f => f.verdict !== 'safe').length;
  const criticalThreats = threats.filter(t => t.status === 'critical').map(t => t.surfaceName);

  let riskScore = 20 + mfaMissing * 8;
  if (buckets.some(b => b.isPublic)) riskScore += 20;
  riskScore = Math.min(100, riskScore);

  const systemInstruction = `You are CloudSpy AI, the in-app security assistant for a cloud security monitoring console.
Answer concisely (2–5 sentences unless a list is clearer). Use the live telemetry below when relevant. Do not invent data not given.

Live telemetry:
- Risk score: ${riskScore}/100
- Active critical threats: ${criticalThreats.join(', ') || 'none'}
- Files scanned: ${files.length} (${flagged} flagged suspicious/malicious)
- Recent anomalies: ${anomalies.map(a => `${a.type}(${a.severity})`).join(', ') || 'none'}
- IAM: ${users.length} users, ${mfaOk} with MFA, ${mfaMissing} missing MFA
- Public storage buckets: ${buckets.filter(b => b.isPublic).length}`;

  const result = await gemini.generate({ systemInstruction, history, userMessage });

  // Persist both turns
  await prisma.chatMessage.createMany({
    data: [
      { role: 'user', message: userMessage, source: 'local' },
      { role: 'assistant', message: result.ok ? result.text : result.error, source: 'gemini' },
    ],
  });

  res.json(result);
});

router.get('/chat/history', auth, allow('all'), async (req, res) => {
  const limit = parseInt(req.query.limit || '50', 10);
  const messages = await prisma.chatMessage.findMany({
    orderBy: { createdAt: 'asc' },
    take: limit,
  });
  res.json(messages);
});

module.exports = router;
