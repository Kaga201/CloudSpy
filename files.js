const express = require('express');
const prisma = require('../lib/prisma');
const auth = require('../middleware/auth');
const { allow } = require('../middleware/rbac');

const router = express.Router();

// Submit a batch of scanned files
router.post('/scan', auth, allow('all'), async (req, res) => {
  const { files } = req.body;
  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ error: 'files array required' });
  }
  const results = [];
  for (const f of files) {
    const created = await prisma.scannedFile.create({
      data: {
        name: f.name,
        href: f.href || null,
        url: f.url || null,
        ext: f.ext || null,
        cloudProvider: f.cloudProvider || null,
        riskScore: f.riskScore || 0,
        verdict: f.verdict || 'safe',
        scannedAt: f.scannedAt ? BigInt(f.scannedAt) : BigInt(Date.now()),
        probed: f.probed || false,
        actualType: f.actualType || null,
        magicMismatch: f.magicMismatch || null,
        contentType: f.contentType || null,
        fileSize: f.size ? BigInt(f.size) : null,
        threats: {
          create: (f.threats || []).map(t => ({
            code: t.code,
            level: t.level,
            message: t.message,
          })),
        },
      },
      include: { threats: true },
    });
    results.push(serializeFile(created));
  }
  res.status(201).json(results);
});

// Get all scanned files with their threats
router.get('/scanned', auth, allow('all'), async (req, res) => {
  const limit = parseInt(req.query.limit || '100', 10);
  const files = await prisma.scannedFile.findMany({
    include: { threats: true },
    orderBy: { createdAt: 'desc' },
    take: limit,
  });
  res.json(files.map(serializeFile));
});

router.get('/:id', auth, allow('all'), async (req, res) => {
  const file = await prisma.scannedFile.findUnique({
    where: { id: req.params.id },
    include: { threats: true },
  });
  if (!file) return res.status(404).json({ error: 'Not found' });
  res.json(serializeFile(file));
});

function serializeFile(f) {
  return {
    ...f,
    scannedAt: f.scannedAt ? Number(f.scannedAt) : null,
    fileSize: f.fileSize ? Number(f.fileSize) : null,
  };
}

module.exports = router;
