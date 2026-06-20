require('./config/env');
const express = require('express');
const cors = require('cors');
const { PORT } = require('./config/env');

const app = express();

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.options('*', cors());
app.use(express.json({ limit: '2mb' }));

app.use('/api/v1/auth', require('./routes/auth'));
app.use('/api/v1/users', require('./routes/users'));
app.use('/api/v1/vms', require('./routes/vms'));
app.use('/api/v1/storage', require('./routes/storage'));
app.use('/api/v1/files', require('./routes/files'));
app.use('/api/v1/threats', require('./routes/threats'));
app.use('/api/v1/alerts', require('./routes/alerts'));
app.use('/api/v1/anomalies', require('./routes/anomalies'));
app.use('/api/v1/audit', require('./routes/audit'));
app.use('/api/v1/recommendations', require('./routes/recommendations'));
app.use('/api/v1/workflow', require('./routes/workflow'));
app.use('/api/v1/ai', require('./routes/ai'));
app.use('/api/v1/risk', require('./routes/risk'));
app.use('/api/v1/state', require('./routes/state'));

app.get('/health', (req, res) => res.json({ ok: true }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`CloudSpy backend running on http://127.0.0.1:${PORT}`);
});
