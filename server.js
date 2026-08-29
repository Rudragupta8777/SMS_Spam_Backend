const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { connectToDb, getDb } = require('./db');
const requireApiKey = require('./middleware/auth');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize DB connection, then start the Express server
connectToDb().then(() => {
  app.listen(process.env.PORT || 3000, () => {
    console.log(`Server running on port ${process.env.PORT || 3000}`);
  });
});

// Unauthenticated liveness check, useful for uptime monitors / the retrain pipeline's connectivity check
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

const SHA256_HEX = /^[a-f0-9]{64}$/i;

// Reporting is the one endpoint every device on earth can reach, so it gets its own (generous
// but bounded) limiter on top of the API key check, in case a key ever leaks or a client misbehaves.
const telemetryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * POST /api/telemetry
 * Body: {
 *   spamHash: string (sha256 hex of the message body),
 *   label: "spam" | "ham"           // the FINAL verdict — model's own call, or a user correction
 *   source: "model" | "user_correction",
 *   confidence: number,             // model's spam probability, 0-1
 *   timestamp: number,              // client-side epoch ms
 *   appVersion: string,
 *   messageText?: string            // ONLY sent (and ONLY stored) when label === "spam"
 * }
 *
 * Privacy rule enforced server-side, not just trusted from the client: message text is only ever
 * written to disk when label === "spam". A "ham" report (including a false-positive correction)
 * is hash-only, so we never end up storing anyone's private conversation.
 */
app.post('/api/telemetry', telemetryLimiter, requireApiKey, async (req, res) => {
  const { spamHash, label, source, confidence, timestamp, appVersion, messageText } = req.body;

  if (!spamHash || !SHA256_HEX.test(spamHash)) {
    return res.status(400).json({ error: 'spamHash must be a sha256 hex string' });
  }
  if (label !== 'spam' && label !== 'ham') {
    return res.status(400).json({ error: 'label must be "spam" or "ham"' });
  }

  try {
    const db = getDb();
    const now = new Date();
    const reportedAt = Number.isFinite(timestamp) ? new Date(timestamp) : now;

    if (label === 'spam') {
      if (!messageText || typeof messageText !== 'string') {
        return res.status(400).json({ error: 'messageText is required when label is "spam"' });
      }

      await db.collection('spam_signals').updateOne(
        { spamHash },
        {
          $inc: { deviceCount: 1 },
          $set: { lastSeen: now, confidence, source, appVersion, reportedAt },
          $setOnInsert: { spamHash, text: messageText, firstSeen: now }
        },
        { upsert: true }
      );

      res.status(200).json({ message: 'Spam signature logged for retraining.' });
    } else {
      // False-positive (or otherwise confirmed-ham) signal. No text is ever accepted here.
      await db.collection('false_positive_signals').updateOne(
        { spamHash },
        {
          $inc: { deviceCount: 1 },
          $set: { lastSeen: now, source, appVersion },
          $setOnInsert: { spamHash, firstSeen: now }
        },
        { upsert: true }
      );

      res.status(200).json({ message: 'Ham signal logged.' });
    }
  } catch (error) {
    console.error('Failed to log telemetry:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/telemetry/stats — quick counters for a dashboard / sanity check before retraining
app.get('/api/telemetry/stats', requireApiKey, async (req, res) => {
  try {
    const db = getDb();
    const [totalSpamPatterns, totalFalsePositiveSignals, deviceReportAgg] = await Promise.all([
      db.collection('spam_signals').countDocuments(),
      db.collection('false_positive_signals').countDocuments(),
      db.collection('spam_signals').aggregate([
        { $group: { _id: null, total: { $sum: '$deviceCount' } } }
      ]).toArray()
    ]);

    res.status(200).json({
      totalSpamPatterns,
      totalFalsePositiveSignals,
      totalDeviceReports: deviceReportAgg[0]?.total || 0
    });
  } catch (error) {
    console.error('Failed to compute stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/telemetry/export?since=<epochMs>&minDeviceCount=<n>&format=json|csv
 * Feeds the retrain pipeline (see ml_pipeline/fetch_telemetry.py): every spam signal is a new
 * labeled training row. `since` lets the pipeline pull incrementally instead of re-downloading
 * everything on every run.
 */
app.get('/api/telemetry/export', requireApiKey, async (req, res) => {
  try {
    const db = getDb();
    const since = Number(req.query.since) || 0;
    const minDeviceCount = Number(req.query.minDeviceCount) || 1;
    const format = req.query.format === 'csv' ? 'csv' : 'json';

    const signals = await db.collection('spam_signals')
      .find({ lastSeen: { $gte: new Date(since) }, deviceCount: { $gte: minDeviceCount } })
      .project({ _id: 0, text: 1, deviceCount: 1, confidence: 1, firstSeen: 1, lastSeen: 1 })
      .sort({ lastSeen: -1 })
      .toArray();

    if (format === 'csv') {
      const escape = (value) => `"${String(value).replace(/"/g, '""')}"`;
      const header = 'text,label\n';
      const rows = signals.map((s) => `${escape(s.text)},1`).join('\n');
      res.set('Content-Type', 'text/csv').status(200).send(header + rows);
    } else {
      res.status(200).json({
        count: signals.length,
        samples: signals.map((s) => ({ text: s.text, label: 1, ...s }))
      });
    }
  } catch (error) {
    console.error('Failed to export telemetry:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
