const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { connectToDb, getDb } = require('./db');
const requireApiKey = require('./middleware/auth');
const requirePublishKey = require('./middleware/publishAuth');

const app = express();
app.use(cors());
app.use(express.json({ limit: '64kb' }));

connectToDb().then(() => {
  app.listen(process.env.PORT || 3000, () => {
    console.log(`Server running on port ${process.env.PORT || 3000}`);
  });
});

// Unauthenticated liveness check, useful for uptime monitors and the retrain pipeline
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

const SHA256_HEX = /^[a-f0-9]{64}$/i;

/**
 * How many DISTINCT devices must independently report the same message before it is allowed to
 * become training data.
 *
 * This is the main defence against model poisoning. The app's API key is embedded in the APK and
 * can be extracted, so anyone can call /api/telemetry; requiring agreement across independent
 * installs means one bad actor with one device cannot steer the model.
 *
 * Set to 1 only for single-device testing - it disables the protection.
 */
const MIN_DEVICE_COUNT = parseInt(process.env.MIN_DEVICE_COUNT || '2', 10);

/**
 * How many new TRUSTED samples must accumulate before CI bothers retraining.
 *
 * A deliberate note on the default: retraining on ~10 samples cannot meaningfully move a model
 * trained on ~32,000 rows, but it does produce a different model (fresh initialisation, freshly
 * tuned threshold) and therefore ships churn to every device for no measurable gain. 100 is a
 * more honest floor. Lower it via env if you want faster iteration while testing.
 */
const RETRAIN_MIN_NEW_SAMPLES = parseInt(process.env.RETRAIN_MIN_NEW_SAMPLES || '100', 10);

const telemetryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  // Rate limit per install rather than per IP: whole colleges sit behind one NAT address, and
  // an attacker rotating IPs is cheap anyway. Falls back to IP when no device id is supplied.
  keyGenerator: (req) => req.body?.deviceId || req.ip
});

/**
 * POST /api/telemetry
 *
 * Body: {
 *   spamHash: string,               // sha256 of the message body
 *   label: "spam" | "ham",          // FINAL verdict, after any user correction
 *   source: "model" | "user_correction",
 *   confidence: number,
 *   timestamp: number,
 *   appVersion: string,
 *   deviceId?: string,              // anonymous per-install uuid, for independent-report counting
 *   messageText?: string,           // see the privacy rules below
 *   textConsent?: boolean           // true only when the user consented to share THIS message
 * }
 *
 * PRIVACY RULES, enforced here rather than trusted from the client:
 *   - label "spam"  -> text is stored. Reporting spam is the point of the product.
 *   - label "ham"   -> text is stored ONLY when this is an explicit user correction AND
 *                      textConsent is true. Anything else is recorded hash-only.
 *   - Automatic screening never uploads ham text, whatever the client sends.
 */
app.post('/api/telemetry', telemetryLimiter, requireApiKey, async (req, res) => {
  const {
    spamHash, label, source, confidence, timestamp, appVersion,
    deviceId, messageText, textConsent
  } = req.body;

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
    const device = typeof deviceId === 'string' && deviceId.length <= 64 ? deviceId : null;

    if (label === 'spam') {
      if (!messageText || typeof messageText !== 'string') {
        return res.status(400).json({ error: 'messageText is required when label is "spam"' });
      }

      await db.collection('spam_signals').updateOne(
        { spamHash },
        {
          $inc: { reportCount: 1 },
          $set: { lastSeen: now, confidence, source, appVersion, reportedAt },
          $setOnInsert: { spamHash, text: messageText, firstSeen: now },
          ...(device ? { $addToSet: { devices: device } } : {})
        },
        { upsert: true }
      );

      return res.status(200).json({ message: 'Spam signature logged for retraining.' });
    }

    // ---- label === "ham" ----
    // Always keep the hash-only counter; it is what the retrain trigger reads.
    await db.collection('false_positive_signals').updateOne(
      { spamHash },
      {
        $inc: { reportCount: 1 },
        $set: { lastSeen: now, source, appVersion },
        $setOnInsert: { spamHash, firstSeen: now },
        ...(device ? { $addToSet: { devices: device } } : {})
      },
      { upsert: true }
    );

    // Text is accepted only for a deliberate correction the user consented to share.
    const isConsentedCorrection =
      source === 'user_correction' && textConsent === true &&
      typeof messageText === 'string' && messageText.length > 0;

    if (isConsentedCorrection) {
      await db.collection('correction_samples').updateOne(
        { spamHash },
        {
          $inc: { reportCount: 1 },
          $set: { lastSeen: now, label: 'ham', appVersion },
          $setOnInsert: { spamHash, text: messageText, firstSeen: now, exported: false },
          ...(device ? { $addToSet: { devices: device } } : {})
        },
        { upsert: true }
      );
      return res.status(200).json({ message: 'Correction logged with text (consented).' });
    }

    return res.status(200).json({ message: 'Ham signal logged (hash only).' });
  } catch (error) {
    console.error('Failed to log telemetry:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/** Counts a doc's independent reporters, tolerating rows written before deviceId existed. */
const deviceCountExpr = { $size: { $ifNull: ['$devices', []] } };

// GET /api/telemetry/stats
app.get('/api/telemetry/stats', requireApiKey, async (req, res) => {
  try {
    const db = getDb();
    const [spam, fp, corrections] = await Promise.all([
      db.collection('spam_signals').countDocuments(),
      db.collection('false_positive_signals').countDocuments(),
      db.collection('correction_samples').countDocuments()
    ]);
    res.status(200).json({
      totalSpamPatterns: spam,
      totalFalsePositiveSignals: fp,
      totalConsentedCorrections: corrections,
      minDeviceCount: MIN_DEVICE_COUNT
    });
  } catch (error) {
    console.error('Failed to compute stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/telemetry/export?since=<epochMs>&format=json|csv&minDeviceCount=<n>
 *
 * Feeds ml_pipeline/fetch_telemetry.py. Returns both new spam AND consented ham corrections,
 * each already labelled, and only rows that clear the independent-reporter threshold.
 */
app.get('/api/telemetry/export', requireApiKey, async (req, res) => {
  try {
    const db = getDb();
    const since = new Date(Number(req.query.since) || 0);
    const minDevices = Number(req.query.minDeviceCount) || MIN_DEVICE_COUNT;

    const trusted = (extra = {}) => ([
      { $match: { lastSeen: { $gte: since }, ...extra } },
      { $addFields: { deviceCount: deviceCountExpr } },
      // Rows predating deviceId have no devices array; fall back to raw report count so old
      // data is not silently dropped.
      { $match: { $or: [{ deviceCount: { $gte: minDevices } }, { reportCount: { $gte: minDevices } }] } },
      { $project: { _id: 0, text: 1, deviceCount: 1, reportCount: 1, firstSeen: 1, lastSeen: 1 } },
      { $sort: { lastSeen: -1 } }
    ]);

    const [spam, ham] = await Promise.all([
      db.collection('spam_signals').aggregate(trusted()).toArray(),
      db.collection('correction_samples').aggregate(trusted({ label: 'ham' })).toArray()
    ]);

    const samples = [
      ...spam.map((s) => ({ ...s, label: 1 })),
      ...ham.map((s) => ({ ...s, label: 0 }))
    ];

    if (req.query.format === 'csv') {
      const esc = (v) => `"${String(v).replace(/"/g, '""')}"`;
      const rows = samples.map((s) => `${esc(s.text)},${s.label}`).join('\n');
      return res.set('Content-Type', 'text/csv').status(200).send('text,label\n' + rows);
    }

    res.status(200).json({
      count: samples.length,
      spamCount: spam.length,
      hamCorrectionCount: ham.length,
      minDeviceCount: minDevices,
      samples
    });
  } catch (error) {
    console.error('Failed to export telemetry:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===========================================================================================
//  Model distribution (OTA)
// ===========================================================================================

/**
 * GET /api/model/latest
 *
 * The manifest the app polls. featureContract is not decoration: the app MUST refuse a model
 * whose contract its TextFeaturizer does not implement. Feeding a model built for a different
 * hashing scheme produces silent garbage - that exact mismatch (a 20,823-word vocab against a
 * 10,000-row embedding) is what crashed 21.5% of messages in an earlier version.
 */
app.get('/api/model/latest', requireApiKey, async (req, res) => {
  try {
    const doc = await getDb().collection('model_versions')
      .findOne({ active: true }, { sort: { version: -1 }, projection: { _id: 0 } });

    if (!doc) return res.status(404).json({ error: 'No model published yet' });
    res.status(200).json(doc);
  } catch (error) {
    console.error('Failed to fetch model manifest:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/model/retrain-status
 *
 * CI calls this before spending a runner on training. Reports how many trusted samples have
 * arrived since the live model was published and whether that clears the threshold.
 */
app.get('/api/model/retrain-status', requirePublishKey, async (req, res) => {
  try {
    const db = getDb();
    const active = await db.collection('model_versions')
      .findOne({ active: true }, { sort: { version: -1 } });
    const since = active?.trainedUpTo ? new Date(active.trainedUpTo) : new Date(0);

    const countTrusted = async (coll, extra = {}) => {
      const out = await db.collection(coll).aggregate([
        { $match: { lastSeen: { $gt: since }, ...extra } },
        { $addFields: { deviceCount: deviceCountExpr } },
        { $match: { $or: [
          { deviceCount: { $gte: MIN_DEVICE_COUNT } },
          { reportCount: { $gte: MIN_DEVICE_COUNT } }
        ] } },
        { $count: 'n' }
      ]).toArray();
      return out[0]?.n || 0;
    };

    const [newSpam, newCorrections] = await Promise.all([
      countTrusted('spam_signals'),
      countTrusted('correction_samples', { label: 'ham' })
    ]);

    const total = newSpam + newCorrections;
    res.status(200).json({
      currentVersion: active?.version || 0,
      since: since.toISOString(),
      newSpamSamples: newSpam,
      newCorrectionSamples: newCorrections,
      totalNewSamples: total,
      threshold: RETRAIN_MIN_NEW_SAMPLES,
      shouldRetrain: total >= RETRAIN_MIN_NEW_SAMPLES
    });
  } catch (error) {
    console.error('Failed to compute retrain status:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /api/model/publish   (CI only - requires PUBLISH_KEY, never the app key)
 *
 * Registers a model that has ALREADY passed the quality gate in CI and been uploaded to a
 * durable URL (a GitHub Release asset). This endpoint stores a pointer plus the checksum the
 * app verifies after downloading; it never receives the weights themselves.
 */
app.post('/api/model/publish', requirePublishKey, async (req, res) => {
  const {
    modelUrl, sha256, threshold, featureContract,
    metrics, trainedUpTo, notes, minAppVersionCode
  } = req.body;

  // https is required in production: the app verifies the sha256 after download, but plain http
  // still lets a network attacker see and stall model rollouts. The escape hatch exists purely so
  // the loop can be exercised against a LAN file server during development, and is off by default.
  const allowInsecure = process.env.ALLOW_INSECURE_MODEL_URL === 'true';
  const urlOk = typeof modelUrl === 'string' &&
    (/^https:\/\//.test(modelUrl) || (allowInsecure && /^http:\/\//.test(modelUrl)));
  if (!urlOk) {
    return res.status(400).json({
      error: allowInsecure
        ? 'modelUrl must be an http(s) URL'
        : 'modelUrl must be an https URL (set ALLOW_INSECURE_MODEL_URL=true for local testing)'
    });
  }
  if (allowInsecure && /^http:\/\//.test(modelUrl)) {
    console.warn(`Publishing over plain http (${modelUrl}) - development only.`);
  }
  if (!sha256 || !SHA256_HEX.test(sha256)) {
    return res.status(400).json({ error: 'sha256 must be a sha256 hex string' });
  }
  if (typeof threshold !== 'number' || threshold <= 0 || threshold >= 1) {
    return res.status(400).json({ error: 'threshold must be between 0 and 1' });
  }
  if (!featureContract || typeof featureContract.numBuckets !== 'number' ||
      typeof featureContract.maxFeatures !== 'number' ||
      typeof featureContract.featureVersion !== 'number') {
    // featureVersion catches a SEMANTIC tokenizer change (e.g. digit masking) that numBuckets/
    // maxFeatures can't see, because the vector shape doesn't change - only what each id means.
    return res.status(400).json({
      error: 'featureContract{numBuckets,maxFeatures,featureVersion} is required'
    });
  }

  try {
    const db = getDb();
    const latest = await db.collection('model_versions').findOne({}, { sort: { version: -1 } });
    const version = (latest?.version || 0) + 1;

    const manifest = {
      version,
      modelUrl,
      sha256: sha256.toLowerCase(),
      threshold,
      featureContract,
      metrics: metrics || null,
      notes: notes || null,
      minAppVersionCode: minAppVersionCode || 1,
      trainedUpTo: trainedUpTo || new Date().toISOString(),
      publishedAt: new Date().toISOString(),
      active: true
    };

    await db.collection('model_versions').insertOne({ ...manifest });
    // Exactly one active version; previous rows are retained so a rollback is a one-field update.
    await db.collection('model_versions').updateMany(
      { version: { $ne: version } }, { $set: { active: false } }
    );

    console.log(`Published model v${version} (${sha256.slice(0, 12)}...)`);
    res.status(201).json({ message: `Published model v${version}`, version });
  } catch (error) {
    console.error('Failed to publish model:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /api/model/rollback   (CI/operator only)
 * Re-activates a previously published version. The reason the app keeps the prior model file on
 * disk is so this is actually survivable when a bad model ships.
 */
app.post('/api/model/rollback', requirePublishKey, async (req, res) => {
  const { version } = req.body;
  if (!Number.isInteger(version)) {
    return res.status(400).json({ error: 'version (integer) is required' });
  }
  try {
    const db = getDb();
    const target = await db.collection('model_versions').findOne({ version });
    if (!target) return res.status(404).json({ error: `No such version ${version}` });

    await db.collection('model_versions').updateMany({}, { $set: { active: false } });
    await db.collection('model_versions').updateOne({ version }, { $set: { active: true } });

    console.warn(`Rolled back to model v${version}`);
    res.status(200).json({ message: `Rolled back to v${version}`, version });
  } catch (error) {
    console.error('Failed to roll back:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/model/versions - publication history, for debugging a bad rollout
app.get('/api/model/versions', requirePublishKey, async (req, res) => {
  try {
    const docs = await getDb().collection('model_versions')
      .find({}, { projection: { _id: 0 } }).sort({ version: -1 }).limit(20).toArray();
    res.status(200).json({ count: docs.length, versions: docs });
  } catch (error) {
    console.error('Failed to list versions:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
