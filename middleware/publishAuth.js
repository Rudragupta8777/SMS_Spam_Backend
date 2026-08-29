/**
 * Auth for the model-publishing endpoints.
 *
 * This is deliberately a DIFFERENT secret from the app's API key. The app key ships inside the
 * APK and can be extracted from any installed copy in about a minute, so it must never be able
 * to publish a model - otherwise anyone who downloads the app could push arbitrary weights to
 * every other user's phone.
 *
 * PUBLISH_KEY lives only in the CI secret store (GitHub Actions secrets) and on this server.
 */
module.exports = function requirePublishKey(req, res, next) {
  const expected = process.env.PUBLISH_KEY;
  const provided = req.get('x-publish-key');

  if (!expected) {
    console.warn('PUBLISH_KEY is not set - refusing all publish requests.');
    return res.status(500).json({ error: 'Server misconfigured: PUBLISH_KEY not set' });
  }

  if (expected === process.env.API_KEY) {
    // Guard against the easy mistake of reusing the app key, which would silently undo the
    // whole point of having a separate publish credential.
    console.error('PUBLISH_KEY must not equal API_KEY (the app key is extractable from the APK).');
    return res.status(500).json({ error: 'Server misconfigured: PUBLISH_KEY must differ from API_KEY' });
  }

  if (!provided || provided !== expected) {
    return res.status(401).json({ error: 'Missing or invalid publish key' });
  }

  next();
};
