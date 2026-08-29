// Shared secret between the Android app (BuildConfig.TELEMETRY_API_KEY) and this server.
// Keeps the reporting/export endpoints from being writable/readable by anyone who finds the URL.
module.exports = function requireApiKey(req, res, next) {
  const expected = process.env.API_KEY;
  const provided = req.get('x-api-key');

  if (!expected) {
    console.warn('API_KEY is not set in .env — refusing all requests until it is configured.');
    return res.status(500).json({ error: 'Server misconfigured: API_KEY not set' });
  }

  if (!provided || provided !== expected) {
    return res.status(401).json({ error: 'Missing or invalid API key' });
  }

  next();
};
