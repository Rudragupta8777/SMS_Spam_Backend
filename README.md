# Telemetry Backend

Receives privacy-preserving spam signals from the SpamShield Android app and exposes them for
the retraining pipeline in `../ml_pipeline`. Native `mongodb` driver, MongoDB Atlas.

## Privacy rule

The raw text of a message is only ever accepted and stored when the final label is **spam**.
Ham messages (including "actually this wasn't spam" corrections) are reported hash-only, so no
one's private conversations ever leave the device.

## Setup

```bash
npm install
cp .env .env.local   # or edit .env directly — never commit it
npm start
```

`.env` needs:

```
MONGODB_URI=<your Atlas connection string>
PORT=3000
API_KEY=<shared secret — must match the Android app's local.properties TELEMETRY_API_KEY>
```

Generate a key with `node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"`.

## Endpoints

All endpoints except `/health` require an `x-api-key` header matching `API_KEY`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness check, no auth |
| POST | `/api/telemetry` | Report one screening result (see body shape below) |
| GET | `/api/telemetry/stats` | Counters: total spam patterns, false-positive signals, device reports |
| GET | `/api/telemetry/export?since=&minDeviceCount=&format=json\|csv` | Pulls spam samples for retraining (consumed by `ml_pipeline/fetch_telemetry.py`) |

### POST /api/telemetry body

```jsonc
{
  "spamHash": "sha256 hex of the message body",
  "label": "spam" | "ham",          // the FINAL verdict, after any user correction
  "source": "model" | "user_correction",
  "confidence": 0.94,
  "timestamp": 1732900000000,
  "appVersion": "1.0",
  "messageText": "only present, and only accepted, when label is \"spam\""
}
```

Requests are additionally rate-limited (120 / 15 min per IP) since this endpoint is reachable by
any installed copy of the app.

## Data model

- `spam_signals` — one doc per unique `spamHash` that was ever labeled spam: `text`, `confidence`,
  `deviceCount` (how many devices independently reported it), `firstSeen`, `lastSeen`.
- `false_positive_signals` — hash-only doc per message a user corrected from spam back to ham.
  No text is stored here, ever.
