const { MongoClient } = require('mongodb');
require('dotenv').config();

const uri = process.env.MONGODB_URI;

// Initialize the MongoClient
const client = new MongoClient(uri);

let dbConnection;

module.exports = {
  // Connect to the cluster
  connectToDb: async () => {
    try {
      await client.connect();
      // Specify your database name here
      dbConnection = client.db('client_telemetry');

      // spamHash is how every report is deduplicated/upserted, so it needs to be unique and
      // indexed; lastSeen speeds up the incremental /export pulls used by the retrain pipeline.
      await dbConnection.collection('spam_signals').createIndex({ spamHash: 1 }, { unique: true });
      await dbConnection.collection('spam_signals').createIndex({ lastSeen: -1 });

      // Hash-only record of messages a user corrected back to ham. Kept even when the user has
      // consented to text upload, because it is the counter the retrain trigger reads.
      await dbConnection.collection('false_positive_signals').createIndex({ spamHash: 1 }, { unique: true });

      // Correction samples WITH text. Only written when the user explicitly corrected a verdict
      // AND consented to sharing that specific message - see the privacy note in server.js.
      await dbConnection.collection('correction_samples').createIndex({ spamHash: 1 }, { unique: true });
      await dbConnection.collection('correction_samples').createIndex({ lastSeen: -1 });
      await dbConnection.collection('correction_samples').createIndex({ trustedAt: -1 });

      // Published model manifests. version is monotonic; the app compares against it.
      await dbConnection.collection('model_versions').createIndex({ version: -1 }, { unique: true });
      await dbConnection.collection('model_versions').createIndex({ active: 1 });

      console.log('Successfully connected to MongoDB Cluster');
    } catch (err) {
      console.error('Database connection failed:', err);
      process.exit(1);
    }
  },
  // Return the database object to use in your routes
  getDb: () => dbConnection
};
