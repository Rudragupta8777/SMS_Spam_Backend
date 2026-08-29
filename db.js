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
      // indexed in both collections; lastSeen speeds up the incremental /export pulls used by
      // the retrain pipeline.
      await dbConnection.collection('spam_signals').createIndex({ spamHash: 1 }, { unique: true });
      await dbConnection.collection('spam_signals').createIndex({ lastSeen: -1 });
      await dbConnection.collection('false_positive_signals').createIndex({ spamHash: 1 }, { unique: true });

      console.log('Successfully connected to MongoDB Cluster');
    } catch (err) {
      console.error('Database connection failed:', err);
      process.exit(1);
    }
  },
  // Return the database object to use in your routes
  getDb: () => dbConnection
};
