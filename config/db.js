const mssql = require('mssql');
require('dotenv').config();

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE1,
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
  port: 1443,
  connectionTimeout: 5000,
  requestTimeout: 5000,
};

// Global for reuse across serverless invocations
let cachedPool = null;

const connectToDatabase = async () => {
  if (cachedPool) {
    try {
      // Ping the DB to ensure it's still alive
      await cachedPool.request().query('SELECT 1');
      return cachedPool;
    } catch (pingError) {
      console.warn('Stale MSSQL pool found. Reconnecting...');
      cachedPool = null;
    }
  }

  try {
    const pool = await mssql.connect(dbConfig);
    console.log('✅ Connected to MSSQL database');
    cachedPool = pool;
    return pool;
  } catch (err) {
    console.error('❌ Failed to connect to MSSQL:', err);
    throw err;
  }
};

module.exports = { connectToDatabase, mssql };
