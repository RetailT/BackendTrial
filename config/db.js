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
  connectionTimeout: 5000,  // << timeout in ms
  requestTimeout: 5000
};

let pool = null;

const connectToDatabase = async () => {
  if (pool) {
    return pool; // reuse pool in serverless
  }

  try {
    pool = await mssql.connect(dbConfig);
    console.log('Connected to MSSQL database');
    return pool;
  } catch (err) {
    console.error('Database connection failed:', err);
    throw err;
  }
};

module.exports = { connectToDatabase, mssql };
