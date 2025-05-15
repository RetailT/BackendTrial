import express from "express";
const app = express();

const { connectToDatabase } = require("../config/db");

app.get("/", async (req, res) => {
  try {
    const pool = await connectToDatabase();
    const result = await pool.request().query("SELECT GETDATE() AS currentTime");
    res.send(`Connected to DB. Server time: ${result.recordset[0].currentTime}`);
  } catch (err) {
    console.error("DB error:", err);
    res.status(500).send("Database connection failed.");
  }
});

app.get("/hello", (req, res) => res.send("Hello Vercel"));

// app.listen(3000, () => console.log("Server ready on port 3000."));

// module.exports = app;

export default app;