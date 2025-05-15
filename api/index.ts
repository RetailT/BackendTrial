import express from "express";
const app = express();

const { connectToDatabase } = require("../config/db");
const { authenticateToken } = require("../middleware/authMiddleware");
const authController = require("../controllers/authController");

// app.get("/", async (req, res) => {
//   try {
//     const pool = await connectToDatabase();
//     const result = await pool.request().query("SELECT GETDATE() AS currentTime");
//     res.send(`Connected to DB. Server time: ${result.recordset[0].currentTime}`);
//   } catch (err) {
//     console.error("DB error:", err);
//     res.status(500).send("Database connection failed.");
//   }
// });

app.get("/", (req, res) => res.send("Hello Vercel"));
app.get("/time", authController.getServerTime);

// app.listen(3000, () => console.log("Server ready on port 3000."));

// module.exports = app;

export default app;