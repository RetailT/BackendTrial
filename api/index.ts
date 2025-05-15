import express from "express";
const app = express();

const { connectToDatabase } = require("../config/db");
const { authenticateToken } = require("../middleware/authMiddleware");
const authController = require("../controllers/authController");

app.get("/", (req, res) => res.send("Hello Vercel"));
app.get("/login", authController.getServerTime);

// app.listen(3000, () => console.log("Server ready on port 3000."));

// module.exports = app;

export default app;