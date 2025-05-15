import express from "express";
import cors from "cors";
const app = express();

const { connectToDatabase } = require("../config/db");
const { authenticateToken } = require("../middleware/authMiddleware");
const authController = require("../controllers/authController");

app.use(cors({
  origin: "https://retailtarget.lk", // Allow only this domain
  credentials: true // If you're sending cookies or auth headers
}));

app.use(express.json());

app.get("/", (req, res) => res.send("Hello Vercel"));
app.get("/time", authController.getServerTime);

app.post('/login', authController.login);

// app.listen(3000, () => console.log("Server ready on port 3000."));

// module.exports = app;

export default app;