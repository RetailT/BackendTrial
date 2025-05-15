import express, { Request, Response } from "express";
import cors from "cors";
import serverless from "serverless-http";

const app = express();

// Import your controllers and middleware here
const authController = require("../controllers/authController");

app.use(
  cors({
    origin: "https://retailtarget.lk",
    credentials: true,
  })
);
app.use(express.json());

// Define routes
app.get("/", (req: Request, res: Response) => {
  res.send("Hello Vercel");
});

app.get("/time", authController.getServerTime);


app.post("/login", authController.login);
app.post('/register', authController.register);

// Export as serverless function
module.exports = app;
module.exports.handler = serverless(app);
