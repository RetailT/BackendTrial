import express, { Request, Response } from "express";
import cors from "cors";
import serverless from "serverless-http";
const { authenticateToken } = require('../middleware/authMiddleware'); 

const app = express();

// Import your controllers and middleware here
const authController = require("../controllers/authController");

app.use(
  cors({
    origin: ["https://retailtarget.lk", "https://retail-web-xo4u.vercel.app"],
    credentials: true,
  })
);
app.use(express.json());

// Define routes
app.get("/", (req: Request, res: Response) => {
  res.send("Hello from Nodejs and Express!");
});

app.get('/companies', authenticateToken, authController.dashboardOptions);
app.get('/vendors', authenticateToken, authController.vendorOptions);

app.post("/login", authController.login);
app.post('/register', authController.register);
app.post('/reset-password', authController.resetPassword);
app.post('/forgot-password', authController.forgotPassword);
app.post('/close-connection', authController.closeConnection);
app.post('/update-temp-sales-table', authController.updateTempSalesTable);
app.post('/update-temp-grn-table', authController.updateTempGrnTable);
app.post('/update-temp-tog-table', authController.updateTempTogTable);

app.delete('/stock-update-delete', authenticateToken, authController.stockUpdateDelete);
app.delete('/grnprn-delete', authenticateToken, authController.grnprnDelete);

app.put('/reset-database-connection', authenticateToken, authController.resetDatabaseConnection);

// Export as serverless function
module.exports = app;
module.exports.handler = serverless(app);
