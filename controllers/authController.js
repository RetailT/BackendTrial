// controllers/authController.js
const { connectToDatabase } = require("../config/db");

exports.getServerTime = async (req, res) => {
  try {
    const pool = await connectToDatabase();

    const result = await pool
      .request()
      .query("SELECT GETDATE() AS serverTime");

    res.status(200).json({
      message: "Successfully connected to DB",
      serverTime: result.recordset[0].serverTime,
    });
  } catch (error) {
    console.error("Error fetching server time:", error);
    res.status(500).json({ message: "Database error" });
  }
};
