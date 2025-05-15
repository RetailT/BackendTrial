const { connectToDatabase } = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const moment = require("moment");
const mssql = require("mssql");

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

//login
exports.login = async (req, res) => {
  let pool;
  try {
    pool = await connectToDatabase();

    const { username, password, ip } = req.body;
    const date = moment().format("YYYY-MM-DD HH:mm:ss");

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    // Get user info
    const userResult = await pool
      .request()
      .input("username", mssql.VarChar, username)
      .query("USE [RTPOS_MAIN]; SELECT * FROM tb_USERS WHERE username = @username");

    if (userResult.recordset.length === 0) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    const user = userResult.recordset[0];
    const { port, ip_address, CUSTOMERID, password: hashedPassword } = user;

    if (!port || !ip_address) {
      return res.status(400).json({
        message: "Connection hasn't been established yet! Please contact system support.",
      });
    }

    const isMatch = await bcrypt.compare(password, hashedPassword);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    // Insert login log
    try {
      await pool
        .request()
        .input("username", mssql.VarChar, username)
        .input("ip", mssql.VarChar, ip)
        .input("datetime", mssql.VarChar, date)
        .query(`
          USE [RTPOS_MAIN];
          INSERT INTO tb_LOG (username, ip, datetime)
          VALUES (@username, @ip, @datetime)
        `);
      console.log("Login log inserted.");
    } catch (logErr) {
      console.error("Failed to insert login log:", logErr);
    }

    // Close old connection
    await mssql.close();

    // Connect to dynamic DB
    const dynamicDbConfig = {
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      server: ip_address.trim(),
      database: process.env.DB_DATABASE2,
      options: {
        encrypt: false,
        trustServerCertificate: true,
      },
      port: parseInt(port),
      connectionTimeout: 5000,  // << timeout in ms
      requestTimeout: 5000
    };

    const dynamicPool = await mssql.connect(dynamicDbConfig);
    console.log("Connected to dynamic DB");

    const companyResult = await dynamicPool
      .request()
      .input("CUSTOMER_ID", mssql.Int, CUSTOMERID)
      .query("USE [RT_WEB]; SELECT * FROM tb_COMPANY WHERE CUSTOMERID = @CUSTOMER_ID");

    if (companyResult.recordset.length === 0) {
      return res.status(400).json({ message: "Invalid customer ID" });
    }

    // Generate token
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        email: user.email,
        a_permission: user.a_permission,
        a_sync: user.a_sync,
        d_company: user.d_company,
        d_department: user.d_department,
        d_category: user.d_category,
        d_scategory: user.d_scategory,
        d_vendor: user.d_vendor,
        d_invoice: user.d_invoice,
        t_scan: user.t_scan,
        t_stock: user.t_stock,
        t_grn: user.t_grn,
        t_prn: user.t_prn,
        t_tog: user.t_tog,
        t_stock_update: user.t_stock_update,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error);
    if (!res.headersSent) {
      return res.status(500).json({ message: "Failed to log in" });
    }
  } finally {
    // Ensure connection is closed in case of error
    if (mssql.connected) await mssql.close();
  }
};

//register
exports.register = async (req, res) => {
  let pool;
  try {
    pool = await connectToDatabase();

    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check for existing user
    const checkUserResult = await pool
      .request()
      .input("username", mssql.VarChar, username)
      .input("email", mssql.VarChar, email)
      .query(`
        USE [RTPOS_MAIN];
        SELECT * FROM tb_USERS WHERE username = @username OR email = @email
      `);

    if (checkUserResult.recordset.length > 0) {
      const existingUser = checkUserResult.recordset[0];
      if (existingUser.username === username) {
        return res.status(400).json({ message: "Username already exists" });
      }
      if (existingUser.email === email) {
        return res.status(400).json({ message: "Email already exists" });
      }
    }

    // Hash password and insert new user
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool
      .request()
      .input("username", mssql.VarChar, username)
      .input("email", mssql.VarChar, email)
      .input("password", mssql.VarChar, hashedPassword)
      .query(`
        USE [RTPOS_MAIN];
        INSERT INTO tb_USERS (username, email, password)
        VALUES (@username, @email, @password)
      `);

    return res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Registration error:", err);
    if (!res.headersSent) {
      return res.status(500).json({ message: "Failed to register user" });
    }
  } finally {
    if (mssql.connected) await mssql.close();
  }
};