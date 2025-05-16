const { connectToDatabase } = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const moment = require("moment");
const mssql = require("mssql");
const crypto = require('crypto');
const nodemailer = require("nodemailer");
const { sendPasswordResetEmail } = require("../utils/nodemailer");


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

    return res.status(201).json({ message: "User added successfully" });
  } catch (err) {
    console.error("Registration error:", err);
    if (!res.headersSent) {
      return res.status(500).json({ message: "Failed to register user" });
    }
  } finally {
    if (mssql.connected) await mssql.close();
  }
};

//reset password
exports.resetPassword = async (req, res) => {
  let pool;

  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ message: "Token and new password are required" });
  }

  try {
    pool = await connectToDatabase();

    // Find user by reset token
    const result = await pool
      .request()
      .input("token", mssql.VarChar, token)
      .query(`
        USE [RTPOS_MAIN];
        SELECT * FROM tb_USERS WHERE resetToken = @token
      `);

    if (result.recordset.length === 0) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const user = result.recordset[0];

    if (Date.now() > user.resetTokenExpiry) {
      return res.status(400).json({ message: "Reset token has expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear reset token fields
    await pool
      .request()
      .input("hashedPassword", mssql.VarChar, hashedPassword)
      .input("token", mssql.VarChar, token)
      .query(`
        USE [RTPOS_MAIN];
        UPDATE tb_USERS
        SET password = @hashedPassword, resetToken = NULL, resetTokenExpiry = NULL
        WHERE resetToken = @token
      `);

    return res.status(200).json({ message: "Password has been reset successfully" });

  } catch (error) {
    console.error("Error resetting password:", error);
    if (!res.headersSent) {
      return res.status(500).json({ message: "Failed to reset password" });
    }
  } finally {
    if (mssql.connected) await mssql.close();
  }
};

//forgot password
exports.forgotPassword = async (req, res) => {
  let pool;
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }

  try {
    pool = await connectToDatabase();

    // Check if user exists
    const result = await pool
      .request()
      .input("username", mssql.VarChar, username)
      .query(`
        USE [RTPOS_MAIN];
        SELECT * FROM tb_USERS WHERE username = @username
      `);

    if (result.recordset.length === 0) {
      return res.status(400).json({ message: "No user found with this username" });
    }

    const user = result.recordset[0];
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry

    // Update user with reset token and expiry
    await pool
      .request()
      .input("resetToken", mssql.VarChar, resetToken)
      .input("resetTokenExpiry", mssql.BigInt, resetTokenExpiry)
      .input("username", mssql.VarChar, username)
      .query(`
        USE [RTPOS_MAIN];
        UPDATE tb_USERS
        SET resetToken = @resetToken, resetTokenExpiry = @resetTokenExpiry
        WHERE username = @username
      `);

    // Send email with token
    await sendPasswordResetEmail(user.email, resetToken);

    return res.status(200).json({ message: "Password reset email sent" });

  } catch (error) {
    console.error("Forgot password error:", error);
    if (!res.headersSent) {
      return res.status(500).json({ message: "Failed to send password reset email" });
    }
  } finally {
    if (mssql.connected) await mssql.close();
  }
};

//log out
exports.closeConnection = async (req, res) => {
  try {
    if (mssql.connected) {
      await mssql.close();
      console.log("MSSQL connection closed");
    }

    res.status(200).json({ message: "Connection Closed successfully" });
  } catch (err) {
    console.error("Error during connection closing:", err);
    res.status(500).json({ message: "Failed to close the connection" });
  }
};

//temp sales table
exports.updateTempSalesTable = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(403).json({ message: "No authorization token provided" });
    }

    const token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    const username = decoded.username;
    const {
      company,
      count,
      type,
      productCode,
      productName,
      costPrice,
      scalePrice,
      stock,
      quantity,
    } = req.body;

    const insertQuery = `
      USE [RT_WEB];
      INSERT INTO tb_STOCKRECONCILATION_DATAENTRYTEMP 
      (COMPANY_CODE, COUNT_STATUS, TYPE, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE, CUR_STOCK, PHY_STOCK, REPUSER)
      VALUES (@company, @count, @type, @productCode, @productName, @costPrice, @scalePrice, @stock, @quantity, @username)
    `;

    const insertRequest = new mssql.Request();
    insertRequest.input("company", mssql.NChar(10), company);
    insertRequest.input("count", mssql.NChar(10), count);
    insertRequest.input("type", mssql.NChar(10), type);
    insertRequest.input("productCode", mssql.NChar(30), productCode);
    insertRequest.input("productName", mssql.NChar(50), productName);
    insertRequest.input("costPrice", mssql.Money, costPrice);
    insertRequest.input("scalePrice", mssql.Money, scalePrice);
    insertRequest.input("stock", mssql.Float, stock);
    insertRequest.input("quantity", mssql.Float, quantity);
    insertRequest.input("username", mssql.NChar(10), username);

    await insertRequest.query(insertQuery);

    res.status(201).json({ message: "Table Updated successfully" });
  } catch (error) {
    console.error("Error updating sales temp table:", error);
    res.status(500).json({ message: "Failed to update table" });
  }
};

//temp grn table
exports.updateTempGrnTable = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(403).json({ message: "No authorization token provided" });
    }

    const token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    const username = decoded.username;

    const {
      company,
      type,
      productCode,
      productName,
      costPrice,
      scalePrice,
      stock,
      quantity,
      vendor_code,
      vendor_name,
      invoice_no,
    } = req.body;

    let insertQuery;
    if (type === "GRN") {
      insertQuery = `
        USE [RT_WEB]
        INSERT INTO tb_GRN_TEMP 
        (COMPANY_CODE, VENDOR_CODE, VENDOR_NAME, INVOICE_NO, TYPE, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE, CUR_STOCK, PHY_STOCK, REPUSER)
        VALUES (@company, @vendor_code, @vendor_name, @invoice_no, @type, @productCode, @productName, @costPrice, @scalePrice, @stock, @quantity, @username)
      `;
    } else if (type === "PRN") {
      insertQuery = `
        USE [RT_WEB]
        INSERT INTO tb_PRN_TEMP 
        (COMPANY_CODE, VENDOR_CODE, VENDOR_NAME, INVOICE_NO, TYPE, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE, CUR_STOCK, PHY_STOCK, REPUSER)
        VALUES (@company, @vendor_code, @vendor_name, @invoice_no, @type, @productCode, @productName, @costPrice, @scalePrice, @stock, @quantity, @username)
      `;
    } else {
      return res.status(400).json({ message: "Invalid type. Must be GRN or PRN." });
    }

    const insertRequest = new mssql.Request();
    insertRequest.input("company", mssql.NChar(10), company);
    insertRequest.input("vendor_code", mssql.NChar(10), vendor_code);
    insertRequest.input("vendor_name", mssql.NChar(50), vendor_name);
    insertRequest.input("invoice_no", mssql.NChar(10), invoice_no);
    insertRequest.input("type", mssql.NChar(10), type);
    insertRequest.input("productCode", mssql.NChar(30), productCode);
    insertRequest.input("productName", mssql.NChar(50), productName);
    insertRequest.input("costPrice", mssql.Money, costPrice);
    insertRequest.input("scalePrice", mssql.Money, scalePrice);
    insertRequest.input("stock", mssql.Float, stock);
    insertRequest.input("quantity", mssql.Float, quantity);
    insertRequest.input("username", mssql.NChar(10), username);

    await insertRequest.query(insertQuery);

    res.status(201).json({ message: "Table Updated successfully" });
  } catch (error) {
    console.error("Error processing GRN table insert:", error);
    res.status(500).json({ message: "Failed to update table" });
  }
};

//temp tog table
exports.updateTempTogTable = async (req, res) => {
  console.log(req.body);
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(403).json({ message: "No authorization token provided" });
    }

    const token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    const username = decoded.username;

    const {
      company,
      companyCodeTo,
      type,
      productCode,
      productName,
      costPrice,
      scalePrice,
      stock,
      quantity
    } = req.body;

    const insertQuery = `
      USE [RT_WEB]
      INSERT INTO tb_TOG_TEMP 
      (COMPANY_CODE, COMPANY_TO_CODE, TYPE, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE, CUR_STOCK, PHY_STOCK, REPUSER)
      VALUES (@company, @companyCodeTo, @type, @productCode, @productName, @costPrice, @scalePrice, @stock, @quantity, @username)
    `;

    const insertRequest = new mssql.Request();
    insertRequest.input("company", mssql.NChar(10), company);
    insertRequest.input("companyCodeTo", mssql.NChar(10), companyCodeTo);
    insertRequest.input("type", mssql.NChar(10), type);
    insertRequest.input("productCode", mssql.NChar(30), productCode);
    insertRequest.input("productName", mssql.NChar(50), productName);
    insertRequest.input("costPrice", mssql.Money, costPrice);
    insertRequest.input("scalePrice", mssql.Money, scalePrice);
    insertRequest.input("stock", mssql.Float, stock);
    insertRequest.input("quantity", mssql.Float, quantity);
    insertRequest.input("username", mssql.NChar(10), username);

    await insertRequest.query(insertQuery);

    res.status(201).json({ message: "Table Updated successfully" });
  } catch (error) {
    console.error("Error processing TOG insert:", error);
    res.status(500).json({ message: "Failed to update table" });
  }
};

//stock update delete
exports.stockUpdateDelete = async (req, res) => {
  try {
    const idx = parseInt(req.query.idx, 10);

    if (isNaN(idx)) {
      return res.status(400).json({ message: "Invalid or missing 'idx' parameter" });
    }

    const request = new mssql.Request();
    request.input("idx", mssql.Int, idx);

    const result = await request.query(`
      USE [RT_WEB]
      DELETE FROM tb_STOCKRECONCILATION_DATAENTRYTEMP WHERE IDX = @idx
    `);

    if (result.rowsAffected[0] === 0) {
      console.log("No stock data found to delete");
      return res.status(404).json({ message: "Stock data not found" });
    }

    res.status(200).json({ message: "Stock data deleted successfully" });
  } catch (error) {
    console.error("Error deleting stock data:", error);
    res.status(500).json({ message: "Failed to delete stock data" });
  }
};

//grnprn delete
exports.grnprnDelete = async (req, res) => {
  try {
    const { idx, type } = req.query;

    if (!idx || isNaN(parseInt(idx, 10))) {
      return res.status(400).json({ message: "Invalid or missing 'idx' parameter" });
    }

    const tableMap = {
      GRN: "tb_GRN_TEMP",
      PRN: "tb_PRN_TEMP",
      TOG: "tb_TOG_TEMP",
    };

    const tableName = tableMap[type];

    if (!tableName) {
      return res.status(400).json({ message: "Invalid 'type' parameter" });
    }

    const request = new mssql.Request();
    request.input("idx", mssql.Int, parseInt(idx, 10));

    const result = await request.query(`
      USE [RT_WEB]
      DELETE FROM dbo.${tableName} WHERE IDX = @idx
    `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ message: "Data not found" });
    }

    res.status(200).json({ message: "Data deleted successfully" });
  } catch (error) {
    console.error("Error deleting data:", error);
    res.status(500).json({ message: "Failed to delete data" });
  }
};

//reset database connection
exports.resetDatabaseConnection = async (req, res) => {
  const {
    name,
    ip = "",
    port = "",
    username,
    customerID = "",
    admin = [],
    dashboard = [],
    stock = [],
    removeAdmin = [],
    removeStock = [],
    removeDashboard = [],
  } = req.body;

  const trimmedName = name?.trim();
  const trimmedIP = ip?.trim();
  const trimmedPort = port?.trim();

  try {
    // Auth validation
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: "No authorization token provided" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(403).json({ message: "Token is missing" });

    try {
      jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    await mssql.close(); // close old connection

    // Connect to primary database
    const config = {
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      server: process.env.DB_SERVER,
      database: process.env.DB_DATABASE1,
      options: { encrypt: false, trustServerCertificate: true },
      port: 1443,
    };
    await mssql.connect(config);

    let dbResult;

    // IP and port update
    if (ip && port) {
      dbResult = await mssql.query`
        USE [RTPOS_MAIN]
        UPDATE tb_USERS SET ip_address = ${trimmedIP}, port = ${trimmedPort}, registered_by = ${username}
        WHERE username = ${trimmedName}
      `;
    } else if (ip) {
      dbResult = await mssql.query`
        USE [RTPOS_MAIN]
        UPDATE tb_USERS SET ip_address = ${trimmedIP}, registered_by = ${username}
        WHERE username = ${trimmedName}
      `;
    } else if (port) {
      dbResult = await mssql.query`
        USE [RTPOS_MAIN]
        UPDATE tb_USERS SET port = ${trimmedPort}, registered_by = ${username}
        WHERE username = ${trimmedName}
      `;
    }

    // Update customer ID
    if (customerID) {
      const req1 = new mssql.Request();
      req1.input("customerID", mssql.Int, customerID);
      req1.input("newName", mssql.NVarChar, trimmedName);
      const result = await req1.query(`
        USE [RTPOS_MAIN];
        UPDATE tb_USERS SET CUSTOMERID = @customerID WHERE username = @newName;
      `);
      if (result.rowsAffected[0] === 0) {
        return res.status(404).json({ message: "Customer ID was not updated." });
      }
    }

    // Utility function to update permissions
    const updatePermissions = async (columns, value) => {
      for (const column of columns) {
        if (!/^[a-zA-Z0-9_]+$/.test(column)) {
          return res.status(400).json({ message: `Invalid column name: ${column}` });
        }

        const query = `
          USE [RTPOS_MAIN];
          UPDATE tb_USERS SET ${column} = @value, registered_by = @registeredBy
          WHERE username = @username;
        `;

        const req2 = new mssql.Request();
        req2.input("value", value);
        req2.input("registeredBy", username);
        req2.input("username", trimmedName);

        const result = await req2.query(query);
        if (result.rowsAffected[0] === 0) {
          return res.status(404).json({ message: `Failed to update permission for ${column}` });
        }
      }
    };

    // Apply T (grant) / F (revoke) permissions
    await updatePermissions(admin, "T");
    await updatePermissions(dashboard, "T");
    await updatePermissions(stock, "T");
    await updatePermissions(removeAdmin, "F");
    await updatePermissions(removeDashboard, "F");
    await updatePermissions(removeStock, "F");

    // Check if nothing was sent
    const nothingToUpdate =
      !ip &&
      !port &&
      !customerID &&
      admin.length === 0 &&
      dashboard.length === 0 &&
      stock.length === 0 &&
      removeAdmin.length === 0 &&
      removeDashboard.length === 0 &&
      removeStock.length === 0;

    if (nothingToUpdate) {
      return res.status(400).json({ message: "Please provide details to update." });
    }

    return res.status(200).json({ message: "Database connection updated successfully" });
  } catch (err) {
    console.error("Error:", err);
    return res.status(500).json({ message: "Failed to update the database connection." });
  }
};

// Get dashboard data function
exports.dashboardOptions = async (req, res) => {
  try {
    // Ensure database connection is open
    if (!mssql.connected) {
      await mssql.connect({
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        server: process.env.DB_SERVER,
        database: process.env.DB_DATABASE2, // or RT_WEB
        options: {
          encrypt: false,
          trustServerCertificate: true,
        },
      });
    }

    const result = await mssql.query`
      USE [RT_WEB];
      SELECT COMPANY_CODE, COMPANY_NAME FROM tb_COMPANY;
    `;

    const records = result.recordset || [];

    if (records.length === 0) {
      return res.status(404).json({ message: "No companies found" });
    }

    const userData = records.map(({ COMPANY_CODE, COMPANY_NAME }) => ({
      COMPANY_CODE: COMPANY_CODE?.trim(),
      COMPANY_NAME: COMPANY_NAME?.trim(),
    }));

    return res.status(200).json({
      message: "Dashboard data retrieved successfully",
      userData,
    });
  } catch (error) {
    console.error("Error retrieving dashboard data:", error);
    return res.status(500).json({ message: "Failed to retrieve dashboard data" });
  }
};

// Get vendor data function
exports.vendorOptions = async (req, res) => {
  try {
    // Ensure MSSQL connection is active
    if (!mssql.connected) {
      await mssql.connect({
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        server: process.env.DB_SERVER,
        database: process.env.DB_DATABASE3 || 'POSBACK_SYSTEM',
        options: {
          encrypt: false,
          trustServerCertificate: true,
        },
      });
    }

    const result = await mssql.query`
      USE [POSBACK_SYSTEM];
      SELECT VENDORCODE, VENDORNAME FROM tb_VENDOR;
    `;

    const vendors = result.recordset || [];

    if (vendors.length === 0) {
      return res.status(404).json({ message: "No vendors found" });
    }

    const vendorData = vendors.map(({ VENDORCODE, VENDORNAME }) => ({
      VENDORCODE: VENDORCODE?.trim(),
      VENDORNAME: VENDORNAME?.trim(),
    }));

    return res.status(200).json({
      message: "Dashboard data retrieved successfully",
      vendorData,
    });
  } catch (error) {
    console.error("Error retrieving vendor data:", error);
    return res.status(500).json({ message: "Failed to retrieve vendor data" });
  }
};

