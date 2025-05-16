const { connectToDatabase } = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const moment = require("moment");
const mssql = require("mssql");
const crypto = require('crypto');
const nodemailer = require("nodemailer");
const { sendPasswordResetEmail } = require("../utils/nodemailer");
const { promisify } = require("util");
const verifyToken = promisify(jwt.verify);
const axios = require('axios');

const buildSqlInClause = (arr) => {
  return arr.map((val) => `'${val}'`).join(",");
};
const buildSqlInClause2 = (arr) => arr.map(code => `'${code}'`).join(",");

//report data, current report, company dashboard, 
// department dashboard, category dashboard, 
// sub category dashboard, vendor dashboard
function formatDate(dateString) {
  // Convert the input string to a Date object
  const dateObject = new Date(dateString);

  // Extract day, month, and year
  const day = String(dateObject.getDate()).padStart(2, "0"); // Ensures two digits
  const month = String(dateObject.getMonth() + 1).padStart(2, "0"); // Months are 0-indexed, so add 1
  const year = dateObject.getFullYear();

  // Return the formatted date as 'DD/MM/YYYY'
  return `${day}/${month}/${year}`;
}

async function syncDBConnection() {
  try {
    // If your pool is already connected, you can do:
    const request = new mssql.Request();
    const query = "SELECT * FROM tb_SYNCDB_USERS"; // Assuming db is set in connection config

    const result = await request.query(query);

    if (result.recordset.length === 0) {
      console.log("No customer data found in tb_SYNCDB_USERS.");
      return [];
    }

    return result.recordset;
  } catch (error) {
    console.error("Error fetching sync DB connection data:", error);
    return [];
  }
}

async function userItemsDetails(ReceiptDate, ReceiptNo) {
  try {
    // Create a new request object from the existing global connection or pool
    const request = new mssql.Request();

    // Query only the SELECT statement (db should be set in config)
    const result = await request.query`
      SELECT Item_Desc, ItemAmt, ItemDiscountAmt 
      FROM tb_OGFITEMSALE 
      WHERE ReceiptDate = ${ReceiptDate} 
        AND ReceiptNo = ${ReceiptNo} 
        AND UPLOAD <> 'T'
    `;

    if (result.recordset.length === 0) {
      console.log("No user items details found for given receipt.");
      return { error: "No user items details found" };
    }

    return result.recordset;
  } catch (error) {
    console.error("Error fetching user items details:", error);
    return { error: `Error fetching user items details: ${error.message}` };
  }
}

async function userPaymentDetails() {
  try {
    const request = new mssql.Request();

    const result = await request.query`
      SELECT 
        ReceiptNo, 
        MAX(ReceiptDate) AS ReceiptDate, 
        MAX(ReceiptTime) AS ReceiptTime, 
        SUM(NoOfItems) AS NoOfItems, 
        MAX(SalesCurrency) AS SalesCurrency, 
        SUM(TotalSalesAmtB4Tax) AS TotalSalesAmtB4Tax, 
        SUM(TotalSalesAmtAfterTax) AS TotalSalesAmtAfterTax, 
        SUM(SalesTaxRate) AS SalesTaxRate, 
        SUM(ServiceChargeAmt) AS ServiceChargeAmt, 
        SUM(PaymentAmt) AS PaymentAmt, 
        MAX(PaymentCurrency) AS PaymentCurrency, 
        (SELECT STUFF(
            (SELECT DISTINCT ',' + t2.PaymentMethod  
             FROM tb_OGFPAYMENT AS t2  
             WHERE t2.ReceiptNo = t1.ReceiptNo  
             FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 1, '')
        ) AS PaymentMethod, 
        MAX(SalesType) AS SalesType
      FROM tb_OGFPAYMENT AS t1 
      WHERE UPLOAD <> 'T'
      GROUP BY ReceiptNo;
    `;

    if (result.recordset.length === 0) {
      console.log("Cannot fetch user payment details");
      return { error: "Cannot fetch user payment details" };
    }

    return result.recordset;
  } catch (error) {
    console.error("Error fetching user payment details:", error);
    return { error: `Error fetching user payment details: ${error.message}` };
  }
}

async function userDetails() {
  try {
    const request = new mssql.Request();

    const result = await request.query`
      SELECT 
        AppCode, PropertyCode, POSInterfaceCode, BatchCode, SalesTaxRate, OAUTH_TOKEN_URL, 
        ClientID, ClientSecret, API_ENDPOINT  
      FROM tb_OGFMAIN;
    `;

    if (result.recordset.length === 0) {
      console.log("Cannot fetch user details");
      return;
    }

    // Trim string fields in the results
    const trimmedUserConnectionDetails = result.recordset.map((user) => {
      const trimmedUser = {};
      for (const key in user) {
        if (typeof user[key] === "string") {
          trimmedUser[key] = user[key].trim();
        } else {
          trimmedUser[key] = user[key];
        }
      }
      return trimmedUser;
    });

    return trimmedUserConnectionDetails;
  } catch (error) {
    console.error("Error fetching user connection details:", error);
  }
}

async function getAccessToken(user) {
  try {
    const data = qs.stringify({
      client_id: user.ClientID,
      client_secret: user.ClientSecret,
      grant_type: "client_credentials",
    });

    const agent = new https.Agent({ family: 4 }); // Force IPv4

    const response = await axios.post(user.OAUTH_TOKEN_URL, data, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      httpsAgent: agent,
      timeout: 10000, // 10 seconds timeout
    });

    return response.data.access_token;
  } catch (error) {
    console.error(
      `Error fetching token from ${user.OAUTH_TOKEN_URL}:`,
      error.response ? error.response.data : error.message
    );
    return null;
  }
}

function trimObjectStrings(obj) {
  if (obj === null || typeof obj !== "object") return obj;

  if (Array.isArray(obj)) {
    return obj.map(trimObjectStrings);
  }

  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => [
      key,
      typeof value === "string" ? value.trim() : trimObjectStrings(value),
    ])
  );
}

async function updateTables() {
  const transaction = new mssql.Transaction();
  try {
    await transaction.begin();

    const request = new mssql.Request(transaction);

    const updatePayment = await request.query(`
      UPDATE tb_OGFPAYMENT
      SET UPLOAD = 'T'
      WHERE UPLOAD <> 'T' OR UPLOAD IS NULL;
    `);

    const updateItems = await request.query(`
      UPDATE tb_OGFITEMSALE
      SET UPLOAD = 'T'
      WHERE UPLOAD <> 'T' OR UPLOAD IS NULL;
    `);

    await transaction.commit();

    const paymentRows = updatePayment.rowsAffected[0];
    const itemsRows = updateItems.rowsAffected[0];

    if (paymentRows === 0 && itemsRows === 0) {
      return {
        message: "No rows were updated in tb_OGFPAYMENT or tb_OGFITEMSALE",
        paymentRowsAffected: paymentRows,
        itemsRowsAffected: itemsRows,
      };
    }

    return {
      message: "Tables updated successfully",
      paymentRowsAffected: paymentRows,
      itemsRowsAffected: itemsRows,
    };
  } catch (error) {
    await transaction.rollback();
    return {
      message: "Could not update tables",
      error: error.message,
    };
  }
}

async function syncDB() {
  try {
    await mssql.close();
    await mssql.connect(dbConfig);

    const dbConnectionData = await syncDBConnection();

    if (!dbConnectionData || dbConnectionData.length === 0) {
      console.log("No customer data found.");
      return { responses: [], errors: ["No customer data found."] };
    }

    const apiResponses = [];
    const errors = [];

    for (const customer of dbConnectionData) {
      const syncdbIp = customer.IP ? customer.IP.trim() : null;
      const syncdbPort = customer.PORT ? parseInt(customer.PORT.trim()) : null;

      if (!syncdbIp) {
        const errMsg = "IP is null for a customer entry";
        console.log(errMsg);
        errors.push(errMsg);
        continue;
      }
      if (!syncdbPort) {
        const errMsg = `Port is null or invalid for IP: ${syncdbIp}`;
        console.log(errMsg);
        errors.push(errMsg);
        continue;
      }

      try {
        await mssql.close();

        const syncdbConfig = {
          user: process.env.DB_USER,
          password: process.env.DB_PASSWORD,
          server: syncdbIp,
          database: process.env.DB_DATABASE2,
          options: {
            encrypt: false,
            trustServerCertificate: true,
          },
          port: syncdbPort,
        };

        await mssql.connect(syncdbConfig);
        console.log(`Successfully connected to sync database at ${syncdbIp}:${syncdbPort}`);

        const users = await userDetails();
        if (!users || users.length === 0) {
          const msg = `No users found for IP: ${syncdbIp}`;
          console.log(msg);
          errors.push(msg);
          continue;
        }

        const payments = await userPaymentDetails();
        if (payments.error) {
          errors.push(payments.error);
          continue;
        }

        // Create HTTPS agent for API calls
        const agent = new https.Agent({ family: 4 });

        for (const user of users) {
          const {
            SalesTaxRate,
            OAUTH_TOKEN_URL,
            API_ENDPOINT,
            ...filteredUser
          } = user;

          const userResult = {
            AppCode: filteredUser.AppCode,
            PropertyCode: filteredUser.PropertyCode,
            ClientID: filteredUser.ClientID,
            ClientSecret: filteredUser.ClientSecret,
            POSInterfaceCode: filteredUser.POSInterfaceCode,
            BatchCode: filteredUser.BatchCode,
            PosSales: [],
          };

          for (const payment of payments) {
            const { IDX, UPLOAD, Insert_Time, ...filteredPayment } = payment;

            const formattedDate = new Date(payment.ReceiptDate)
              .toLocaleDateString("en-GB")
              .replace(/\//g, "/");

            const formattedTime = new Date(payment.ReceiptTime)
              .toLocaleTimeString("en-GB", { hour12: false });

            const newPaymentDetails = {
              PropertyCode: filteredUser.PropertyCode,
              POSInterfaceCode: filteredUser.POSInterfaceCode,
              ...filteredPayment,
              ReceiptDate: formattedDate,
              ReceiptTime: formattedTime,
            };

            const items = await userItemsDetails(payment.ReceiptDate, payment.ReceiptNo);
            if (items.error) {
              errors.push(items.error);
            }

            const paymentWithItems = {
              ...newPaymentDetails,
              Items: items,
            };

            userResult.PosSales.push(trimObjectStrings(paymentWithItems));
          }

          const token = await getAccessToken(user);
          if (!token) {
            const errorMsg = `Skipping API call for user ${user.AppCode} due to token error.`;
            console.error(errorMsg);
            errors.push(errorMsg);
            continue; // skip this user, move on to next
          }

          const requestBody = JSON.stringify(trimObjectStrings(userResult), null, 2);
          console.log("Sending JSON Payload:", requestBody);

          try {
            const response = await axios.post(user.API_ENDPOINT, requestBody, {
              headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
                Accept: "application/json",
              },
              httpsAgent: agent,
              transformRequest: [(data) => data],
              timeout: 10000,
            });

            console.log(`API Call Successful for user ${user.AppCode}:`, response.data);
            apiResponses.push(response.data);
          } catch (error) {
            const errorMessage = `API Call Failed for user ${user.AppCode}: ${error.response?.data || error.message}`;
            console.error(errorMessage);
            errors.push(errorMessage);
            apiResponses.push({ error: errorMessage });
          }
        }

        await mssql.close(); // close connection after finishing this customer
      } catch (err) {
        const errMsg = `Database Connection Error for IP ${syncdbIp}: ${err.message}`;
        console.error(errMsg);
        errors.push(errMsg);
      }
    }

    return { responses: apiResponses, errors };
  } catch (error) {
    console.error("Unexpected error occurred in syncDB:", error);
    return { responses: [], errors: [error.message] };
  }
}


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

//report data
exports.reportData = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(403).json({ message: "No authorization token provided" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(403).json({ message: "Token is missing" });
    }

    const decoded = await verifyToken(token, process.env.JWT_SECRET);
    const username = decoded.username;

    const { fromDate, toDate, invoiceNo, selectedOptions } = req.query;

    if (!fromDate || !toDate || !Array.isArray(selectedOptions) || selectedOptions.length === 0) {
      return res.status(400).json({ message: "Missing required parameters" });
    }

    const formattedFromDate = formatDate(fromDate);
    const formattedToDate = formatDate(toDate);
    const reportType = "INVOICEWISE";

    // Clean start: delete previous report for user
    await mssql.query`
      USE RT_WEB;
      DELETE FROM tb_SALESVIEW WHERE REPUSER = ${username};
    `;

    // Run SP for each company
    for (const companyCode of selectedOptions) {
      await mssql.query`
        EXEC RT_WEB.dbo.Sp_SalesView 
        @COMPANY_CODE = ${companyCode},
        @DATE1 = ${formattedFromDate},
        @DATE2 = ${formattedToDate},
        @REPUSER = ${username},
        @REPORT_TYPE = ${reportType};
      `;
    }

    // Main report data
    const reportQuery = await mssql.query`
      USE RT_WEB;
      SELECT 
        INVOICENO, COMPANY_CODE, UNITNO, REPNO, 'CASH' AS PRODUCT_NAME, 
        ISNULL(SUM(CASE PRODUCT_NAME 
          WHEN 'CASH' THEN AMOUNT 
          WHEN 'BALANCE' THEN -AMOUNT 
          ELSE 0 END), 0) AS AMOUNT, 
        SALESDATE
      FROM tb_SALESVIEW 
      WHERE (ID='PT' OR ID='BL') 
        AND (PRODUCT_NAME = 'CASH' OR PRODUCT_NAME = 'BALANCE') 
        AND REPUSER = ${username}
      GROUP BY COMPANY_CODE, SALESDATE, UNITNO, REPNO, INVOICENO

      UNION ALL

      SELECT 
        INVOICENO, COMPANY_CODE, UNITNO, REPNO, PRODUCT_NAME, 
        ISNULL(SUM(AMOUNT), 0) AS AMOUNT, SALESDATE
      FROM tb_SALESVIEW 
      WHERE ID='PT' AND PRODUCT_NAME NOT IN ('CASH', 'BALANCE') 
        AND REPUSER = ${username}
      GROUP BY COMPANY_CODE, SALESDATE, UNITNO, REPNO, INVOICENO, PRODUCT_NAME;
    `;

    // Invoice detail data if requested
    let invoiceData = [];
    if (invoiceNo) {
      const result = await mssql.query`
        USE RT_WEB;
        SELECT INVOICENO, PRODUCT_NAME, QTY, AMOUNT, COSTPRICE, UNITPRICE, DISCOUNT 
        FROM tb_SALESVIEW 
        WHERE INVOICENO = ${invoiceNo} 
          AND ID IN ('SL', 'SLF', 'RF', 'RFF') 
          AND REPUSER = ${username};
      `;
      invoiceData = result.recordset;
    }

    res.status(200).json({
      message: "Invoice data found",
      success: true,
      reportData: reportQuery.recordset || [],
      invoiceData: invoiceData || [],
    });

  } catch (error) {
    console.error("Error generating report:", error);
    res.status(500).json({ message: "Failed to generate report" });
  }
};

//current report
exports.currentReportData = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(403).json({ message: "No authorization token provided" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(403).json({ message: "Token is missing" });
    }

    const decoded = await verifyToken(token, process.env.JWT_SECRET);
    const username = decoded.username;

    const { companyCodes, currentDate, invoiceNo } = req.query;

    if (!Array.isArray(companyCodes) || companyCodes.length === 0 || !currentDate) {
      return res.status(400).json({ message: "Missing or invalid parameters" });
    }

    const date = formatDate(currentDate);
    const reportType = "INVOICEWISE";

    // Step 1: Clean previous report data
    await mssql.query`
      USE RT_WEB;
      DELETE FROM tb_SALESVIEW WHERE REPUSER = ${username};
    `;

    // Step 2: Execute SP for each company
    for (const companyCode of companyCodes) {
      await mssql.query`
        EXEC RT_WEB.dbo.Sp_SalesCurView 
        @COMPANY_CODE = ${companyCode}, 
        @DATE = ${date}, 
        @REPUSER = ${username}, 
        @REPORT_TYPE = ${reportType};
      `;
    }

    // Step 3: Fetch summarized report data
    const reportQuery = await mssql.query`
      USE RT_WEB;
      SELECT 
        INVOICENO, COMPANY_CODE, UNITNO, REPNO, 'CASH' AS PRODUCT_NAME, 
        ISNULL(SUM(CASE PRODUCT_NAME 
          WHEN 'CASH' THEN AMOUNT 
          WHEN 'BALANCE' THEN -AMOUNT 
          ELSE 0 END), 0) AS AMOUNT, 
        SALESDATE
      FROM tb_SALESVIEW 
      WHERE (ID = 'PT' OR ID = 'BL') 
        AND PRODUCT_NAME IN ('CASH', 'BALANCE') 
        AND REPUSER = ${username}
      GROUP BY COMPANY_CODE, SALESDATE, UNITNO, REPNO, INVOICENO

      UNION ALL

      SELECT 
        INVOICENO, COMPANY_CODE, UNITNO, REPNO, PRODUCT_NAME, 
        ISNULL(SUM(AMOUNT), 0) AS AMOUNT, SALESDATE
      FROM tb_SALESVIEW 
      WHERE ID = 'PT' 
        AND PRODUCT_NAME NOT IN ('CASH', 'BALANCE') 
        AND REPUSER = ${username}
      GROUP BY COMPANY_CODE, SALESDATE, UNITNO, REPNO, INVOICENO, PRODUCT_NAME;
    `;

    // Step 4: Fetch detailed invoice data if requested
    let invoiceData = [];
    if (invoiceNo) {
      const result = await mssql.query`
        USE RT_WEB;
        SELECT INVOICENO, PRODUCT_NAME, QTY, AMOUNT, COSTPRICE, UNITPRICE, DISCOUNT 
        FROM tb_SALESVIEW 
        WHERE INVOICENO = ${invoiceNo} 
          AND ID IN ('SL', 'SLF', 'RF', 'RFF') 
          AND REPUSER = ${username};
      `;
      invoiceData = result.recordset;
    }

    // Step 5: Respond
    res.status(200).json({
      message: "Invoice data found",
      success: true,
      reportData: reportQuery.recordset || [],
      invoiceData,
    });

  } catch (error) {
    console.error("Error retrieving current report data:", error);
    res.status(500).json({ message: "Failed to retrieve current report data" });
  }
};

//company dashboard
exports.loadingDashboard = async (req, res) => {
  try {
    // Auth
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: "No authorization token provided" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(403).json({ message: "Token is missing" });

    const decoded = await verifyToken(token, process.env.JWT_SECRET);
    const username = decoded.username;

    const { currentDate, fromDate, toDate, selectedOptions } = req.query;

    if (!Array.isArray(selectedOptions) || selectedOptions.length === 0) {
      return res.status(400).json({ message: "Invalid or missing company codes" });
    }

    const formattedCurrentDate = formatDate(currentDate);
    const formattedFromDate = formatDate(fromDate);
    const formattedToDate = formatDate(toDate);
    const reportType = "SALESSUM1";

    // Clear previous dashboard view data
    await mssql.query`USE RT_WEB; DELETE FROM tb_SALES_DASHBOARD_VIEW WHERE REPUSER = ${username};`;

    // Execute stored procedures per company
    for (const companyCode of selectedOptions) {
      if (fromDate && toDate) {
        await mssql.query`
          EXEC RT_WEB.dbo.Sp_SalesView 
            @COMPANY_CODE = ${companyCode}, 
            @DATE1 = ${formattedFromDate}, 
            @DATE2 = ${formattedToDate}, 
            @REPUSER = ${username}, 
            @REPORT_TYPE = ${reportType};
        `;
      } else {
        await mssql.query`
          EXEC RT_WEB.dbo.Sp_SalesCurView 
            @COMPANY_CODE = ${companyCode}, 
            @DATE = ${formattedCurrentDate}, 
            @REPUSER = ${username}, 
            @REPORT_TYPE = ${reportType};
        `;
      }
    }

    // Query results
    const companyCodesList = selectedOptions.map((_, i) => `@code${i}`).join(", ");
    const params = selectedOptions.reduce((acc, code, i) => {
      acc[`code${i}`] = code;
      return acc;
    }, {});

    // One row summary
    const loadingDashboardResult = await mssql.query({
      query: `
        USE RT_WEB;
        SELECT 
          SUM(NETSALES) AS NETSALES,
          SUM(CASHSALES) AS CASHSALES,
          SUM(CARDSALES) AS CARDSALES,
          SUM(CREDITSALES) AS CREDITSALES,
          SUM(OTHER_PAYMENT) AS OTHER_PAYMENT,
          SUM(GVOUCHER_SALE) AS GIFT_VOUCHER,
          SUM(PAIDOUT) AS PAIDOUT,
          SUM(CASHINHAND) AS CASHINHAND
        FROM tb_SALES_DASHBOARD_VIEW
        WHERE REPUSER = @username AND COMPANY_CODE IN (${companyCodesList});
      `,
      params: { username, ...params }
    });

    // Per company
    const record = await mssql.query({
      query: `
        USE RT_WEB;
        SELECT 
          COMPANY_CODE,      
          SUM(NETSALES) AS NETSALES, 
          SUM(CASHSALES) AS CASHSALES, 
          SUM(CARDSALES) AS CARDSALES, 
          SUM(CREDITSALES) AS CREDITSALES, 
          SUM(OTHER_PAYMENT) AS OTHER_PAYMENT,
          SUM(GVOUCHER_SALE) AS GIFT_VOUCHER,
          SUM(PAIDOUT) AS PAIDOUT,
          SUM(CASHINHAND) AS CASHINHAND
        FROM tb_SALES_DASHBOARD_VIEW
        WHERE REPUSER = @username AND COMPANY_CODE IN (${companyCodesList})
        GROUP BY COMPANY_CODE;
      `,
      params: { username, ...params }
    });

    // Per unit
    const cashierPointRecord = await mssql.query({
      query: `
        USE RT_WEB;
        SELECT 
          COMPANY_CODE, 
          UNITNO, 
          SUM(NETSALES) AS NETSALES, 
          SUM(CASHSALES) AS CASHSALES, 
          SUM(CARDSALES) AS CARDSALES, 
          SUM(CREDITSALES) AS CREDITSALES, 
          SUM(OTHER_PAYMENT) AS OTHER_PAYMENT,
          SUM(GVOUCHER_SALE) AS GIFT_VOUCHER,
          SUM(PAIDOUT) AS PAIDOUT,
          SUM(CASHINHAND) AS CASHINHAND
        FROM tb_SALES_DASHBOARD_VIEW
        WHERE REPUSER = @username AND COMPANY_CODE IN (${companyCodesList})
        GROUP BY COMPANY_CODE, UNITNO;
      `,
      params: { username, ...params }
    });

    const formattedResult = loadingDashboardResult.recordset.map(row => ({
      NETSALES: parseFloat(row.NETSALES).toFixed(2),
      CASHSALES: parseFloat(row.CASHSALES).toFixed(2),
      CARDSALES: parseFloat(row.CARDSALES).toFixed(2),
      CREDITSALES: parseFloat(row.CREDITSALES).toFixed(2),
      OTHER_PAYMENT: parseFloat(row.OTHER_PAYMENT).toFixed(2),
      GIFT_VOUCHER: parseFloat(row.GIFT_VOUCHER).toFixed(2),
      PAIDOUT: parseFloat(row.PAIDOUT).toFixed(2),
      CASHINHAND: parseFloat(row.CASHINHAND).toFixed(2),
    }));

    res.status(200).json({
      message: "Processed parameters for company codes",
      success: true,
      result: formattedResult,
      record: record.recordset,
      cashierPointRecord: cashierPointRecord.recordset,
    });

  } catch (error) {
    console.error("Error loading dashboard:", error);
    res.status(500).json({ message: "Failed to load dashboard data" });
  }
};

//department dashboard
exports.departmentDashboard = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(403).json({ message: "No authorization token provided" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(403).json({ message: "Token is missing" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: "Invalid or expired token" });
      }

      const username = decoded.username;
      const { currentDate, fromDate, toDate, selectedOptions } = req.query;

      if (!Array.isArray(selectedOptions) || selectedOptions.length === 0) {
        return res.status(400).json({ message: "No company codes provided" });
      }

      const formattedCurrentDate = formatDate(currentDate);
      const formattedFromDate = formatDate(fromDate);
      const formattedToDate = formatDate(toDate);
      const reportType = "SALESDET";

      try {
        await mssql.query`
          USE [RT_WEB];
          DELETE FROM tb_SALESVIEW WHERE REPUSER = ${username}`;
      } catch (deleteErr) {
        console.error("Error deleting previous records:", deleteErr);
      }

      // Call SPs based on date range
      for (let i = 0; i < selectedOptions.length; i++) {
        const companyCode = String(selectedOptions[i]);

        try {
          if (fromDate && toDate) {
            await mssql.query`
              EXEC Sp_SalesView @COMPANY_CODE = ${companyCode}, 
                                @DATE1 = ${formattedFromDate}, 
                                @DATE2 = ${formattedToDate}, 
                                @REPUSER = ${username}, 
                                @REPORT_TYPE = ${reportType}`;
          } else {
            await mssql.query`
              EXEC Sp_SalesCurView @COMPANY_CODE = ${companyCode}, 
                                   @DATE = ${formattedCurrentDate}, 
                                   @REPUSER = ${username}, 
                                   @REPORT_TYPE = ${reportType}`;
          }
        } catch (spErr) {
          console.error(`Error executing stored procedure for ${companyCode}:`, spErr);
        }
      }

      const inClause = buildSqlInClause(selectedOptions);

      // Fetch department sales data
      const [tableRecords, amountBarChart, quantityBarChart] = await Promise.all([
        mssql.query(`
          USE [RT_WEB];
          SELECT   
            LTRIM(RTRIM(COMPANY_CODE)) AS COMPANY_CODE,
            LTRIM(RTRIM(DEPTCODE)) AS DEPARTMENT_CODE,
            DEPTNAME AS DEPARTMENT_NAME,
            SUM(QTY) AS QUANTITY,
            SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY COMPANY_CODE, DEPTCODE, DEPTNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT DEPTNAME, SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY DEPTNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT DEPTNAME, SUM(QTY) AS QUANTITY
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY DEPTNAME`, { username }),
      ]);

      return res.status(200).json({
        message: "Processed parameters for company codes",
        success: true,
        tableRecords: tableRecords.recordset || [],
        amountBarChart: amountBarChart.recordset || [],
        quantityBarChart: quantityBarChart.recordset || [],
      });
    });
  } catch (error) {
    console.error("Unhandled error in departmentDashboard:", error);
    return res.status(500).json({ message: "Failed to load department dashboard" });
  }
};

//category dashboard
exports.categoryDashboard = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: "No authorization token provided" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(403).json({ message: "Token is missing" });

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Invalid or expired token" });

      const username = decoded.username;
      const { currentDate, fromDate, toDate, selectedOptions } = req.query;

      if (!Array.isArray(selectedOptions) || selectedOptions.length === 0) {
        return res.status(400).json({ message: "No company codes provided" });
      }

      const formattedCurrentDate = formatDate(currentDate);
      const formattedFromDate = formatDate(fromDate);
      const formattedToDate = formatDate(toDate);
      const reportType = "SALESDET";

      try {
        await mssql.query`USE [RT_WEB]; DELETE FROM tb_SALESVIEW WHERE REPUSER = ${username}`;
      } catch (err) {
        console.error("Error clearing tb_SALESVIEW:", err);
      }

      // Run stored procedures
      for (const companyCode of selectedOptions) {
        try {
          if (fromDate && toDate) {
            await mssql.query`
              EXEC Sp_SalesView 
                @COMPANY_CODE = ${companyCode}, 
                @DATE1 = ${formattedFromDate}, 
                @DATE2 = ${formattedToDate}, 
                @REPUSER = ${username}, 
                @REPORT_TYPE = ${reportType}`;
          } else {
            await mssql.query`
              EXEC Sp_SalesCurView 
                @COMPANY_CODE = ${companyCode}, 
                @DATE = ${formattedCurrentDate}, 
                @REPUSER = ${username}, 
                @REPORT_TYPE = ${reportType}`;
          }
        } catch (err) {
          console.error(`Error running SP for company ${companyCode}:`, err);
        }
      }

      const inClause = buildSqlInClause(selectedOptions);

      // Run summary queries
      const [categoryTableRecords, categoryAmountBarChart, categoryQuantityBarChart] = await Promise.all([
        mssql.query(`
          USE [RT_WEB];
          SELECT
            LTRIM(RTRIM(COMPANY_CODE)) AS COMPANY_CODE,
            LTRIM(RTRIM(CATCODE)) AS CATEGORY_CODE,
            CATNAME AS CATEGORY_NAME,
            SUM(QTY) AS QUANTITY,
            SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY COMPANY_CODE, CATCODE, CATNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT CATNAME, SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY CATNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT CATNAME, SUM(QTY) AS QUANTITY
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY CATNAME`, { username }),
      ]);

      return res.status(200).json({
        message: "Processed parameters for company codes",
        success: true,
        categoryTableRecords: categoryTableRecords.recordset || [],
        categoryAmountBarChart: categoryAmountBarChart.recordset || [],
        categoryQuantityBarChart: categoryQuantityBarChart.recordset || [],
      });
    });
  } catch (error) {
    console.error("Unhandled error in categoryDashboard:", error);
    res.status(500).json({ message: "Failed to load category dashboard" });
  }
};

//sub category dashboard
exports.subCategoryDashboard = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: "No authorization token provided" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(403).json({ message: "Token is missing" });

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Invalid or expired token" });

      const username = decoded.username;
      const { currentDate, fromDate, toDate, selectedOptions } = req.query;

      if (!Array.isArray(selectedOptions) || selectedOptions.length === 0) {
        return res.status(400).json({ message: "No company codes provided" });
      }

      const formattedCurrentDate = formatDate(currentDate);
      const formattedFromDate = formatDate(fromDate);
      const formattedToDate = formatDate(toDate);
      const reportType = "SALESDET";

      try {
        await mssql.query`USE [RT_WEB]; DELETE FROM tb_SALESVIEW WHERE REPUSER = ${username}`;
      } catch (error) {
        console.error("Error clearing tb_SALESVIEW:", error);
      }

      for (const companyCode of selectedOptions) {
        try {
          if (fromDate && toDate) {
            await mssql.query`
              EXEC Sp_SalesView 
                @COMPANY_CODE = ${companyCode}, 
                @DATE1 = ${formattedFromDate}, 
                @DATE2 = ${formattedToDate}, 
                @REPUSER = ${username}, 
                @REPORT_TYPE = ${reportType}`;
          } else {
            await mssql.query`
              EXEC Sp_SalesCurView 
                @COMPANY_CODE = ${companyCode}, 
                @DATE = ${formattedCurrentDate}, 
                @REPUSER = ${username}, 
                @REPORT_TYPE = ${reportType}`;
          }
        } catch (error) {
          console.error(`Error running SP for company ${companyCode}:`, error);
        }
      }

      const inClause = buildSqlInClause2(selectedOptions);

      const [subCategoryTableRecords, subCategoryAmountBarChart, subCategoryQuantityBarChart] = await Promise.all([
        mssql.query(`
          USE [RT_WEB];
          SELECT
            LTRIM(RTRIM(COMPANY_CODE)) AS COMPANY_CODE,
            LTRIM(RTRIM(SCATCODE)) AS SUBCATEGORY_CODE,
            SCATNAME AS SUBCATEGORY_NAME,
            SUM(QTY) AS QUANTITY,
            SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY COMPANY_CODE, SCATCODE, SCATNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT SCATNAME, SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY SCATNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT SCATNAME, SUM(QTY) AS QUANTITY
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY SCATNAME`, { username }),
      ]);

      return res.status(200).json({
        message: "Processed parameters for company codes",
        success: true,
        subCategoryTableRecords: subCategoryTableRecords.recordset || [],
        subCategoryAmountBarChart: subCategoryAmountBarChart.recordset || [],
        subCategoryQuantityBarChart: subCategoryQuantityBarChart.recordset || [],
      });
    });
  } catch (error) {
    console.error("Unhandled error in subCategoryDashboard:", error);
    res.status(500).json({ message: "Failed to load subcategory dashboard" });
  }
};

//vendor dashboard
exports.vendorDashboard = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: "No authorization token provided" });

    const token = authHeader.split(" ")[1];
    if (!token) return res.status(403).json({ message: "Token is missing" });

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Invalid or expired token" });

      const username = decoded.username;
      const { currentDate, fromDate, toDate, selectedOptions } = req.query;

      if (!Array.isArray(selectedOptions) || selectedOptions.length === 0) {
        return res.status(400).json({ message: "No company codes provided" });
      }

      const formattedCurrentDate = formatDate(currentDate);
      const formattedFromDate = formatDate(fromDate);
      const formattedToDate = formatDate(toDate);
      const reportType = "SALESDET";
      const inClause = buildSqlInClause(selectedOptions);

      try {
        await mssql.query`USE [RT_WEB]; DELETE FROM tb_SALESVIEW WHERE REPUSER = ${username}`;
      } catch (error) {
        console.error("Error deleting tb_SALESVIEW records:", error);
      }

      for (const companyCode of selectedOptions) {
        try {
          if (fromDate && toDate) {
            await mssql.query`
              EXEC Sp_SalesView 
                @COMPANY_CODE = ${companyCode},
                @DATE1 = ${formattedFromDate},
                @DATE2 = ${formattedToDate},
                @REPUSER = ${username},
                @REPORT_TYPE = ${reportType}`;
          } else {
            await mssql.query`
              EXEC Sp_SalesCurView 
                @COMPANY_CODE = ${companyCode},
                @DATE = ${formattedCurrentDate},
                @REPUSER = ${username},
                @REPORT_TYPE = ${reportType}`;
          }
        } catch (error) {
          console.error(`Error running SP for company ${companyCode}:`, error);
        }
      }

      const [vendorTableRecords, vendorAmountBarChart, vendorQuantityBarChart] = await Promise.all([
        mssql.query(`
          USE [RT_WEB];
          SELECT
            LTRIM(RTRIM(COMPANY_CODE)) AS COMPANY_CODE,
            LTRIM(RTRIM(VENDORCODE)) AS VENDOR_CODE,
            VENDORNAME AS VENDOR_NAME,
            SUM(QTY) AS QUANTITY,
            SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY COMPANY_CODE, VENDORCODE, VENDORNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT VENDORNAME, SUM(AMOUNT) AS AMOUNT
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY VENDORNAME`, { username }),

        mssql.query(`
          USE [RT_WEB];
          SELECT VENDORNAME, SUM(QTY) AS QUANTITY
          FROM tb_SALESVIEW
          WHERE REPUSER = @username AND COMPANY_CODE IN (${inClause})
          GROUP BY VENDORNAME`, { username }),
      ]);

      return res.status(200).json({
        message: "Processed parameters for company codes",
        success: true,
        vendorTableRecords: vendorTableRecords.recordset || [],
        vendorAmountBarChart: vendorAmountBarChart.recordset || [],
        vendorQuantityBarChart: vendorQuantityBarChart.recordset || [],
      });
    });
  } catch (error) {
    console.error("Unhandled error in vendorDashboard:", error);
    res.status(500).json({ message: "Failed to load vendor dashboard" });
  }
};

// sales scan
exports.scan = async (req, res) => {
  const codeData = req.query.data?.trim();
  const company = req.query.company?.trim();

  if (!codeData || codeData === "No result") {
    return res.status(400).json({ message: "Please provide a valid barcode or product code" });
  }

  if (!company) {
    return res.status(400).json({ message: "Company code is required" });
  }

  try {
    let productCode = null;

    // Try finding a product code via barcode link table
    const barcodeResult = await mssql.query`
      USE [POSBACK_SYSTEM];
      SELECT PRODUCT_CODE FROM tb_BARCODELINK WHERE BARCODE = ${codeData};
    `;

    if (barcodeResult.recordset.length > 0) {
      productCode = barcodeResult.recordset[0].PRODUCT_CODE;
    }

    // If not found in barcode link, use product table directly
    const productQuery = productCode
      ? mssql.query`
        USE [POSBACK_SYSTEM];
        SELECT PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, SCALEPRICE 
        FROM tb_PRODUCT WHERE PRODUCT_CODE = ${productCode};`
      : mssql.query`
        USE [POSBACK_SYSTEM];
        SELECT PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, SCALEPRICE 
        FROM tb_PRODUCT 
        WHERE PRODUCT_CODE = ${codeData} OR BARCODE = ${codeData} OR BARCODE2 = ${codeData};`;

    const salesDataResult = await productQuery;
    const salesData = salesDataResult.recordset;

    if (!salesData || salesData.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    const foundCode = salesData[0].PRODUCT_CODE;

    const stockResult = await mssql.query`
      USE [POSBACK_SYSTEM];
      SELECT ISNULL(SUM(STOCK), 0) AS STOCK 
      FROM tb_STOCK 
      WHERE COMPANY_CODE = ${company} 
        AND (BIN = 'F' OR BIN IS NULL) 
        AND PRODUCT_CODE = ${foundCode};
    `;

    const stockQty = stockResult.recordset[0]?.STOCK ?? 0;

    return res.status(200).json({
      message: "Item Found Successfully",
      salesData,
      amount: stockQty,
    });

  } catch (error) {
    console.error("Error retrieving barcode data:", error);
    return res.status(500).json({ message: "Failed to retrieve barcode data" });
  }
};

// stock update
exports.stockUpdate = async (req, res) => {
  const { name, code } = req.query;

  // Validate required query parameters
  if (!name || !code) {
    return res.status(400).json({ message: "Missing required query parameters: name and/or code" });
  }

  const username = String(name).trim();
  const company = String(code).trim();

  try {
    const stockData = await mssql.query`
      USE [RT_WEB];
      SELECT 
        IDX,
        COMPANY_CODE,
        TYPE,
        COUNT_STATUS,
        PRODUCT_CODE,
        PRODUCT_NAMELONG,
        COSTPRICE,
        UNITPRICE,
        CUR_STOCK,
        PHY_STOCK
      FROM tb_STOCKRECONCILATION_DATAENTRYTEMP 
      WHERE REPUSER = ${username} AND COMPANY_CODE = ${company} AND TYPE = 'STK';
    `;

    const records = stockData.recordset;

    if (!records || records.length === 0) {
      return res.status(404).json({ message: "Stock data not found" });
    }

    return res.status(200).json({
      message: "Stock data Found Successfully",
      stockData: records,
    });
  } catch (error) {
    console.error("Error retrieving stock data:", error);
    return res.status(500).json({ message: "Failed to retrieve stock data" });
  }
};

// GRN/PRN/TOG table for scan page
exports.grnprnTableData = async (req, res) => {
  const { name, code } = req.query;

  // Validate input
  if (!name || !code) {
    return res.status(400).json({ message: "Missing required query parameters: name and/or code" });
  }

  const username = String(name).trim();
  const company = String(code).trim();

  try {
    const grnDataPromise = mssql.query`
      USE [RT_WEB];
      SELECT IDX, COMPANY_CODE, VENDOR_CODE, VENDOR_NAME, INVOICE_NO, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE, CUR_STOCK, PHY_STOCK
      FROM tb_GRN_TEMP 
      WHERE REPUSER = ${username} AND COMPANY_CODE = ${company} AND TYPE = 'GRN';
    `;

    const prnDataPromise = mssql.query`
      USE [RT_WEB];
      SELECT IDX, COMPANY_CODE, VENDOR_CODE, VENDOR_NAME, INVOICE_NO, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE, CUR_STOCK, PHY_STOCK
      FROM tb_PRN_TEMP 
      WHERE REPUSER = ${username} AND COMPANY_CODE = ${company} AND TYPE = 'PRN';
    `;

    const togDataPromise = mssql.query`
      USE [RT_WEB];
      SELECT IDX, COMPANY_CODE, COMPANY_TO_CODE, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE, CUR_STOCK, PHY_STOCK
      FROM tb_TOG_TEMP 
      WHERE REPUSER = ${username} AND COMPANY_CODE = ${company} AND TYPE = 'TOG';
    `;

    // Execute all queries in parallel
    const [grnData, prnData, togData] = await Promise.all([
      grnDataPromise,
      prnDataPromise,
      togDataPromise,
    ]);

    // Check if all are empty
    if (
      grnData.recordset.length === 0 &&
      prnData.recordset.length === 0 &&
      togData.recordset.length === 0
    ) {
      return res.status(404).json({ message: "No GRN/PRN/TOG data found" });
    }

    return res.status(200).json({
      message: "Data Found Successfully",
      grnData: grnData.recordset,
      prnData: prnData.recordset,
      togData: togData.recordset,
    });
  } catch (error) {
    console.error("Error retrieving GRN/PRN/TOG data:", error);
    return res.status(500).json({ message: "Failed to retrieve data" });
  }
};

// stock update final
exports.finalStockUpdate = async (req, res) => {
  const { username, company } = req.query;

  if (!username || !company) {
    return res.status(400).json({
      success: false,
      message: "Missing 'username' or 'company' parameter",
    });
  }

  let transaction;

  try {
    transaction = new mssql.Transaction();
    await transaction.begin();

    // Step 1: Retrieve data
    const selectResult = await new mssql.Request(transaction)
      .input("REPUSER", mssql.NVarChar(10), username)
      .input("COMPANY_CODE", mssql.NChar(10), company)
      .query(`
        SELECT * FROM [RT_WEB].dbo.tb_STOCKRECONCILATION_DATAENTRYTEMP 
        WHERE REPUSER = @REPUSER AND COMPANY_CODE = @COMPANY_CODE
      `);

    const dataRows = selectResult.recordset;

    if (dataRows.length === 0) {
      await transaction.rollback();
      return res.status(404).json({ success: false, message: "No data found" });
    }

    // Step 2: Insert data into main table
    const insertQuery = `
      INSERT INTO [RT_WEB].dbo.tb_STOCKRECONCILATION_DATAENTRY (
        COMPANY_CODE, PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE,
        CUR_STOCK, PHY_STOCK, TYPE, COUNT_STATUS, REPUSER
      )
      VALUES (
        @COMPANY_CODE, @PRODUCT_CODE, @PRODUCT_NAMELONG, @COSTPRICE, @UNITPRICE,
        @CUR_STOCK, @PHY_STOCK, @TYPE, @COUNT_STATUS, @REPUSER
      )
    `;

    let insertCount = 0;

    for (const row of dataRows) {
      const insert = await new mssql.Request(transaction)
        .input("COMPANY_CODE", mssql.NChar(10), row.COMPANY_CODE)
        .input("PRODUCT_CODE", mssql.NChar(30), row.PRODUCT_CODE)
        .input("PRODUCT_NAMELONG", mssql.NVarChar(50), row.PRODUCT_NAMELONG)
        .input("COSTPRICE", mssql.Money, row.COSTPRICE)
        .input("UNITPRICE", mssql.Money, row.UNITPRICE)
        .input("CUR_STOCK", mssql.Float, row.CUR_STOCK)
        .input("PHY_STOCK", mssql.Float, row.PHY_STOCK)
        .input("TYPE", mssql.NChar(10), row.TYPE)
        .input("COUNT_STATUS", mssql.NChar(10), row.COUNT_STATUS)
        .input("REPUSER", mssql.NVarChar(10), row.REPUSER)
        .query(insertQuery);

      if (insert.rowsAffected?.[0] > 0) insertCount += insert.rowsAffected[0];
    }

    if (insertCount === 0) {
      await transaction.rollback();
      return res.status(400).json({
        success: false,
        message: "No records were inserted into final table.",
      });
    }

    // Step 3: Delete original data
    const deleteResult = await new mssql.Request(transaction)
      .input("REPUSER", mssql.NVarChar(10), username)
      .input("COMPANY_CODE", mssql.NChar(10), company)
      .query(`
        DELETE FROM [RT_WEB].dbo.tb_STOCKRECONCILATION_DATAENTRYTEMP
        WHERE REPUSER = @REPUSER AND COMPANY_CODE = @COMPANY_CODE
      `);

    if (deleteResult.rowsAffected?.[0] === 0) {
      await transaction.rollback();
      return res.status(404).json({
        success: false,
        message: "Insert succeeded but no records were deleted from temp table.",
      });
    }

    // Step 4: Commit transaction
    await transaction.commit();
    console.log(`✅ Transaction committed: ${insertCount} rows inserted and temp rows deleted.`);

    return res.status(200).json({
      success: true,
      message: "Data moved and deleted successfully",
      inserted: insertCount,
    });
  } catch (error) {
    console.error("❌ Error in finalStockUpdate:", error.message);
    if (transaction && !transaction._aborted) {
      await transaction.rollback();
    }
    return res.status(500).json({
      success: false,
      message: "Unexpected error occurred during the process.",
      error: error.message,
    });
  }
};

// GRN/PRN/TOG update final
exports.finalGrnPrnUpdate = async (req, res) => {
  const { username, company, type, remarks = "" } = req.query;

  if (!username || !company || !type) {
    return res.status(400).json({
      success: false,
      message: "Missing required parameters (username, company, or type)",
    });
  }

  const tempTables = {
    GRN: "tb_GRN_TEMP",
    PRN: "tb_PRN_TEMP",
    TOG: "tb_TOG_TEMP",
  };

  const finalTables = {
    GRN: "tb_GRN",
    PRN: "tb_PRN",
    TOG: "tb_TOG",
  };

  if (!tempTables[type]) {
    return res.status(400).json({ success: false, message: "Invalid type" });
  }

  let transaction;
  try {
    transaction = new mssql.Transaction();
    await transaction.begin();

    const request = new mssql.Request(transaction);

    // Step 2: Retrieve temp data
    request.input("REPUSER", mssql.NVarChar(10), username.trim());
    request.input("COMPANY_CODE", mssql.NChar(10), company.trim());

    const selectResult = await request.query(`
      SELECT * FROM [RT_WEB].dbo.${tempTables[type]} 
      WHERE REPUSER = @REPUSER AND COMPANY_CODE = @COMPANY_CODE
    `);

    const records = selectResult.recordset;
    if (records.length === 0) {
      await transaction.rollback();
      return res.status(404).json({ success: false, message: "No data found in temp table" });
    }

    // Step 3: Fetch or insert document row
    const docRequest = new mssql.Request(transaction);
    docRequest.input("COMPANY_CODE", mssql.NChar(10), company.trim());

    let documentResult = await docRequest.query(`
      SELECT * FROM [RT_WEB].dbo.tb_DOCUMENT WHERE COMPANY_CODE = @COMPANY_CODE
    `);

    let grn = "00", prn = "00", tog = "00";

    if (documentResult.recordset.length === 0) {
      const insertDocReq = new mssql.Request(transaction);
      insertDocReq
        .input("COMPANY_CODE", mssql.NChar(10), company.trim())
        .input("GRN", mssql.NVarChar(2), "00")
        .input("PRN", mssql.NVarChar(2), "00")
        .input("TOG", mssql.NVarChar(2), "00")
        .input("REPUSER", mssql.NVarChar(10), username.trim());

      const insertDoc = await insertDocReq.query(`
        INSERT INTO [RT_WEB].dbo.tb_DOCUMENT (COMPANY_CODE, GRN, PRN, TOG, REPUSER)
        VALUES (@COMPANY_CODE, @GRN, @PRN, @TOG, @REPUSER)
      `);
      if (insertDoc.rowsAffected[0] === 0) throw new Error("Document insert failed");
    } else {
      const doc = documentResult.recordset[0];
      grn = doc.GRN || "00";
      prn = doc.PRN || "00";
      tog = doc.TOG || "00";
    }

    // Step 4: Generate new document number
    const newGrn = String(Number(grn) + 1).padStart(2, "0");
    const newPrn = String(Number(prn) + 1).padStart(2, "0");
    const newTog = String(Number(tog) + 1).padStart(2, "0");

    const newDocNums = { GRN: newGrn, PRN: newPrn, TOG: newTog };
    const documentNo = company.trim() + newDocNums[type];

    // Step 5: Update document number
    const updateDocReq = new mssql.Request(transaction);
    updateDocReq.input("COMPANY_CODE", mssql.NChar(10), company.trim());

    if (type === "GRN") updateDocReq.input("GRN", mssql.NVarChar(2), newGrn);
    else if (type === "PRN") updateDocReq.input("PRN", mssql.NVarChar(2), newPrn);
    else updateDocReq.input("TOG", mssql.NVarChar(2), newTog);

    const updateQuery = `
      UPDATE [RT_WEB].dbo.tb_DOCUMENT
      SET ${type} = @${type}
      WHERE COMPANY_CODE = @COMPANY_CODE
    `;

    const updateResult = await updateDocReq.query(updateQuery);
    if (updateResult.rowsAffected[0] === 0) {
      throw new Error(`Failed to update ${type} number`);
    }

    // Step 6: Insert records into final table
    for (const record of records) {
      const insertReq = new mssql.Request(transaction);

      // Common inputs
      insertReq.input("DOCUMENT_NO", mssql.NVarChar(20), documentNo);
      insertReq.input("COMPANY_CODE", mssql.NChar(10), record.COMPANY_CODE.trim());
      insertReq.input("PRODUCT_CODE", mssql.NChar(30), record.PRODUCT_CODE.trim());
      insertReq.input("PRODUCT_NAMELONG", mssql.NVarChar(50), record.PRODUCT_NAMELONG.trim());
      insertReq.input("COSTPRICE", mssql.Money, record.COSTPRICE);
      insertReq.input("UNITPRICE", mssql.Money, record.UNITPRICE);
      insertReq.input("CUR_STOCK", mssql.Float, record.CUR_STOCK);
      insertReq.input("PHY_STOCK", mssql.Float, record.PHY_STOCK);
      insertReq.input("REPUSER", mssql.NVarChar(10), username.trim());
      insertReq.input("REMARKS", mssql.NVarChar(255), remarks);

      let insertQuery = "";
      if (type === "GRN" || type === "PRN") {
        insertReq
          .input("VENDOR_CODE", mssql.NChar(20), record.VENDOR_CODE.trim())
          .input("VENDOR_NAME", mssql.NVarChar(100), record.VENDOR_NAME.trim())
          .input("INVOICE_NO", mssql.NChar(30), record.INVOICE_NO.trim())
          .input("TYPE", mssql.NChar(10), record.TYPE.trim());

        insertQuery = `
          INSERT INTO [RT_WEB].dbo.${finalTables[type]} 
          (DOCUMENT_NO, COMPANY_CODE, VENDOR_CODE, VENDOR_NAME, INVOICE_NO, TYPE,
           PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE,
           CUR_STOCK, PHY_STOCK, REPUSER, REMARKS)
          VALUES
          (@DOCUMENT_NO, @COMPANY_CODE, @VENDOR_CODE, @VENDOR_NAME, @INVOICE_NO, @TYPE,
           @PRODUCT_CODE, @PRODUCT_NAMELONG, @COSTPRICE, @UNITPRICE,
           @CUR_STOCK, @PHY_STOCK, @REPUSER, @REMARKS)
        `;
      } else if (type === "TOG") {
        insertReq
          .input("COMPANY_TO_CODE", mssql.NChar(10), record.COMPANY_TO_CODE.trim())
          .input("TYPE", mssql.NChar(10), record.TYPE.trim());

        insertQuery = `
          INSERT INTO [RT_WEB].dbo.${finalTables[type]} 
          (DOCUMENT_NO, COMPANY_CODE, COMPANY_TO_CODE, TYPE,
           PRODUCT_CODE, PRODUCT_NAMELONG, COSTPRICE, UNITPRICE,
           CUR_STOCK, PHY_STOCK, REMARKS, REPUSER)
          VALUES
          (@DOCUMENT_NO, @COMPANY_CODE, @COMPANY_TO_CODE, @TYPE,
           @PRODUCT_CODE, @PRODUCT_NAMELONG, @COSTPRICE, @UNITPRICE,
           @CUR_STOCK, @PHY_STOCK, @REMARKS, @REPUSER)
        `;
      }

      await insertReq.query(insertQuery);
    }

    // Step 7: Delete temp data
    const deleteReq = new mssql.Request(transaction);
    deleteReq.input("REPUSER", mssql.NVarChar(10), username.trim());
    deleteReq.input("COMPANY_CODE", mssql.NChar(10), company.trim());

    await deleteReq.query(`
      DELETE FROM [RT_WEB].dbo.${tempTables[type]} 
      WHERE REPUSER = @REPUSER AND COMPANY_CODE = @COMPANY_CODE
    `);

    // Step 8: Commit transaction
    await transaction.commit();

    return res.status(200).json({
      success: true,
      message: "Data moved successfully",
      documentNo,
    });

  } catch (error) {
    console.error("Error in finalGrnPrnUpdate:", error.message);
    if (transaction && !transaction._aborted) {
      await transaction.rollback();
    }
    return res.status(500).json({
      success: false,
      message: "Unexpected error occurred",
      error: error.message,
    });
  }
};

//sync db
exports.syncDatabases = async (req, res) => {
  try {
    const responses = await syncDB();

    if (responses.errors && responses.errors.length > 0) {
      // Send the collected errors to the frontend
      return res.status(400).json({
        success: false,
        message: "Issues detected during sync.",
        errors: responses.errors,
      });
    }

    if (
      Array.isArray(responses.responses) &&
      responses.responses[0]?.returnStatus === "Success"
    ) {
      console.log("Database sync completed successfully.");
      const updateTableResult = await updateTables();

      return res.status(200).json({
        success: true,
        message: "Database sync completed successfully.",
        syncDetails: responses.responses,
        updateDetails: updateTableResult,
      });
    } else {
      console.error("Database sync had some issues.");
      return res.status(500).json({
        success: false,
        message: "Database sync encountered an error.",
        errors: responses.responses,
      });
    }
  } catch (error) {
    console.error("Database sync failed:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to start database sync.",
      errors: [error.message],
    });
  }
};

// Get user connection details
exports.findUserConnection = async (req, res) => {
  const name = req.query.nameNew;

  if (!name || typeof name !== "string") {
    return res.status(400).json({ message: "Invalid or missing username parameter" });
  }

  try {
    await mssql.close();

    const dbConnection = {
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      server: process.env.DB_SERVER,
      database: process.env.DB_DATABASE1,
      options: {
        encrypt: false,
        trustServerCertificate: true,
      },
      port: 1433, // verify this port is correct for your DB server
    };

    await mssql.connect(dbConnection);

    const userPermissionResult = await mssql.query`
      USE [RTPOS_MAIN];
      SELECT [a_permission], [a_sync], [d_company], [d_department], [d_category], [d_scategory], 
             [d_vendor], [d_invoice], [t_scan], [t_stock], [t_grn], [t_prn], [t_sales],[t_stock_update]
      FROM tb_USERS
      WHERE username = ${name};
    `;

    await mssql.close();

    if (userPermissionResult.recordset.length === 0) {
      console.log("No results found for username:", name);
      return res.status(404).json({ message: "User details not found" });
    }

    res.status(200).json({
      message: "User permission data retrieved successfully",
      userData: userPermissionResult.recordset,
    });
  } catch (error) {
    console.error("Error retrieving user permission data:", error);
    res.status(500).json({ message: "Failed to retrieve dashboard data" });
  }
};

