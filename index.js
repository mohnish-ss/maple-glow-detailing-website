import express from "express";
import path from "path";
import ejs from "ejs";
import bodyParser from "body-parser";
import { MongoClient, ServerApiVersion } from "mongodb";
import session from "express-session";
import cookieParser from "cookie-parser";
import nodemailer from "nodemailer";
import RateLimit from "express-rate-limit";
import dotenv from "dotenv";
import helmet from "helmet";
import bcrypt from "bcrypt";
import { body, validationResult } from "express-validator";
import crypto from "crypto";
import Tokens from "csrf";
dotenv.config();

// Initialize Express app first
const app = express();
app.set('trust proxy', 1); // Trust first proxy for correct client IP handling

// Initialize CSRF protection
const tokens = new Tokens();

// Basic middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: false, // better for login flows
    rolling: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'lax'
    }
  })
);

// Add session debugging middleware
app.use((req, res, next) => {
  next();
});

// Add middleware to ensure CSRF secret is in session
app.use((req, res, next) => {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = crypto.randomBytes(32).toString('hex');
  }
  next();
});

// Add CSRF token to all responses
app.use((req, res, next) => {
  if (req.session.csrfSecret) {
    const token = tokens.create(req.session.csrfSecret);
    res.locals.csrfToken = token;
  }
  next();
});

// Account lockout settings
const ACCOUNT_LOCKOUT = {
  maxAttempts: 5,
  lockoutDuration: 15 * 60 * 1000 // 15 minutes
};

// Store failed login attempts
const failedLoginAttempts = new Map();

// MongoDB Configuration - Fixed URI construction
const PASS = process.env.MONGODB_PASS;
const uri = `mongodb+srv://Admin:${PASS}@cluster0.ak6hid0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// MongoDB Connection Pool - Fixed initialization
let mongoClient;
let db;

async function initializeMongoDB() {
  try {
    mongoClient = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
      maxPoolSize: 10,
      minPoolSize: 5,
      maxIdleTimeMS: 30000,
      connectTimeoutMS: 10000,
    });

    await mongoClient.connect();
    db = mongoClient.db("user-details");
  } catch (error) {
    process.exit(1);
  }
}

// Initialize MongoDB on startup
initializeMongoDB().catch(console.error);

// Cleanup on application shutdown
process.on('SIGINT', async () => {
  try {
    if (mongoClient) {
      await mongoClient.close();
    }
    process.exit(0);
  } catch (error) {
    process.exit(1);
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'unsafe-hashes'",
        "https://cdn.jsdelivr.net",
        "https://cdn.jsdelivr.net/npm/@tensorflow/tfjs",
        "https://cdn.jsdelivr.net/npm/@tensorflow-models/mobilenet",
        "https://cdn.jsdelivr.net/npm/@teachablemachine/image",
        "https://cdn.jsdelivr.net/npm/seedrandom"
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:", "blob:", "https://*.wikimedia.org", "https://*.iconduck.com"],
      connectSrc: [
        "'self'",
        "https://teachablemachine.withgoogle.com",
        "https://storage.googleapis.com"
      ],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      workerSrc: ["'self'", "blob:"],
      childSrc: ["'self'", "blob:"]
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true
}));

// Additional security headers
app.use((req, res, next) => {
  res.header("Cache-Control", "private, no-cache, no-store, must-revalidate");
  res.header("X-Content-Type-Options", "nosniff");
  res.header("X-Frame-Options", "DENY");
  res.header("X-XSS-Protection", "1; mode=block");
  res.locals.isLoggedIn = req.session.username !== undefined;
  next();
});

// Rate limiting
const loginLimiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts, please try again later.'
});

// Enhanced input validation middleware
const validateLogin = [
  body('username').trim().notEmpty().withMessage('Username or email is required'),
  body('password').notEmpty().withMessage('Password is required')
];

// Enhanced signup validation middleware
const validateSignup = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email address'),
  body('username')
    .isLength({ min: 3 })
    .trim()
    .escape()
    .withMessage('Username must be at least 3 characters long'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage('Password must contain at least one special character')
];

// Check if account is locked
function isAccountLocked(username) {
  const attempts = failedLoginAttempts.get(username);
  if (!attempts) return false;

  if (attempts.count >= ACCOUNT_LOCKOUT.maxAttempts) {
    if (Date.now() - attempts.timestamp < ACCOUNT_LOCKOUT.lockoutDuration) {
      return true;
    } else {
      failedLoginAttempts.delete(username);
      return false;
    }
  }
  return false;
}

// Update failed login attempts
function updateFailedAttempts(key) {
  const attempts = failedLoginAttempts.get(key) || { count: 0, timestamp: Date.now() };
  attempts.count++;
  attempts.timestamp = Date.now();
  failedLoginAttempts.set(key, attempts);
}

// Reset failed login attempts
function resetFailedAttempts(key) {
  failedLoginAttempts.delete(key);
}

// Function to check the user's login credentials - Fixed
async function checkUserLogin(user, pass, req, res) {
  try {
    // Input validation
    if (!user || !pass) {
      return { success: false, message: 'Username and password are required' };
    }

    // Sanitize user input
    const sanitizedUser = String(user).trim().toLowerCase();

    // Check for account lockout
    if (isAccountLocked(sanitizedUser)) {
      return { success: false, message: 'Account is temporarily locked. Please try again later.' };
    }

    // Rate limiting check
    const clientIP = req.ip;
    const rateLimitKey = `login_${clientIP}`;
    const attempts = failedLoginAttempts.get(rateLimitKey) || { count: 0, timestamp: Date.now() };

    if (attempts.count >= 5 && Date.now() - attempts.timestamp < 15 * 60 * 1000) {
      return { success: false, message: 'Too many login attempts. Please try again later.' };
    }

    let query;
    const details = db.collection("details");
    if (sanitizedUser.includes("@")) {
      query = await details.findOne({ email: sanitizedUser });
    } else {
      query = await details.findOne({ username: sanitizedUser });
    }

    if (!query) {
      updateFailedAttempts(rateLimitKey);
      return { success: false, message: 'Invalid credentials' };
    }

    // Check if the stored password is a bcrypt hash
    const isBcryptHash = query.password.startsWith('$2');

    let passwordMatch;
    if (isBcryptHash) {
      // If it's already a bcrypt hash, compare normally
      passwordMatch = await bcrypt.compare(pass, query.password);
    } else {
      // If it's plain text, compare directly and update to hash
      passwordMatch = pass === query.password;
      if (passwordMatch) {
        // Update the password to be a bcrypt hash
        const hashedPassword = await bcrypt.hash(pass, 10);
        await details.updateOne(
          { _id: query._id },
          { $set: { password: hashedPassword } }
        );
      }
    }

    if (passwordMatch) {
      resetFailedAttempts(rateLimitKey);
      const userData = {
        firstName: query.firstName,
        lastName: query.lastName,
        email: query.email,
        phoneNum: query.phoneNumber,
        adr: query.address,
        pCode: query.postalCode,
        userName: query.username
      };
      return { success: true, userData: userData };
    } else {
      updateFailedAttempts(rateLimitKey);
      return { success: false, message: 'Invalid credentials' };
    }
  } catch (error) {
    return { success: false, message: 'An error occurred during login' };
  }
}

// Set up view engine and static files
app.use(express.static("public"));
app.set("view engine", "ejs");

const __dirname = path.resolve();

// Routes
app.get("/", (req, res) => {
  const username = req.session.username;
  res.render("home", {
    username,
    isLoggedIn: !!username,
    csrfToken: res.locals.csrfToken
  });
});

app.get("/login", (req, res) => {
  res.render('login', {
    loginInvalid: false,
    loginError: null,
    csrfToken: res.locals.csrfToken
  });
});

app.post("/check-login", loginLimiter, validateLogin, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.json({
      success: false,
      message: 'Please provide valid username and password'
    });
  }

  try {
    const { username, password } = req.body;

    const result = await checkUserLogin(username, password, req, res);

    if (!result.success) {
      return res.json({
        success: false,
        message: result.message || 'Invalid username or password'
      });
    }

    // Set session data
    req.session.username = result.userData.userName;
    req.session.userData = {
      firstName: result.userData.firstName,
      lastName: result.userData.lastName,
      email: result.userData.email,
      phoneNum: result.userData.phoneNum,
      adr: result.userData.adr,
      pCode: result.userData.pCode,
      userName: result.userData.userName
    };

    // Force session save
    req.session.save((err) => {
      if (err) {
        return res.json({
          success: false,
          message: 'Failed to save session'
        });
      }

      res.json({
        success: true,
        redirect: '/profile'
      });
    });
  } catch (error) {
    res.json({
      success: false,
      message: 'An error occurred during login'
    });
  }
});

app.get("/forgot-password", (req, res) => {
  if (req.session.username) {
    res.redirect("/profile");
  } else {
    res.render("forgot-password", { csrfToken: res.locals.csrfToken });
  }
});

app.get("/home", (req, res) => {
  const username = req.session.username;
  res.render("home", {
    username,
    isLoggedIn: !!username,
    csrfToken: res.locals.csrfToken
  });
});

app.get("/booking", (req, res) => {
  const username = req.session.username;
  if (username) {
    res.render("booking", {
      username,
      csrfToken: res.locals.csrfToken
    });
  } else {
    res.render("login", {
      loginInvalid: false,
      loginError: null,
      csrfToken: res.locals.csrfToken
    });
  }
});

app.get("/estimate", (req, res) => {
  const username = req.session.username;
  res.render("estimate", {
    username,
    csrfToken: res.locals.csrfToken
  });
});

app.get("/contact", (req, res) => {
  res.render("contact", { csrfToken: res.locals.csrfToken });
});

app.get("/sign-up", (req, res) => {
  const usernameTaken = req.session.usernameTaken;
  req.session.usernameTaken = false; // Clear the flag
  res.render("sign-up", {
    usernameTaken,
    csrfToken: res.locals.csrfToken
  });
});

app.get("/profile", (req, res) => {
  if (!req.session.username) {
    return res.redirect("/login");
  }

  res.render("profile", {
    username: req.session.username,
    userData: req.session.userData,
    csrfToken: res.locals.csrfToken
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    res.clearCookie('connect.sid');
    res.redirect("/login");
  });
});

// Modified signup route with validation
app.post("/sign-up-form", validateSignup, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const formData = req.body;
    const username = req.body.username;

    let usernameTaken = await checkValidUsername(username);

    if (usernameTaken === false) {
      const hashedPassword = await bcrypt.hash(formData.password, 10);
      formData.password = hashedPassword;

      await saveDetails(formData);

      req.session.username = formData.username;
      req.session.userData = {
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        phoneNum: formData.phoneNumber,
        adr: formData.address,
        pCode: formData.postalCode,
        userName: formData.username
      };

      res.redirect("/profile");
    } else {
      req.session.usernameTaken = true;
      res.redirect("/sign-up");
    }
  } catch (error) {
    res.status(500).send("Error submitting details, try again.");
  }
});

// Generates a random five-digit number to use as a verification code
function generateVerificationCode() {
  const numbers = "0123456789";
  let code = "";

  for (let i = 0; i < 5; i++) {
    const randomIndex = Math.floor(Math.random() * numbers.length);
    code += numbers.charAt(randomIndex);
  }

  return code;
}

var verificationCode = "";

// Checks if the user's e-mail exists within the database
async function checkEmailExists(email) {
  try {
    const details = db.collection("details");
    const sanitizedEmail = String(email).trim().toLowerCase();
    const eMail = { email: sanitizedEmail };
    const query = await details.findOne(eMail);
    return query !== null;
  } catch (error) {
    throw error;
  }
}

// Runs when the user submits their e-mail in the "Forgot password" page
app.post("/forgot-password-email", async (req, res) => {
  const code = generateVerificationCode();
  const customerEmail = req.body.email;

  try {
    const emailExists = await checkEmailExists(customerEmail);

    if (emailExists) {
      verificationCode = code;
      req.session.customerEmail = customerEmail;

      const transporter = nodemailer.createTransporter({
        service: "gmail",
        auth: {
          user: "mapleglowdetailing@gmail.com",
          pass: process.env.EMAIL_PASSWORD,
        },
      });

      if (!process.env.EMAIL_PASSWORD) {
        return res.status(500).send("Email service configuration error");
      }

      const emailLayout = {
        from: "mapleglowdetailing@gmail.com",
        to: customerEmail,
        subject: "Password Recovery",
        text: "Enter this code to log-in: " + code,
      };

      try {
        await transporter.sendMail(emailLayout);
        res.send("Email sent successfully");
      } catch (error) {
        res.status(500).send("Failed to send email");
      }
    } else {
      res.send("Email not linked to an account");
    }
  } catch (error) {
    res.status(500).send("An error occurred");
  }
});

// Runs when the user submits the code they receive in their e-mail
app.post("/verify-code", (req, res) => {
  const code = req.body.codeValue;
  const storedCode = verificationCode;

  if (code === storedCode) {
    res.send("Code verified successfully");
  } else {
    res.send("Invalid verification code");
  }
});

// Finds the password of the user based on their e-mail if the user submits the correct verification code
async function findPassword(email) {
  try {
    const details = db.collection("details");
    const sanitizedEmail = String(email).trim().toLowerCase();
    const eMail = { email: sanitizedEmail };
    const query = await details.findOne(eMail);

    if (query) {
      return { success: true, userData: query };
    } else {
      return { success: false, message: "Email not found" };
    }
  } catch (error) {
    throw error;
  }
}

// Runs after the code verification and logs the user in after everything is completed
app.post("/login-remotely", async (req, res) => {
  const eMail = req.body.email;

  try {
    const result = await findPassword(eMail);

    if (result.success) {
      req.session.username = result.userData.username;
      req.session.userData = {
        firstName: result.userData.firstName,
        lastName: result.userData.lastName,
        email: result.userData.email,
        phoneNum: result.userData.phoneNumber,
        adr: result.userData.address,
        pCode: result.userData.postalCode,
        userName: result.userData.username,
      };
      res.status(200).json({ success: true });
    } else {
      res.status(404).json({ success: false });
    }
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// A function to send booking confirmation e-mails to the customer as well as admin
async function sendConfirmationEmail(email, name, day, month, time, detail, address) {
  try {
    const transporter = nodemailer.createTransporter({
      service: "gmail",
      auth: {
        user: "mapleglowdetailing@gmail.com",
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const email1 = {
      from: "mapleglowdetailing@gmail.com",
      to: ["shethmohnish@gmail.com"],
      subject: "New Customer Detail Booking",
      text:
        "Customer Name: " +
        name +
        "\n" +
        "Customer E-mail: " +
        email +
        "\n" +
        "Address: " +
        address +
        "\n" +
        "Date: " +
        month +
        " " +
        day +
        "\n" +
        "Time: " +
        time +
        "\n" +
        "Detail Type: " +
        detail,
    };

    const email2 = {
      from: "mapleglowdetailing@gmail.com",
      to: email,
      subject: "Detail Booking Confirmation",
      text:
        "Hi " +
        name +
        ", \n \n" +
        "Your " +
        detail +
        " detail is booked for " +
        month +
        " " +
        day +
        " at " +
        time +
        ".",
    };

    await transporter.sendMail(email1);
    await transporter.sendMail(email2);
  } catch (error) {
    throw error;
  }
}

app.post("/send-confirmation-email", async (req, res) => {
  try {
    const email = req.session.userData.email;
    const name = req.session.userData.firstName;
    const day = req.body.day;
    const month = req.body.month;
    const time = req.body.time;
    const detail = req.body.detail;
    const address = req.session.userData.adr;

    await sendConfirmationEmail(email, name, day, month, time, detail, address);
    res.send("e-mails sent");
  } catch (error) {
    res.status(500).send("Error sending emails");
  }
});

// Function to send a customer's inquiry
async function sendEmail(customerEmail, subject, text) {
  try {
    const transporter = nodemailer.createTransporter({
      service: "gmail",
      auth: {
        user: "mapleglowdetailing@gmail.com",
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const emailLayout = {
      from: "mapleglowdetailing@gmail.com",
      to: ["shethmohnish@gmail.com"],
      subject: subject,
      text: "Customer Inquiry from " + customerEmail + ": " + text,
    };

    await transporter.sendMail(emailLayout);
  } catch (error) {
    throw error;
  }
}

app.post("/contact-form", async (req, res) => {
  try {
    const subject = req.body.subject;
    const message = req.body.message;
    const customerEmail = req.body.email;

    await sendEmail(customerEmail, subject, message);
    res.redirect("/contact");
  } catch (error) {
    res.status(500).send("Error sending message");
  }
});

// Function to update user details in the database
async function updateDetails(formData, user, req) {
  try {
    const details = db.collection("details");
    const sanitizedUser = String(user).trim().toLowerCase();
    const query = { username: sanitizedUser };

    const result = await details.updateOne(query, { $set: formData });

    if (result.matchedCount === 1 && result.modifiedCount === 0) {
      console.warn("Update did not modify any fields.");
    } else {
      console.log("Update completed successfully.");

      req.session.userData = {
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        phoneNum: formData.phoneNumber,
        adr: formData.address,
        pCode: formData.postalCode,
        userName: formData.username,
      };
    }
  } catch (error) {
    throw error;
  }
}

// Saving the user details to the database
async function saveDetails(formData) {
  try {
    const details = db.collection("details");
    await details.insertOne(formData);
  } catch (error) {
    throw error;
  }
}

// Checking for unique username
async function checkValidUsername(user) {
  try {
    const details = db.collection("details");
    const sanitizedUser = String(user).trim().toLowerCase();
    let query = await details.findOne({ username: sanitizedUser });
    return query !== null;
  } catch (error) {
    throw error;
  }
}

// Reading admin schedule
async function getAdminSchedule() {
  try {
    const database = mongoClient.db("user-details");
    const adminScheduleCollection = database.collection("adminSchedule");
    const adminSchedule = await adminScheduleCollection.findOne({});
    return adminSchedule;
  } catch (error) {
    throw error;
  } finally {
    await mongoClient.close();
  }
}

app.get("/admin-schedule", async (req, res) => {
  try {
    const adminSchedule = await getAdminSchedule();
    res.json(adminSchedule);
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

async function updateDocument() {
  try {
    await mongoClient.connect();
    console.log("Connected to the database");

    const database = mongoClient.db("user-details");
    const adminScheduleCollection = database.collection("adminSchedule");

    // Reset the values of the database to defaults.
    const update = {
      $set: {
        "Schedule.0": Array.from({ length: 31 }, (_, index) => [
          [String(index * 3 + 1), true, "none", "none"],
          [String(index * 3 + 2), true, "none", "none"],
          [String(index * 3 + 3), true, "none", "none"],
        ]),
        "Schedule.1": Array.from({ length: 31 }, (_, index) => [
          [String(index * 3 + 1), true, "none", "none"],
          [String(index * 3 + 2), true, "none", "none"],
          [String(index * 3 + 3), true, "none", "none"],
        ]),
      },
    };

    const result = await adminScheduleCollection.updateMany({}, update);

    if (result.modifiedCount > 0) {
      console.log("Documents updated successfully");
    } else {
      console.log("No documents matched the query");
    }
  } finally {
    await mongoClient.close();
    console.log("Connection closed");
  }
}

app.get("/update-admin", async (req, res) => {
  try {
    const result = await updateDocument();

    if (result && result.modifiedCount > 0) {
      res.status(200).json({ message: "Document updated successfully" });
    } else {
      res.status(404).json({ message: "No documents matched the query" });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

async function book(month, day, timeslot, detailtype, req) {
  try {
    await mongoClient.connect();
    console.log("Connected to the database");

    const database = mongoClient.db("user-details");
    const adminScheduleCollection = database.collection("adminSchedule");

    // Updating the values in the database.
    const update = {
      $set: {
        [`Schedule.${month}.${day}.${timeslot}.1`]: false,
        [`Schedule.${month}.${day}.${timeslot}.2`]: detailtype,
        [`Schedule.${month}.${day}.${timeslot}.3`]: req.session.username,
      },
    };

    const result = await adminScheduleCollection.updateOne(
      { id1: "hello" },
      update
    );

    if (result.modifiedCount > 0) {
      console.log("Document updated successfully");
    } else {
      console.log("No document matched the query");
    }
  } finally {
    await mongoClient.close();
    console.log("Connection closed");
  }
}

app.post("/book", async (req, res) => {
  try {
    const { selectedDay, viewingMonth, selectedTimeSlot, detailType } =
      req.body;
    const result = await book(
      viewingMonth,
      selectedDay,
      selectedTimeSlot,
      detailType,
      req
    );

    if (result && result.modifiedCount > 0) {
      res.status(200).json({ message: "Document updated successfully" });
    } else {
      res.status(404).json({ message: "No documents matched the query" });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Password change validation
const validatePasswordChange = [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage('Password must contain at least one special character')
];

app.post("/change-password", validatePasswordChange, async (req, res) => {
  // Verify CSRF token
  if (!tokens.verify(req.session.csrfSecret, req.body._csrf)) {
    return res.status(403).json({
      success: false,
      message: 'Invalid CSRF token'
    });
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.json({
      success: false,
      message: errors.array()[0].msg
    });
  }

  try {
    const { currentPassword, newPassword } = req.body;
    const username = req.session.username;

    if (!username) {
      return res.json({
        success: false,
        message: 'Not authenticated'
      });
    }

    // Sanitize username
    const sanitizedUser = String(username).trim().toLowerCase();

    // Get user from database
    const details = db.collection("details");
    const user = await details.findOne({ username: sanitizedUser });

    if (!user) {
      return res.json({
        success: false,
        message: 'User not found'
      });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password in database
    await details.updateOne(
      { username: sanitizedUser },
      { $set: { password: hashedPassword } }
    );

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    res.json({
      success: false,
      message: 'An error occurred while changing password'
    });
  }
});

// Start server with error handling
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
}).on('error', (err) => {
});
