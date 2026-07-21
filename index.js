import express from "express";
import path from "path";
import ejs from "ejs";
import bodyParser from "body-parser";
import { MongoClient, ServerApiVersion } from "mongodb";
import session from "express-session";
import MongoStore from "connect-mongo";
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

const SESSION_SECRET = process.env.SESSION_SECRET;
const MONGODB_PASS = process.env.MONGODB_PASS;
const MONGODB_URI = process.env.MONGODB_URI ||
  (MONGODB_PASS
    ? `mongodb+srv://Admin:${encodeURIComponent(MONGODB_PASS)}@cluster0.ak6hid0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
    : null);

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be set to at least 32 characters.");
}

if (!MONGODB_URI) {
  throw new Error("Set MONGODB_URI or MONGODB_PASS before starting the app.");
}

const COOKIE_NAME = "maple_glow.sid";
const ADMIN_USERNAMES = new Set(
  (process.env.ADMIN_USERNAMES || "")
    .split(",")
    .map((username) => username.trim().toLowerCase())
    .filter(Boolean)
);

const csrfExemptPaths = new Set([]);

const unsafeRequestLimiter = RateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { success: false, message: "Too many requests, please try again later." },
  skip: (req) => ["GET", "HEAD", "OPTIONS"].includes(req.method)
});

const profileUpdateLimiter = RateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many profile updates, please try again later."
});

// Basic middleware
app.use(bodyParser.json({ limit: "50kb" }));
app.use(bodyParser.urlencoded({ extended: false, limit: "50kb" }));
app.use(cookieParser());

// Session configuration
app.use(
  session({
    name: COOKIE_NAME,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // better for login flows
    rolling: true,
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      dbName: "user-details",
      collectionName: "sessions",
      ttl: 24 * 60 * 60,
      crypto: {
        secret: SESSION_SECRET
      }
    }),
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
  res.locals.json = (value) =>
    JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (char) => {
      const replacements = {
        "<": "\\u003c",
        ">": "\\u003e",
        "&": "\\u0026",
        "\u2028": "\\u2028",
        "\u2029": "\\u2029"
      };
      return replacements[char];
    });
  next();
});

app.use(unsafeRequestLimiter);

app.use((req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method) || csrfExemptPaths.has(req.path)) {
    return next();
  }

  const submittedToken = req.body?._csrf || req.get("X-CSRF-Token");
  if (!req.session.csrfSecret || !submittedToken || !tokens.verify(req.session.csrfSecret, submittedToken)) {
    return res.status(403).json({ success: false, message: "Invalid CSRF token" });
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

// MongoDB Connection Pool - Fixed initialization
let mongoClient;
let db;

async function initializeMongoDB() {
  try {
    mongoClient = new MongoClient(MONGODB_URI, {
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
    await db.collection("details").createIndex({ username: 1 }, { unique: true });
    await db.collection("details").createIndex({ email: 1 }, { unique: true });
  } catch (error) {
    process.exit(1);
  }
}

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
  res.locals.currentPath = req.path;
  next();
});

// Rate limiting
const loginLimiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts, please try again later.'
});

const passwordRecoveryLimiter = RateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'Too many password recovery attempts, please try again later.'
});

// Enhanced input validation middleware
const validateLogin = [
  body('username').isString().trim().notEmpty().isLength({ max: 254 }).withMessage('Username or email is required'),
  body('password').isString().notEmpty().isLength({ max: 256 }).withMessage('Password is required')
];

// Enhanced signup validation middleware
const validateSignup = [
  body('firstName').isString().trim().isLength({ min: 1, max: 80 }).withMessage('First name is required'),
  body('lastName').isString().trim().isLength({ min: 1, max: 80 }).withMessage('Last name is required'),
  body('email')
    .isString()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email address'),
  body('phoneNumber').isString().trim().isLength({ min: 7, max: 30 }).withMessage('Please enter a valid phone number'),
  body('address').isString().trim().isLength({ min: 3, max: 200 }).withMessage('Please enter a valid address'),
  body('postalCode').isString().trim().isLength({ min: 3, max: 20 }).withMessage('Please enter a valid postal code'),
  body('username')
    .isString()
    .trim()
    .isLength({ min: 3, max: 40 })
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage('Username must be 3-40 characters and use only letters, numbers, dots, underscores, or hyphens'),
  body('password')
    .isString()
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

const validateProfileUpdate = [
  body('firstName').isString().trim().isLength({ min: 1, max: 80 }).withMessage('First name is required'),
  body('lastName').isString().trim().isLength({ min: 1, max: 80 }).withMessage('Last name is required'),
  body('email').isString().isEmail().normalizeEmail().withMessage('Please enter a valid email address'),
  body('phoneNumber').isString().trim().isLength({ min: 7, max: 30 }).withMessage('Please enter a valid phone number'),
  body('address').isString().trim().isLength({ min: 3, max: 200 }).withMessage('Please enter a valid address'),
  body('postalCode').isString().trim().isLength({ min: 3, max: 20 }).withMessage('Please enter a valid postal code'),
  body('username')
    .isString()
    .trim()
    .isLength({ min: 3, max: 40 })
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage('Username must be 3-40 characters and use only letters, numbers, dots, underscores, or hyphens')
];

const validateContact = [
  body('subject').isString().trim().isLength({ min: 1, max: 200 }).withMessage('Subject is required'),
  body('email').isString().trim().isEmail().normalizeEmail().withMessage('Please enter a valid email address'),
  body('message').isString().trim().isLength({ min: 1, max: 5000 }).withMessage('Message is required')
];

const validateForgotPasswordEmail = [
  body('email').isString().trim().isEmail().normalizeEmail().withMessage('Please enter a valid email address')
];

const validateVerificationCode = [
  body('codeValue').isString().trim().matches(/^\d{6}$/).withMessage('Invalid verification code')
];

const validateBooking = [
  body('selectedDay').isInt({ min: 0, max: 30 }).withMessage('Invalid day'),
  body('viewingMonth').isInt({ min: 0, max: 1 }).withMessage('Invalid month'),
  body('selectedTimeSlot').isInt({ min: 0, max: 2 }).withMessage('Invalid time slot'),
  body('detailType').isInt({ min: 0, max: 3 }).withMessage('Invalid detail type')
];

const validateConfirmationEmail = [
  body('day').isString().trim().isLength({ min: 1, max: 2 }).matches(/^\d{1,2}$/).withMessage('Invalid day'),
  body('month').isString().trim().isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z]+$/).withMessage('Invalid month'),
  body('time').isString().trim().isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9 :]+$/).withMessage('Invalid time'),
  body('detail').isString().trim().isLength({ min: 3, max: 80 }).matches(/^[a-zA-Z0-9 ]+$/).withMessage('Invalid detail')
];

function normalizeUsername(username) {
  return String(username).trim().toLowerCase();
}

function requireAuth(req, res, next) {
  if (!req.session.username) {
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.username) {
    return res.status(401).json({ error: "Authentication required" });
  }
  if (!ADMIN_USERNAMES.has(normalizeUsername(req.session.username))) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

function buildUserData(user) {
  return {
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phoneNum: user.phoneNumber,
    adr: user.address,
    pCode: user.postalCode,
    userName: user.username
  };
}

function pickUserFields(formData) {
  return {
    firstName: String(formData.firstName).trim(),
    lastName: String(formData.lastName).trim(),
    email: String(formData.email).trim().toLowerCase(),
    phoneNumber: String(formData.phoneNumber).trim(),
    address: String(formData.address).trim(),
    postalCode: String(formData.postalCode).trim(),
    username: normalizeUsername(formData.username)
  };
}

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  next();
}

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
    const sanitizedUser = normalizeUsername(user);

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
    const storedPassword = typeof query.password === "string" ? query.password : "";
    const isBcryptHash = storedPassword.startsWith('$2');

    let passwordMatch;
    if (isBcryptHash) {
      // If it's already a bcrypt hash, compare normally
      passwordMatch = await bcrypt.compare(pass, storedPassword);
    } else {
      // If it's plain text, compare directly and update to hash
      passwordMatch = pass === storedPassword;
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
      const userData = buildUserData(query);
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

    req.session.regenerate((regenerateError) => {
      if (regenerateError) {
        return res.json({
          success: false,
          message: 'Failed to establish session'
        });
      }

      req.session.csrfSecret = crypto.randomBytes(32).toString('hex');
      req.session.username = result.userData.userName;
      req.session.userData = result.userData;

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
    });
  } catch (error) {
    console.error("Login error:", error);
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

const MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const TIME_NAMES = ["12 PM", "3 PM", "6 PM"];
const DETAIL_NAMES = ["Interior", "Exterior", "Full Package", "Headlight Polish"];

app.get("/my-bookings", requireAuth, async (req, res) => {
  try {
    const username = normalizeUsername(req.session.username);
    const adminScheduleCollection = db.collection("adminSchedule");
    // Older schedule documents may not have the legacy id1 marker.
    const doc = await adminScheduleCollection.findOne({ id1: "hello" })
      || await adminScheduleCollection.findOne({ Schedule: { $exists: true } });
    if (!doc || !Array.isArray(doc.Schedule)) return res.json([]);

    const now = new Date();
    const currentMonth = now.getMonth();
    const currentDay = now.getDate() - 1; // 0-indexed

    const userBookings = [];
    const schedule = doc.Schedule;

    // Schedule is indexed 0 = current month, 1 = next month
    for (let monthIdx = 0; monthIdx < schedule.length; monthIdx++) {
      const monthData = schedule[monthIdx];
      if (!monthData) continue;
      for (let dayIdx = 0; dayIdx < monthData.length; dayIdx++) {
        const daySlots = monthData[dayIdx];
        if (!daySlots) continue;
        for (let timeIdx = 0; timeIdx < daySlots.length; timeIdx++) {
          const slot = daySlots[timeIdx];
          // slot: [label, isAvailable, detailType, username]
          if (slot && normalizeUsername(slot[3]) === username && slot[1] === false) {
            const realMonth = (currentMonth + monthIdx) % 12;
            const dayNum = dayIdx + 1;
            // Skip past dates
            if (monthIdx === 0 && dayIdx < currentDay) continue;
            userBookings.push({
              month: MONTH_NAMES[realMonth],
              day: dayNum,
              time: TIME_NAMES[timeIdx] || slot[0],
              service: DETAIL_NAMES[slot[2]] || "Unknown"
            });
          }
        }
      }
    }

    // Sort chronologically
    userBookings.sort((a, b) => {
      const aDate = new Date(`${a.month} ${a.day}, ${now.getFullYear()}`);
      const bDate = new Date(`${b.month} ${b.day}, ${now.getFullYear()}`);
      return aDate - bDate;
    });

    res.json(userBookings);
  } catch (error) {
    console.error("Error fetching user bookings:", error);
    res.status(500).json([]);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    res.clearCookie(COOKIE_NAME);
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
    const formData = pickUserFields(req.body);
    const username = formData.username;
    const password = String(req.body.password);

    const usernameTaken = await checkValidUsername(username);
    const emailTaken = await checkEmailExists(formData.email);

    if (!usernameTaken && !emailTaken) {
      const hashedPassword = await bcrypt.hash(password, 12);
      formData.password = hashedPassword;

      await saveDetails(formData);

      req.session.regenerate((regenerateError) => {
        if (regenerateError) {
          return res.status(500).send("Error creating session.");
        }

        req.session.csrfSecret = crypto.randomBytes(32).toString('hex');
        req.session.username = formData.username;
        req.session.userData = buildUserData(formData);
        res.redirect("/profile");
      });
    } else {
      req.session.usernameTaken = true;
      res.redirect("/sign-up");
    }
  } catch (error) {
    res.status(500).send("Error submitting details, try again.");
  }
});

// Generates a cryptographically secure 6-digit verification code
function generateVerificationCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// Verification code expiry time (10 minutes)
const VERIFICATION_CODE_EXPIRY_MS = 10 * 60 * 1000;

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
app.post("/forgot-password-email", passwordRecoveryLimiter, validateForgotPasswordEmail, handleValidationErrors, async (req, res) => {
  const code = generateVerificationCode();
  const customerEmail = String(req.body.email).trim().toLowerCase();

  try {
    const emailExists = await checkEmailExists(customerEmail);

    // Always return the same message to prevent email enumeration
    if (emailExists) {
      // Store verification code in session (not a global variable)
      req.session.verificationCode = code;
      req.session.verificationCodeExpiry = Date.now() + VERIFICATION_CODE_EXPIRY_MS;
      req.session.customerEmail = customerEmail;
      req.session.codeVerified = false;
      req.session.verificationAttempts = 0;

      if (!process.env.EMAIL_PASSWORD) {
        return res.status(500).send("Email service configuration error");
      }

      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "mapleglowdetailing@gmail.com",
          pass: process.env.EMAIL_PASSWORD,
        },
      });

      const emailLayout = {
        from: "mapleglowdetailing@gmail.com",
        to: customerEmail,
        subject: "Password Recovery",
        text: "Enter this code to log-in: " + code,
      };

      try {
        await transporter.sendMail(emailLayout);
      } catch (error) {
        // Log but don't reveal to user
        console.error("Failed to send verification email");
      }
    }
    // Return the same message regardless of whether the email was found
    res.send("If this email is registered, a verification code has been sent.");
  } catch (error) {
    res.status(500).send("An error occurred");
  }
});

// Runs when the user submits the code they receive in their e-mail
app.post("/verify-code", validateVerificationCode, handleValidationErrors, (req, res) => {
  const code = String(req.body.codeValue).trim();
  const storedCode = req.session.verificationCode;
  const expiry = req.session.verificationCodeExpiry;
  req.session.verificationAttempts = req.session.verificationAttempts || 0;

  // Check that a code exists, hasn't expired, and matches
  if (!storedCode || !expiry) {
    return res.send("Invalid verification code");
  }

  if (req.session.verificationAttempts >= 5) {
    req.session.verificationCode = null;
    req.session.verificationCodeExpiry = null;
    req.session.codeVerified = false;
    return res.status(429).send("Too many invalid attempts. Please request a new code.");
  }

  if (Date.now() > expiry) {
    // Clear expired code
    req.session.verificationCode = null;
    req.session.verificationCodeExpiry = null;
    return res.send("Verification code has expired. Please request a new one.");
  }

  if (code === storedCode) {
    req.session.codeVerified = true;
    // Clear the code so it can't be reused
    req.session.verificationCode = null;
    req.session.verificationCodeExpiry = null;
    res.send("Code verified successfully");
  } else {
    req.session.verificationAttempts++;
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
app.post("/login-remotely", validateForgotPasswordEmail, handleValidationErrors, async (req, res) => {
  const eMail = String(req.body.email).trim().toLowerCase();

  // SECURITY: Verify that the code was actually verified in this session
  // and the email matches the one that requested the code
  if (!req.session.codeVerified || req.session.customerEmail !== eMail) {
    return res.status(403).json({ success: false, message: 'Verification required' });
  }

  try {
    const result = await findPassword(eMail);

    if (result.success) {
      const userData = buildUserData(result.userData);
      req.session.regenerate((regenerateError) => {
        if (regenerateError) {
          return res.status(500).json({ success: false });
        }

        req.session.csrfSecret = crypto.randomBytes(32).toString('hex');
      req.session.username = result.userData.username;
        req.session.userData = userData;
        res.status(200).json({ success: true });
      });
    } else {
      res.status(404).json({ success: false });
    }
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// A function to send booking confirmation e-mails to the customer as well as admin (Demo mode: suppressed real sending)
async function sendConfirmationEmail(email, name, day, month, time, detail, address) {
  console.log(`[DEMO MODE] Booking confirmation email suppressed for ${name} (${email}): ${detail} detail on ${month} ${day} at ${time}.`);
  return true;
}

app.post("/send-confirmation-email", requireAuth, validateConfirmationEmail, handleValidationErrors, async (req, res) => {
  // Require authentication
  if (!req.session.userData) {
    return res.status(401).send("Authentication required");
  }

  try {
    const email = req.session.userData.email;
    const name = req.session.userData.firstName;
    const day = String(req.body.day).trim();
    const month = String(req.body.month).trim();
    const time = String(req.body.time).trim();
    const detail = String(req.body.detail).trim();
    const address = req.session.userData.adr;

    await sendConfirmationEmail(email, name, day, month, time, detail, address);
    res.send("e-mails sent");
  } catch (error) {
    res.status(500).send("Error sending emails");
  }
});

// Function to send a customer's inquiry (Demo mode: suppressed real sending)
async function sendEmail(customerEmail, subject, text) {
  console.log(`[DEMO MODE] Customer inquiry email suppressed from ${customerEmail}: Subject "${subject}"`);
  return true;
}

app.post("/contact-form", validateContact, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send(errors.array()[0].msg);
  }

  try {
    // Sanitize inputs to prevent header injection
    const subject = String(req.body.subject).trim().substring(0, 200).replace(/[\r\n]/g, '');
    const message = String(req.body.message).trim().substring(0, 5000);
    const customerEmail = String(req.body.email).trim().toLowerCase();

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
    const sanitizedUser = normalizeUsername(user);
    const query = { username: sanitizedUser };

    const result = await details.updateOne(query, { $set: formData });

    if (result.matchedCount === 1 && result.modifiedCount === 0) {
      console.warn("Update did not modify any fields.");
    } else {
      console.log("Update completed successfully.");

      req.session.username = formData.username;
      req.session.userData = buildUserData(formData);
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

// POST /save-form — Save profile edits with field whitelisting
app.post("/save-form", profileUpdateLimiter, validateProfileUpdate, async (req, res) => {
  // Require authentication
  if (!req.session.username) {
    return res.redirect("/login");
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send(errors.array()[0].msg);
  }

  try {
    const sanitizedData = pickUserFields(req.body);
    const currentUsername = normalizeUsername(req.session.username);
    const details = db.collection("details");
    const duplicate = await details.findOne({
      $and: [
        { username: { $ne: currentUsername } },
        { $or: [{ username: sanitizedData.username }, { email: sanitizedData.email }] }
      ]
    });

    if (duplicate) {
      return res.status(409).send("Username or email already in use");
    }

    await updateDetails(sanitizedData, currentUsername, req);
    res.redirect("/profile");
  } catch (error) {
    res.status(500).send("Error saving profile changes");
  }
});

// Checking for unique username
async function checkValidUsername(user) {
  try {
    const details = db.collection("details");
    const sanitizedUser = normalizeUsername(user);
    let query = await details.findOne({ username: sanitizedUser });
    return query !== null;
  } catch (error) {
    throw error;
  }
}

// Reading admin schedule — uses the shared connection pool (do NOT close mongoClient here)
async function getAdminSchedule() {
  try {
    const adminScheduleCollection = db.collection("adminSchedule");
    const adminSchedule = await adminScheduleCollection.findOne({});
    return adminSchedule;
  } catch (error) {
    throw error;
  }
}

app.get("/admin-schedule", requireAuth, async (req, res) => {
  try {
    const adminSchedule = await getAdminSchedule();
    res.json(adminSchedule);
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

async function updateDocument() {
  try {
    const adminScheduleCollection = db.collection("adminSchedule");

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
    return result;
  } catch (error) {
    throw error;
  }
}

app.post("/update-admin", requireAdmin, async (req, res) => {
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
  // SECURITY: Validate all parameters are safe non-negative integers to prevent NoSQL injection
  const safeMonth = parseInt(month, 10);
  const safeDay = parseInt(day, 10);
  const safeTimeslot = parseInt(timeslot, 10);
  const safeDetailtype = parseInt(detailtype, 10);

  if ([safeMonth, safeDay, safeTimeslot, safeDetailtype].some(v => isNaN(v) || v < 0)) {
    throw new Error('Invalid booking parameters');
  }
  if (safeMonth > 1 || safeDay > 30 || safeTimeslot > 2 || safeDetailtype > 3) {
    throw new Error('Booking parameters out of range');
  }

  try {
    const adminScheduleCollection = db.collection("adminSchedule");

    // Updating the values in the database.
    const update = {
      $set: {
        [`Schedule.${safeMonth}.${safeDay}.${safeTimeslot}.1`]: false,
        [`Schedule.${safeMonth}.${safeDay}.${safeTimeslot}.2`]: safeDetailtype,
        [`Schedule.${safeMonth}.${safeDay}.${safeTimeslot}.3`]: req.session.username,
      },
    };

    const result = await adminScheduleCollection.updateOne(
      {
        id1: "hello",
        [`Schedule.${safeMonth}.${safeDay}.${safeTimeslot}.1`]: true
      },
      update
    );

    return result;
  } catch (error) {
    throw error;
  }
}

app.post("/book", requireAuth, validateBooking, handleValidationErrors, async (req, res) => {
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
    if (error.message.includes('Invalid booking') || error.message.includes('out of range')) {
      return res.status(400).json({ error: error.message });
    }
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
await initializeMongoDB();
app.listen(PORT, () => {
}).on('error', (err) => {
});
