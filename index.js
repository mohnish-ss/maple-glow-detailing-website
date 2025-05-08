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
dotenv.config();

//Connecting to our MongoDB Database before utilization throughout code.
const PASS = process.env.MONGODB_PASS;
const uri =
  "mongodb+srv://Admin:" + PASS + "@cluster0.ak6hid0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

const app = express();

var limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

//Using "sessions" allows the user to be logged-in throughout multiple pages in the website without re-loggin in (esentially a "cookie").
app.use(
  session({
    name: "sessionID",
    secret: "SECRET",
    cookie: { maxAge: 86400 },
  })
);

app.use(limiter);

app.use((req, res, next) => {
  res.header("Cache-Control", "private, no-cache, no-store, must-revalidate"); //So that user cannot logout and then still be logged in using the back button in their browser.
  res.locals.isLoggedIn = req.session.username !== undefined; //Setting the "isLoggedIn" variable to either true or false so that user can be authenticated throughout the website.
  next();
});

app.use(express.static("public"));

app.set("view engine", "ejs");

const __dirname = path.resolve();

//app.get methods to redirect to other pages.

app.get("/", (req, res) => {
  const username = req.session.username;
  res.render("home", { username });
});

app.get("/forgot-password", (req, res) => {
  if (req.session.username) {
    res.redirect("/profile");
  } else {
    res.render("forgot-password");
  }
});

app.get("/home", (req, res) => {
  const username = req.session.username;
  res.render("home", { username });
});

app.get("/booking", (req, res) => {
  const username = req.session.username;
  if (username) {
    res.render("booking", { username });
  } else {
    res.render("login");
  }
});

app.get("/estimate", (req, res) => {
  const username = req.session.username;
  res.render("estimate", { username });
});

app.get("/contact", (req, res) => {
  res.render("contact");
});

app.get("/sign-up", (req, res) => {
  const usernameTaken = req.session.usernameTaken;
  res.render("sign-up", { usernameTaken });
});

app.get("/login", (req, res) => {
  let loginInvalid = req.session.loginInvalid;
  if (req.session.username) {
    res.redirect("/");
  } else {
    console.log("Login invalid", loginInvalid);
    res.render("login", { loginInvalid });
  }
});

app.get("/profile", (req, res) => {
  console.log("Username in session:", req.session.username);
  if (req.session.username) {
    const userData = req.session.userData;
    res.render("profile", { userData });
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    } else {
      res.locals.isLoggedIn = false;
      res.redirect("/login");
    }
  });
});

//Generates a random five-digit number to use as a verification code.
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

//Checks if the user's e-mail exists within the database.
async function checkEmailExists(email) {
  try {
    await client.connect();

    const database = client.db("user-details");
    const details = database.collection("details");

    const eMail = { email: email };
    const query = await details.findOne(eMail);

    return query !== null;
  } catch (error) {
    console.log(error);
  } finally {
    await client.close();
  }
}

//Runs when the user submits their e-mail in the "Forgot password" page, esentially tying together all aspects of the code.
app.post("/forgot-password-email", async (req, res) => {
  const code = generateVerificationCode();
  const customerEmail = req.body.email;

  try {
    const emailExists = await checkEmailExists(customerEmail);

    if (emailExists) {
      verificationCode = code;
      req.session.customerEmail = customerEmail;
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "mapleglowdetailing@gmail.com",
          pass: process.env.EMAIL_PASSWORD, //App password for mapleglowdetailing@gmail.com account.
        },
      });

      const emailLayout = {
        from: "mapleglowdetailing@gmail.com",
        to: customerEmail,
        subject: "Password Recovery",
        text: "Enter this code to log-in: " + code,
      };

      transporter.sendMail(emailLayout, (error, info) => {
        if (error) {
          console.error("Error sending email:", error);
        }
      });

      res.send("Email sent successfully");
    } else {
      res.send("Email not linked to an account");
      return;
    }
  } catch (error) {
    console.error("Error checking email:", error);
  }
});

//Runs when the user submits the code they recieve in their e-mail.
app.post("/verify-code", (req, res) => {
  const code = req.body.codeValue;
  const customerEmail = req.session.customerEmail;

  const storedCode = verificationCode;

  if (code === storedCode) {
    res.send("Code verified successfully");
  } else {
    res.send("Invalid verification code");
  }
});

//Finds the password of the user based on their e-mail if the user submits the correct verification code.
async function findPassword(email) {
  try {
    await client.connect();
    const database = client.db("user-details");
    const details = database.collection("details");

    const eMail = { email: email };
    const query = await details.findOne(eMail);
    const detailsDoc = await details.findOne(query);

    if (detailsDoc) {
      return { success: true, userData: detailsDoc };
    } else {
      return { success: false, message: "Email not found" };
    }
  } finally {
    await client.close();
  }
}

//Runs after the code verification and logs the user in after everything is completed.
app.post("/login-remotely", async (req, res) => {
  const eMail = req.body.email;
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
      passWord: result.userData.password,
    };
    res.status(200).json({ success: true });
  } else {
    res.status(404).json({ success: false });
  }
});

//A function to send booking confirmation e-mails to the customer as well as Liam and Owen.
async function sendConfirmationEmail(
  email,
  name,
  day,
  month,
  time,
  detail,
  address
) {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "mapleglowdetailing@gmail.com",
        pass: "lfcp rjsv xbkn vfan", // App password for mapleglowdetailing@gmail.com account.
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
    console.error("Error", error);
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
    console.error("Error:", error);
    res.status(500).send("Error");
  }
});

//Function to check the user's login credentials by connecting to the database and comparing their input values to the information in the database.
//Full error trapping with the username and password are implemented.
async function checkUserLogin(user, pass, req, res) {
  console.log("Checking login info...");
  try {
    await client.connect();

    const database = client.db("user-details");
    const details = database.collection("details");

    let query;

    if (user.includes("@")) {
      const email = { email: user };
      query = await details.findOne(email);
      if (query === null) {
        console.log("email not found");
        req.session.loginInvalid = true;
        return { success: false };
      }
    } else {
      const username = { username: user };
      query = await details.findOne(username);
      if (query === null) {
        console.log("user not found");
        req.session.loginInvalid = true;
        return { success: false };
      }
    }

    const detailsDoc = await details.findOne(query);

    if (detailsDoc) {
      const password = detailsDoc.password;
      if (password == pass) {
        req.session.loginInvalid = false;
        return { success: true, userData: detailsDoc };
      } else {
        console.log("incorrect password");
        req.session.loginInvalid = true;
        return { success: false };
      }
    }
  } finally {
    await client.close();
  }
}

app.post("/check-login", async (req, res) => {
  const userName = req.body.user;
  const passWord = req.body.pass;
  const result = await checkUserLogin(userName, passWord, req, res);
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
      passWord: result.userData.password,
    };

    res.send("Login successful");
  } else {
    res.send("Invalid credentials");
  }
});

app.post("/save-form", async (req, res) => {
  try {
    const updates = req.body;
    const username = req.body.username;
    await updateDetails(updates, username, req);
    res.redirect("/profile");
  } finally {
    await client.close();
  }
});

//Function to send a customer's inquiry to Liam and Owen if one is submitted through the "Contact" page.
async function sendEmail(customerEmail, subject, text) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "mapleglowdetailing@gmail.com ",
      pass: "lfcp rjsv xbkn vfan", //App password for mapleglowdetailing@gmail.com account.
    },
  });

  const emailLayout = {
    from: "mapleglowdetailing@gmail.com",
    to: ["shethmohnish@gmail.com"],
    subject: subject,
    text: "Customer Inquiry from " + customerEmail + ": " + text,
  };

  transporter.sendMail(emailLayout, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
    }
  });
}

app.post("/contact-form", (req, res) => {
  const subject = req.body.subject;
  const message = req.body.message;
  const customerEmail = req.body.email;

  sendEmail(customerEmail, subject, message);

  console.log("Sent e-mail sucessfully");

  res.redirect("/contact");
});

//Function to update user details in the database once they are edited in the "Profile" page.
async function updateDetails(formData, user, req) {
  try {
    console.log("Connecting to update server...");

    await client.connect();
    const database = client.db("user-details");
    const details = database.collection("details");

    const query = { username: user };

    console.log("Updated details sent to DB:", formData);

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
        passWord: formData.password,
      };
    }
  } catch (error) {
    console.error("Error updating details:", error);
    throw error;
  } finally {
    await client.close();
  }
}

app.post("/sign-up-form", async (req, res) => {
  try {
    const formData = req.body;
    username = req.body.username;

    let usernameTaken = await checkValidUsername(username);

    if (usernameTaken === false) {
      console.log(formData);

      await saveDetails(formData);

      req.session.username = formData.username;
      req.session.userData = {
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        phoneNum: formData.phoneNumber,
        adr: formData.address,
        pCode: formData.postalCode,
        userName: formData.username,
        passWord: formData.password,
      };

      res.redirect("/profile");
    } else {
      req.session.usernameTaken = true;
      console.log("username taken.");
      res.redirect("/sign-up");
      return;
    }
  } catch (error) {
    console.error(error);
    res.send("Error submitting details, try again.");
  }
});

//Saving the user details to the database by connecting to it and inserting the form details.
async function saveDetails(formData) {
  try {
    console.log("Connecting to Database");

    await client.connect();
    const database = client.db("user-details");
    const details = database.collection("details");

    await details.insertOne(formData);

    console.log("User details sumbitted to Database");
  } finally {
    await client.close();
  }
}

//Checking for unique username so that there aren't duplicate users.
async function checkValidUsername(user) {
  console.log("Checking username...");

  await client.connect();
  const database = client.db("user-details");
  const details = database.collection("details");

  let query = await details.findOne({ username: user });

  if (query) {
    return true;
  } else {
    return false;
  }
}

//Reading admin schedule
async function getAdminSchedule() {
  console.log("Trying to get schedule");
  try {
    await client.connect();

    const database = client.db("user-details");
    const adminScheduleCollection = database.collection("adminSchedule");
    const adminSchedule = await adminScheduleCollection.findOne({});

    return adminSchedule;
  } finally {
    await client.close();
  }
}

app.get("/admin-schedule", async (req, res) => {
  try {
    const adminSchedule = await getAdminSchedule();
    res.json(adminSchedule);
  } catch (error) {
    console.error("Error getting admin schedule:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

async function updateDocument() {
  try {
    await client.connect();
    console.log("Connected to the database");

    const database = client.db("user-details");
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
    await client.close();
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
    console.error("Error updating admin schedule:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

async function book(month, day, timeslot, detailtype, req) {
  try {
    await client.connect();
    console.log("Connected to the database");

    const database = client.db("user-details");
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
    await client.close();
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
    console.error("Error updating admin schedule:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

//Running the server on PORT 3000.
app.listen(3000, () => {
  console.log("Express server initialized");
});
