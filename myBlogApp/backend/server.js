const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");


const { open } = require("sqlite");
const sqlite3 = require("sqlite3");

const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, "signup.db");
let db = null;

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    // Creating user table in signup Database

    await db.run(`CREATE TABLE IF NOT EXISTS
             user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT,
                phone INT,
                username TEXT,
                password TEXT
     )`);
    app.listen(5000, () => {
      console.log("Server Running at http://localhost:5000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};
initializeDbAndServer();

// Signup api
app.post("/signup", async (req, res) => {
  const { name, email, phone, username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = "SELECT * FROM user WHERE username = ?";

  try {
    await db.run(
      "INSERT INTO user (name,email,phone,username,password) VALUES (?, ?,?, ?,?)",
      [name, email, phone, username, hashedPassword]
    );
    res.send("User registered successfully!");
    
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// login api
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const selectQuery = "SELECT * FROM user WHERE username = ?";
  try {
    const dbUser = await db.get(selectQuery, [username]);
    // console.log(dbUser);
    if (dbUser === undefined) {
      res.status(400);
      res.send("Invalid User");
    } else {
      const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
      if (isPasswordMatched === true) {
        res.send("Login Success!");
      } else {
        res.status(400);
        res.send("Invalid Password");
      }
    }
  } catch (err) {
    console.log(err.message);
  }
});