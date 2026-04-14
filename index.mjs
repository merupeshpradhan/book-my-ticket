// =======================
// IMPORTS
// =======================
import express from "express";
import pg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// =======================
// CONFIG
// =======================
dotenv.config();

const app = express();
const port = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;

// =======================
// MIDDLEWARE
// =======================
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT"],
}));

app.use(express.json());

// =======================
// DATABASE CONNECTION
// =======================
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// =======================
// AUTH MIDDLEWARE
// =======================
function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "No token" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// =======================
// REGISTER
// =======================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users(name,email,password) VALUES($1,$2,$3)",
      [name, email, hash]
    );

    res.json({ message: "User created" });

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "User already exists or DB error" });
  }
});

// =======================
// LOGIN
// =======================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (user.rowCount === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const valid = await bcrypt.compare(
      password,
      user.rows[0].password
    );

    if (!valid) {
      return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user.rows[0].id, email },
      JWT_SECRET
    );

    res.json({ token });

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// =======================
// GET SEATS
// =======================
app.get("/seats", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM seats ORDER BY id"
    );

    res.json(result.rows);

  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Failed to fetch seats" });
  }
});

// =======================
// BOOK SEAT
// =======================
app.put("/:id", auth, async (req, res) => {
  const id = req.params.id;

  const conn = await pool.connect();

  try {
    await conn.query("BEGIN");

    const seat = await conn.query(
      "SELECT * FROM seats WHERE id=$1 AND isbooked=0 FOR UPDATE",
      [id]
    );

    if (seat.rowCount === 0) {
      await conn.query("ROLLBACK");
      return res.json({ error: "Already booked" });
    }

    await conn.query(
      "UPDATE seats SET isbooked=1 WHERE id=$1",
      [id]
    );

    await conn.query("COMMIT");

    res.json({ message: "Booked successfully" });

  } catch (err) {
    console.log(err);
    await conn.query("ROLLBACK");
    res.status(500).json({ error: "Booking failed" });

  } finally {
    conn.release();
  }
});

// =======================
// START SERVER
// =======================
app.listen(port, () => {
  console.log("Server running on port " + port);
});