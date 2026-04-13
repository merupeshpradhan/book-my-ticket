// =======================
// IMPORTS
// =======================
import express from "express";
import pg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

// =======================
// INIT
// =======================
const app = express();
const port = 8080;
const JWT_SECRET = "secret123";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// =======================
// MIDDLEWARE
// =======================
app.use(cors());
app.use(express.json());
app.use(express.static("frontend")); // serve frontend

// =======================
// POSTGRES
// =======================
const pool = new pg.Pool({
  host: "localhost",
  user: "rupesh",
  password: "Rupesh7327",
  database: "book_my_ticket",
  port: 5432,
});

// =======================
// AUTH MIDDLEWARE
// =======================
function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.send({ error: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.send({ error: "Invalid token" });
  }
}

// =======================
// CREATE TABLES (RUN ONCE)
// =======================
/*
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100) UNIQUE,
  password TEXT
);

CREATE TABLE seats (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),
  isbooked INT DEFAULT 0
);

INSERT INTO seats (isbooked) SELECT 0 FROM generate_series(1,20);
*/

// =======================
// REGISTER
// =======================
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    "INSERT INTO users (name,email,password) VALUES ($1,$2,$3)",
    [name, email, hash]
  );

  res.send({ message: "User created" });
});

// =======================
// LOGIN
// =======================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (user.rowCount === 0)
    return res.send({ error: "User not found" });

  const valid = await bcrypt.compare(password, user.rows[0].password);

  if (!valid) return res.send({ error: "Wrong password" });

  const token = jwt.sign(
    { id: user.rows[0].id, email },
    JWT_SECRET
  );

  res.send({ token });
});

// =======================
// GET SEATS
// =======================
app.get("/seats", async (req, res) => {
  const result = await pool.query("SELECT * FROM seats");
  res.send(result.rows);
});

// =======================
// BOOK SEAT (PROTECTED)
// =======================
app.put("/:id", auth, async (req, res) => {
  const id = req.params.id;
  const userId = req.user.id;

  const conn = await pool.connect();

  try {
    await conn.query("BEGIN");

    const seat = await conn.query(
      "SELECT * FROM seats WHERE id=$1 AND isbooked=0 FOR UPDATE",
      [id]
    );

    if (seat.rowCount === 0) {
      await conn.query("ROLLBACK");
      return res.send({ error: "Already booked" });
    }

    await conn.query(
      "UPDATE seats SET isbooked=1, name=$2 WHERE id=$1",
      [id, userId]
    );

    await conn.query("COMMIT");
    res.send({ message: "Booked" });
  } catch (err) {
    await conn.query("ROLLBACK");
    res.send({ error: "Error booking" });
  } finally {
    conn.release();
  }
});

// =======================
// START SERVER
// =======================
app.listen(port, () => {
  console.log("Server running on http://localhost:" + port);
});