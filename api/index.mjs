import express from "express";
import pg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();

app.use(cors());
app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET;

/* ROOT */
app.get("/", (req, res) => {
  res.json({ message: "API Working 🚀" });
});

/* REGISTER */
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users(name,email,password) VALUES($1,$2,$3)",
      [name, email, hash]
    );

    res.json({ message: "User created" });
  } catch (err) {
    res.status(500).json({ error: "User exists or DB error" });
  }
});

/* LOGIN */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  if (user.rowCount === 0)
    return res.status(400).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.rows[0].password);

  if (!ok)
    return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign(
    { id: user.rows[0].id },
    JWT_SECRET
  );

  res.json({ token });
});

/* SEATS */
app.get("/seats", async (req, res) => {
  const result = await pool.query("SELECT * FROM seats ORDER BY id");
  res.json(result.rows);
});

/* BOOK */
app.put("/book/:id", async (req, res) => {
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
    await conn.query("ROLLBACK");
    res.status(500).json({ error: "Booking failed" });
  } finally {
    conn.release();
  }
});

export default app;