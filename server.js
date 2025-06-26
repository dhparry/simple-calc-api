/******************************************************************
 *  server.js – Mini API with authentication backed by PostgreSQL
 * ----------------------------------------------------------------
 *  1.  Serves static files from /public                (GET /)
 *  2.  POST /register  – create user in DB             (email + pw)
 *  3.  POST /login     – returns JWT on success
 *  4.  POST /api/calculate – protected, returns sum/division
 * ----------------------------------------------------------------
 *  IMPORTANT:
 *   • Uses Prisma + Render Postgres (no more in-memory array!)
 *   • SECRET_KEY & DATABASE_URL come from environment variables
 ******************************************************************/

/* ── Core / 3rd-party imports ────────────────────────────────── */
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client"); // <-- Prisma ORM

/* ── Instantiate app & helpers ───────────────────────────────── */
const app = express();
const prisma = new PrismaClient(); // DB client

const PORT = process.env.PORT || 3000;
/* NEVER keep secrets in code – pull from env vars in production */
const SECRET_KEY = process.env.SECRET_KEY || "REPLACE_ME_WITH_ENV_VAR";

/* ── Global middleware ───────────────────────────────────────── */
// Parse JSON bodies
app.use(express.json());
// Serve everything inside ./public at the site root
app.use(express.static("public"));

/* ── Auth-helper middleware ----------------------------------- */
/**
 *  Checks `Authorization: Bearer <token>`
 *  If valid → attaches decoded user to req.user
 *  If missing/invalid → 401 / 403
 */
function authMiddleware(req, res, next) {
  const hdr = req.headers["authorization"]; // ex: "Bearer abc.def.ghi"
  if (!hdr) return res.status(401).json({ error: "No token provided" });

  const token = hdr.split(" ")[1]; // grab part after "Bearer"
  try {
    const decoded = jwt.verify(token, SECRET_KEY); // throws if invalid/expired
    req.user = decoded; // make user data available
    next(); // continue to route handler
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

/* ── ROUTES ──────────────────────────────────────────────────── */

/**
 *  POST /register
 *  Body: { "email": "a@b.com", "password": "secret" }
 *  Flow:
 *   1. Basic validation
 *   2. Reject duplicate emails (via unique DB constraint)
 *   3. Hash password → store in DB
 */
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  /* Check DB for duplicate email */
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing)
    return res.status(400).json({ error: "Email already registered" });

  /* Hash & store */
  const passwordHash = await bcrypt.hash(password, 10);
  await prisma.user.create({ data: { email, passwordHash } });

  return res.json({ message: "Registered successfully" });
});

/**
 *  POST /login
 *  Body: { "email": "...", "password": "..." }
 *  Flow:
 *   1. Look up user
 *   2. Compare hashed passwords
 *   3. Return signed JWT (1 h expiry)
 */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user)
    // generic message for security
    return res.status(400).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  /* Sign token – payload kept light */
  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "1h" });
  return res.json({ token });
});

/**
 *  POST /api/calculate  (protected)
 *  Headers:  Authorization: Bearer <token>
 *  Body:     { "a": 10, "b": 5 }
 *  Returns:  { user, sum, division }
 */
app.post("/api/calculate", authMiddleware, (req, res) => {
  const { a, b } = req.body;

  const numA = parseFloat(a);
  const numB = parseFloat(b);

  if (Number.isNaN(numA) || Number.isNaN(numB))
    return res.status(400).json({ error: "Invalid input numbers" });

  res.json({
    user: req.user.email,
    sum: numA + numB,
    division: numB !== 0 ? numA / numB : null,
  });
});

/* -----------------------------------------------------------
   GET /api/scenarios    (protected)
   Returns an array of saved calculations for the logged user
   -----------------------------------------------------------*/
  //  app.get('/api/scenarios', authMiddleware, async (req, res) => {
  //   const scenarios = await prisma.calculation.findMany({
  //     where: { user: { email: req.user.email } },
  //     orderBy: { createdAt: 'desc' }
  //   });
  //   res.json(scenarios);
  // });

  app.get("/api/scenarios", async (req, res) => {
    try {
      const scenarios = await prisma.calculation.findMany({
        orderBy: { createdAt: "desc" },
      });
      res.json(scenarios);
    } catch (err) {
      console.error("❌ Error in /api/scenarios:", err);
      res.status(500).json({ error: "Server error" });
    }
  });

/* ── START SERVER ───────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`✅  Server running on http://localhost:${PORT}`);
});
