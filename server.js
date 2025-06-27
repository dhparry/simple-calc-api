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
  const hdr = req.headers.authorization || "";
  const token = hdr.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY); // { id, email, iat, exp }
    req.user = decoded; // 👈 now defined
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
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
  const token = jwt.sign(
    { id: user.id, email: user.email }, // 👈 include both!
    SECRET_KEY,
    { expiresIn: "1h" }
  );
  return res.json({ token });
});

/**
 *  POST /api/calculate  (protected)
 *  Headers:  Authorization: Bearer <token>
 *  Body:     { "a": 10, "b": 5 }
 *  Returns:  { user, sum, division }
 */
//* ========= POST /api/calculate (protected) ========= */
app.post('/api/calculate', authMiddleware, async (req, res) => {
  try {
    // 1️⃣ pull all needed fields from the body
    const {
      name = 'Untitled',
      project = 'General',   // 👈 project now included
      a,
      b
    } = req.body;

    const numA = parseFloat(a);
    const numB = parseFloat(b);

    if (Number.isNaN(numA) || Number.isNaN(numB)) {
      return res.status(400).json({ error: 'Invalid input numbers' });
    }

    // 2️⃣ save to the database
    const calc = await prisma.calculation.create({
      data: {
        project,
        name,
        a: numA,
        b: numB,
        sum: numA + numB,
        division: numB ? numA / numB : null,
        userId: req.user.id
      }
    });

    // 3️⃣ respond with the saved row
    res.json(calc);          // you can shorten to this, or send custom fields
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 *  POST /api/compute-only  (protected)
 *  Returns result only (no DB write)
 */
app.post("/api/compute-only", authMiddleware, (req, res) => {
  const { a, b } = req.body;

  const numA = parseFloat(a);
  const numB = parseFloat(b);

  if (Number.isNaN(numA) || Number.isNaN(numB)) {
    return res.status(400).json({ error: "Invalid input numbers" });
  }

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

/**
 * DELETE /api/scenarios/:id   (protected)
 * Deletes a scenario by ID, only if it belongs to the logged-in user
 */
app.delete("/api/scenarios/:id", authMiddleware, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid scenario ID" });

  // Ensure the scenario belongs to the logged-in user
  const scenario = await prisma.calculation.findUnique({ where: { id } });
  if (!scenario || scenario.userId !== req.user.id)
    return res.status(403).json({ error: "Not authorized to delete this scenario" });

  await prisma.calculation.delete({ where: { id } });
  res.json({ message: "Scenario deleted" });
});


  app.get("/api/scenarios", authMiddleware, async (req, res) => {
    const scenarios = await prisma.calculation.findMany({
      where: { userId: req.user.id }, // 👈 use id, not email
      orderBy: { createdAt: "desc" },
    });
    res.json(scenarios);
  });

/* ── START SERVER ───────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`✅  Server running on http://localhost:${PORT}`);
});
