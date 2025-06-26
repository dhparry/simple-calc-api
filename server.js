/***************************************************************
 *  server.js – Mini API with basic authentication
 * -------------------------------------------------------------
 *  1. Serves static files from /public      (GET /)
 *  2. POST /register  – create new user (email + password)
 *  3. POST /login     – returns JWT on success
 *  4. POST /api/calculate – protected, returns sum & division
 * -------------------------------------------------------------
 *  NOTES:
 *   • Uses an in-memory array `users[]` to keep things simple.
 *     (Dies when server restarts – replace with a real DB later.)
 *   • SECRET_KEY should come from an env var in production.
 ***************************************************************/

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

/* ---------- CONFIG ------------------------------------------------------ */

// Will hold user objects: { email, password: <bcryptHash> }
const users = [];

// ❗ Replace this with process.env.SECRET_KEY in a real app
const SECRET_KEY = "REPLACE_ME_WITH_ENV_VAR";

/* ---------- MIDDLEWARE -------------------------------------------------- */

// Parse incoming JSON bodies
app.use(express.json());

// Serve everything in ./public at the site root (/, /index.html, etc.)
app.use(express.static("public"));

/* ---------- AUTH MIDDLEWARE -------------------------------------------- */
/**
 * Checks the `Authorization: Bearer <token>` header.
 * If valid, adds `req.user` and calls next(); else 401/403.
 */
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"]; // e.g. "Bearer abc.def.ghi"
  if (!authHeader) return res.status(401).json({ error: "No token provided" });

  const token = authHeader.split(" ")[1]; // grab the part after "Bearer"
  try {
    const decoded = jwt.verify(token, SECRET_KEY); // throws if invalid/expired
    req.user = decoded; // make user info available downstream
    next(); // proceed to route handler
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

/* ---------- ROUTES ------------------------------------------------------ */

/**
 * POST /register
 * Body: { "email": "...", "password": "..." }
 * Steps:
 *   1. Reject duplicate emails.
 *   2. Hash password with bcrypt (saltRounds = 10).
 *   3. Store user object in the in-memory array.
 */
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  // Basic validation – production apps should be stricter
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  // Check for duplicates
  if (users.find((u) => u.email === email))
    return res.status(400).json({ error: "Email already registered" });

  // Hash password (10 salt rounds is a good default)
  const hash = await bcrypt.hash(password, 10);

  users.push({ email, password: hash });
  return res.json({ message: "Registered successfully" });
});

/**
 * POST /login
 * Body: { "email": "...", "password": "..." }
 * Steps:
 *   1. Find user by email
 *   2. Compare plaintext vs hashed password
 *   3. Issue signed JWT (expires in 1 hour)
 */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);

  // Same generic error for bad email or bad pw (prevents account fishing)
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  // Payload can include whatever claims you need; keep it light
  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "1h" });
  return res.json({ token });
});

/**
 * POST /api/calculate   (PROTECTED)
 * Header: Authorization: Bearer <token>
 * Body:   { "a": 10, "b": 5 }
 * Returns: { sum, division, user }
 */
app.post("/api/calculate", authMiddleware, (req, res) => {
  const { a, b } = req.body;

  // Convert to numbers (handle strings)
  const numA = parseFloat(a);
  const numB = parseFloat(b);

  if (Number.isNaN(numA) || Number.isNaN(numB))
    return res.status(400).json({ error: "Invalid input numbers" });

  res.json({
    user: req.user.email, // Who made the request
    sum: numA + numB,
    division: numB !== 0 ? numA / numB : null,
  });
});

/* ---------- START SERVER ------------------------------------------------ */

app.listen(PORT, () => {
  console.log(`✅  Server running on http://localhost:${PORT}`);
});
