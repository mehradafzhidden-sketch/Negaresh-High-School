const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const { Pool } = require("pg");

const app = express();
const port = process.env.PORT || 3000;
const databaseUrl = process.env.DATABASE_URL;
const isProduction = process.env.NODE_ENV === "production";
const allowedRoles = new Set(["manager", "staff", "teacher", "parent"]);

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

if (!databaseUrl) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}
const pool = new Pool({
  connectionString: databaseUrl,
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

app.use(session({
  store: new PgSession({ pool, createTableIfMissing: true, tableName: "user_sessions" }),
  name: "negaresh.sid",
  secret: process.env.SESSION_SECRET || "",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProduction, sameSite: "strict", maxAge: 8 * 60 * 60 * 1000 }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "too_many_attempts", message: "تلاش‌های ورود زیاد است؛ ۱۵ دقیقه بعد دوباره امتحان کنید." }
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS announcements (
      id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS students (
      id BIGSERIAL PRIMARY KEY, student_code TEXT UNIQUE, full_name TEXT NOT NULL,
      grade TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('manager','staff','teacher','parent')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  const count = await pool.query("SELECT COUNT(*)::int AS count FROM announcements");
  if (count.rows[0].count === 0) {
    await pool.query(
      "INSERT INTO announcements (title, body) VALUES ($1,$2),($3,$4)",
      ["به سامانه مدرسه نگرش خوش آمدید", "این نسخه آغازین سامانه است. پیش از ثبت اطلاعات واقعی، ورود امن و سطح دسترسی کاربران باید تکمیل شود.",
       "یادآوری نسخه آزمایشی", "اطلاعات این صفحه نمایشی است و نباید با اطلاعات واقعی دانش‌آموزان جایگزین شود."]
    );
  }
  // The first administrator is created only from private Render environment variables.
  const adminUsername = process.env.ADMIN_USERNAME;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminUsername && adminPassword && adminPassword.length >= 12) {
    const existing = await pool.query("SELECT id FROM users WHERE username = $1", [adminUsername]);
    if (existing.rowCount === 0) {
      const hash = await bcrypt.hash(adminPassword, 12);
      await pool.query("INSERT INTO users (username,password_hash,role) VALUES ($1,$2,'manager')", [adminUsername, hash]);
      console.log("Initial manager account created from environment configuration.");
    }
  }
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "authentication_required" });
  next();
}
function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: "authentication_required" });
    if (!roles.includes(req.session.user.role)) return res.status(403).json({ error: "forbidden" });
    next();
  };
}

app.get("/api/health", async (_req, res) => {
  try { await pool.query("SELECT 1"); res.json({ ok: true, database: "connected" }); }
  catch (_e) { res.status(503).json({ ok: false, database: "unavailable" }); }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: req.session.user });
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!username || !password) return res.status(400).json({ error: "missing_credentials", message: "نام کاربری و رمز عبور را وارد کنید." });
  try {
    const result = await pool.query("SELECT id, username, password_hash, role FROM users WHERE username = $1", [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "invalid_credentials", message: "نام کاربری یا رمز عبور درست نیست." });
    }
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: "session_error" });
      req.session.user = { id: user.id, username: user.username, role: user.role };
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: "session_error" });
        res.json({ ok: true, user: req.session.user });
      });
    });
  } catch (_e) { res.status(500).json({ error: "login_unavailable" }); }
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "logout_failed" });
    res.clearCookie("negaresh.sid", { httpOnly: true, secure: isProduction, sameSite: "strict" });
    res.json({ ok: true });
  });
});

app.get("/api/announcements", requireAuth, async (_req, res) => {
  try {
    const result = await pool.query("SELECT id,title,body,created_at FROM announcements ORDER BY created_at DESC LIMIT 10");
    res.json(result.rows);
  } catch (_e) { res.status(500).json({ error: "could_not_load_announcements" }); }
});

app.get("/api/students/count", requireRoles("manager", "staff", "teacher"), async (_req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*)::int AS count FROM students");
    res.json({ count: result.rows[0].count });
  } catch (_e) { res.status(500).json({ error: "could_not_count_students" }); }
});

app.post("/api/users", requireRoles("manager"), async (req, res) => {
  const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const role = typeof req.body.role === "string" ? req.body.role : "";
  if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return res.status(400).json({ error: "invalid_username", message: "نام کاربری باید ۳ تا ۴۰ حرف انگلیسی، عدد یا . _ - باشد." });
  if (password.length < 12) return res.status(400).json({ error: "weak_password", message: "رمز عبور باید دست‌کم ۱۲ نویسه داشته باشد." });
  if (!allowedRoles.has(role)) return res.status(400).json({ error: "invalid_role" });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query("INSERT INTO users (username,password_hash,role) VALUES ($1,$2,$3) RETURNING id,username,role,created_at", [username, hash, role]);
    res.status(201).json({ user: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "username_exists", message: "این نام کاربری قبلاً استفاده شده است." });
    res.status(500).json({ error: "could_not_create_user" });
  }
});

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

initializeDatabase().then(() => {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    console.error("SESSION_SECRET must be set to a random value of at least 32 characters.");
    process.exit(1);
  }
  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
    console.warn("Initial manager not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD in Render environment variables.");
  }
  app.listen(port, "0.0.0.0", () => console.log(`Negaresh School app listening on ${port}`));
}).catch((error) => {
  console.error("Database initialization failed:", error.message);
  process.exit(1);
});
