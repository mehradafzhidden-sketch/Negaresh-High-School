const express = require("express");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const port = process.env.PORT || 3000;
const databaseUrl = process.env.DATABASE_URL;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let pool = null;
if (databaseUrl) {
  pool = new Pool({
    connectionString: databaseUrl,
    ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
  });
}

async function initializeDatabase() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS announcements (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS students (
      id BIGSERIAL PRIMARY KEY,
      student_code TEXT UNIQUE,
      full_name TEXT NOT NULL,
      grade TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  const count = await pool.query("SELECT COUNT(*)::int AS count FROM announcements");
  if (count.rows[0].count === 0) {
    await pool.query(
      "INSERT INTO announcements (title, body) VALUES ($1, $2), ($3, $4)",
      [
        "به سامانه مدرسه نگرش خوش آمدید",
        "این نسخه آغازین سامانه است. پیش از ثبت اطلاعات واقعی، ورود امن و سطح دسترسی کاربران باید تکمیل شود.",
        "یادآوری نسخه آزمایشی",
        "اطلاعات این صفحه نمایشی است و نباید با اطلاعات واقعی دانش‌آموزان جایگزین شود."
      ]
    );
  }
}

app.get("/api/health", async (_req, res) => {
  if (!pool) return res.status(503).json({ ok: false, database: "not_configured" });
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (_error) {
    res.status(503).json({ ok: false, database: "unavailable" });
  }
});

app.get("/api/announcements", async (_req, res) => {
  if (!pool) return res.status(503).json({ error: "database_not_configured" });
  try {
    const result = await pool.query(
      "SELECT id, title, body, created_at FROM announcements ORDER BY created_at DESC LIMIT 10"
    );
    res.json(result.rows);
  } catch (_error) {
    res.status(500).json({ error: "could_not_load_announcements" });
  }
});

// Student records are intentionally not exposed until authentication and role-based access are added.
app.get("/api/students/count", async (_req, res) => {
  if (!pool) return res.status(503).json({ error: "database_not_configured" });
  try {
    const result = await pool.query("SELECT COUNT(*)::int AS count FROM students");
    res.json({ count: result.rows[0].count });
  } catch (_error) {
    res.status(500).json({ error: "could_not_count_students" });
  }
});

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initializeDatabase()
  .then(() => {
    app.listen(port, "0.0.0.0", () => console.log(`Negaresh School app listening on ${port}`));
  })
  .catch((error) => {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  });
