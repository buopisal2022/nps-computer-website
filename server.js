'use strict';

const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const port = Number(process.env.PORT || 10000);
const databaseUrl = process.env.DATABASE_URL;
const sessionSecret = process.env.SESSION_SECRET;
const allowedOrigins = new Set([
  'https://nps-computer-static.onrender.com',
  'http://localhost:3000',
  'http://127.0.0.1:5500'
]);
const pool = databaseUrl ? new Pool({
  connectionString: databaseUrl,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
}) : null;

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' } }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json({ limit: '16kb' }));

if (pool && sessionSecret) {
  const PgStore = connectPgSimple(session);
  app.use(session({
    store: new PgStore({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
    name: 'nps.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  }));
} else {
  app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
      res.status(503).json({ error: 'Authentication service is not configured yet.' });
      return;
    }
    next();
  });
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
function normalizePhone(value) {
  if (typeof value !== 'string') return null;
  let phone = value.trim().replace(/[\s().-]/g, '');
  if (phone.startsWith('00')) phone = '+' + phone.slice(2);
  if (phone.startsWith('0')) phone = '+855' + phone.slice(1);
  else if (/^855\d+$/.test(phone)) phone = '+' + phone;
  if (!/^\+[1-9]\d{7,14}$/.test(phone)) return null;
  return phone;
}
function publicUser(row) {
  return { id: String(row.id), phone_number: row.phone_number, display_name: row.display_name };
}
function startSession(req, res, row) {
  req.session.regenerate((error) => {
    if (error) return res.status(500).json({ error: 'Could not start your session.' });
    req.session.userId = String(row.id);
    req.session.save((saveError) => {
      if (saveError) return res.status(500).json({ error: 'Could not save your session.' });
      return res.json({ user: publicUser(row) });
    });
  });
}
app.get('/api/config', (req, res) => res.json({ authEnabled: Boolean(pool && sessionSecret) }));
app.get('/api/health', async (req, res) => {
  if (!pool) return res.status(503).json({ status: 'database_not_configured' });
  try { await pool.query('SELECT 1'); return res.json({ status: 'ok' }); }
  catch { return res.status(503).json({ status: 'database_unavailable' }); }
});
app.post('/api/auth/register', authLimiter, async (req, res) => {
  if (!pool || !sessionSecret) return res.status(503).json({ error: 'Authentication service is not configured yet.' });
  const phone = normalizePhone(req.body && req.body.phone);
  const password = req.body && req.body.password;
  if (!phone) return res.status(400).json({ error: 'សូមបញ្ចូលលេខទូរស័ព្ទឲ្យបានត្រឹមត្រូវ។' });
  if (typeof password !== 'string' || password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ error: 'ពាក្យសម្ងាត់ត្រូវមានយ៉ាងតិច 8 តួអក្សរ។' });
  }
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (phone_number, password_hash, display_name, email, google_subject, avatar_url, email_verified)
       VALUES ($1, $2, $1, NULL, NULL, NULL, FALSE)
       ON CONFLICT (phone_number) DO NOTHING
       RETURNING id, phone_number, display_name`,
      [phone, passwordHash]
    );
    if (!result.rowCount) return res.status(409).json({ error: 'លេខទូរស័ព្ទនេះមានគណនីរួចហើយ។ សូមចូលគណនី។' });
    return startSession(req, res, result.rows[0]);
  } catch (error) {
    console.error('Phone registration failed:', error.message);
    return res.status(500).json({ error: 'មិនអាចបង្កើតគណនីបានទេ។ សូមព្យាយាមម្តងទៀត។' });
  }
});
app.post('/api/auth/login', authLimiter, async (req, res) => {
  if (!pool || !sessionSecret) return res.status(503).json({ error: 'Authentication service is not configured yet.' });
  const phone = normalizePhone(req.body && req.body.phone);
  const password = req.body && req.body.password;
  if (!phone || typeof password !== 'string' || password.length > 72) {
    return res.status(400).json({ error: 'សូមពិនិត្យលេខទូរស័ព្ទ និងពាក្យសម្ងាត់។' });
  }
  try {
    const result = await pool.query(
      'SELECT id, phone_number, display_name, password_hash FROM users WHERE phone_number = $1',
      [phone]
    );
    const user = result.rows[0];
    const matches = user && user.password_hash ? await bcrypt.compare(password, user.password_hash) : false;
    if (!matches) return res.status(401).json({ error: 'លេខទូរស័ព្ទ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវទេ។' });
    return startSession(req, res, user);
  } catch (error) {
    console.error('Phone login failed:', error.message);
    return res.status(500).json({ error: 'មិនអាចចូលគណនីបានទេ។ សូមព្យាយាមម្តងទៀត។' });
  }
});
app.get('/api/me', async (req, res) => {
  if (!pool || !sessionSecret) return res.status(503).json({ error: 'Authentication service is not configured yet.' });
  if (!req.session || !req.session.userId) return res.json({ user: null });
  try {
    const result = await pool.query('SELECT id, phone_number, display_name FROM users WHERE id = $1', [req.session.userId]);
    if (!result.rowCount) return res.json({ user: null });
    return res.json({ user: publicUser(result.rows[0]) });
  } catch { return res.status(503).json({ error: 'Could not load your account.' }); }
});
app.post('/api/logout', (req, res) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy((error) => {
    res.clearCookie('nps.sid', { httpOnly: true, secure: true, sameSite: 'none' });
    return error ? res.status(500).json({ error: 'Could not sign out.' }) : res.json({ ok: true });
  });
});
app.use(express.static(__dirname));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: 'Unexpected server error.' });
});

const start = async () => {
  if (pool) {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      google_subject TEXT UNIQUE,
      email TEXT UNIQUE,
      phone_number TEXT UNIQUE,
      password_hash TEXT,
      display_name TEXT NOT NULL,
      avatar_url TEXT,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number TEXT');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT');
    await pool.query('ALTER TABLE users ALTER COLUMN google_subject DROP NOT NULL');
    await pool.query('ALTER TABLE users ALTER COLUMN email DROP NOT NULL');
    await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_phone_number_unique ON users (phone_number)');
  }
  app.listen(port, '0.0.0.0', () => console.log(`NPS Computer server listening on ${port}`));
};
start().catch((error) => {
  console.error('Startup failed:', error.message);
  process.exit(1);
});
