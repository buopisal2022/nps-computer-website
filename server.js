'use strict';

const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = Number(process.env.PORT || 10000);
const databaseUrl = process.env.DATABASE_URL;
const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
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
const googleClient = new OAuth2Client();

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

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
app.get('/api/config', (req, res) => res.json({ googleClientId, authEnabled: Boolean(googleClientId && pool && sessionSecret) }));
app.get('/api/health', async (req, res) => {
  if (!pool) return res.status(503).json({ status: 'database_not_configured' });
  try { await pool.query('SELECT 1'); return res.json({ status: 'ok' }); }
  catch { return res.status(503).json({ status: 'database_unavailable' }); }
});
app.post('/api/auth/google', authLimiter, async (req, res) => {
  if (!pool || !sessionSecret || !googleClientId) return res.status(503).json({ error: 'Google sign-in is not configured yet.' });
  const credential = req.body && req.body.credential;
  if (typeof credential !== 'string' || credential.length > 10000) return res.status(400).json({ error: 'Google credential is missing or invalid.' });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: googleClientId });
    const payload = ticket.getPayload();
    if (!payload || !payload.sub || !payload.email || payload.email_verified !== true) {
      return res.status(401).json({ error: 'Please use a verified Google account.' });
    }
    const result = await pool.query(
      `INSERT INTO users (google_subject, email, display_name, avatar_url, email_verified)
       VALUES ($1, lower($2), $3, $4, TRUE)
       ON CONFLICT (google_subject) DO UPDATE SET
         email = EXCLUDED.email,
         display_name = EXCLUDED.display_name,
         avatar_url = EXCLUDED.avatar_url,
         email_verified = TRUE,
         updated_at = NOW()
       RETURNING id, email, display_name, avatar_url`,
      [payload.sub, payload.email, payload.name || payload.email, payload.picture || null]
    );
    req.session.regenerate((sessionError) => {
      if (sessionError) return res.status(500).json({ error: 'Could not start your session.' });
      req.session.userId = String(result.rows[0].id);
      req.session.save((saveError) => {
        if (saveError) return res.status(500).json({ error: 'Could not save your session.' });
        return res.json({ user: result.rows[0] });
      });
    });
  } catch (error) {
    console.error('Google sign-in failed:', error.message);
    return res.status(401).json({ error: 'Google sign-in could not be verified.' });
  }
});
app.get('/api/me', async (req, res) => {
  if (!pool || !sessionSecret) return res.status(503).json({ error: 'Authentication service is not configured yet.' });
  if (!req.session || !req.session.userId) return res.json({ user: null });
  try {
    const result = await pool.query('SELECT id, email, display_name, avatar_url FROM users WHERE id = $1', [req.session.userId]);
    if (!result.rowCount) return res.json({ user: null });
    return res.json({ user: result.rows[0] });
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
      google_subject TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      avatar_url TEXT,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
  }
  app.listen(port, '0.0.0.0', () => console.log(`NPS Computer server listening on ${port}`));
};
start().catch((error) => {
  console.error('Startup failed:', error.message);
  process.exit(1);
});
