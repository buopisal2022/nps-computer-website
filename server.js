'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const bcrypt = require('bcryptjs');
const multer = require('multer');
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
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024, files: 1 } });
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
const telegramStartLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
function isValidTelegramSecret(value) {
  const expected = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (!expected || typeof value !== 'string') return false;
  const actualBuffer = Buffer.from(value);
  const expectedBuffer = Buffer.from(expected);
  return actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}
app.post('/api/telegram/connect/start', telegramStartLimiter, async (req, res) => {
  const username = (process.env.TELEGRAM_BOT_USERNAME || '').replace(/^@/, '');
  if (!pool || !username || !/^[A-Za-z0-9_]{5,32}$/.test(username)) {
    return res.status(503).json({ error: 'Telegram bot is not configured yet.' });
  }
  try {
    await pool.query('DELETE FROM telegram_chat_id_flows WHERE expires_at < NOW()');
    const state = crypto.randomBytes(24).toString('base64url');
    await pool.query(
      "INSERT INTO telegram_chat_id_flows (state, expires_at) VALUES ($1, NOW() + INTERVAL '10 minutes')",
      [state]
    );
    return res.json({ url: `https://t.me/${username}?start=${state}`, state });
  } catch (error) {
    console.error('Could not start Telegram chat ID flow:', error.message);
    return res.status(503).json({ error: 'មិនអាចចាប់ផ្ដើម Telegram បានទេ។' });
  }
});
app.get('/api/telegram/connect/status', async (req, res) => {
  const state = req.query.state;
  if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{30,40}$/.test(state)) {
    return res.status(400).json({ error: 'Invalid connection request.' });
  }
  try {
    const result = await pool.query(
      'SELECT chat_id, expires_at > NOW() AS active FROM telegram_chat_id_flows WHERE state = $1',
      [state]
    );
    const flow = result.rows[0];
    if (!flow || !flow.active) {
      await pool.query('DELETE FROM telegram_chat_id_flows WHERE state = $1', [state]);
      return res.status(410).json({ error: 'Telegram connection expired. Please try again.' });
    }
    if (!flow.chat_id) return res.json({ status: 'pending' });
    await pool.query('DELETE FROM telegram_chat_id_flows WHERE state = $1', [state]);
    return res.json({ status: 'connected', chatId: String(flow.chat_id) });
  } catch (error) {
    console.error('Could not check Telegram chat ID flow:', error.message);
    return res.status(503).json({ error: 'មិនអាចពិនិត្យ Telegram បានទេ។' });
  }
});
app.post('/api/telegram/webhook', async (req, res) => {
  if (!isValidTelegramSecret(req.get('x-telegram-bot-api-secret-token'))) {
    return res.sendStatus(401);
  }
  const message = req.body && req.body.message;
  const match = message && message.chat && message.chat.type === 'private' &&
    typeof message.text === 'string' &&
    message.text.match(/^\/start(?:@\w+)?\s+([A-Za-z0-9_-]{30,40})(?:\s|$)/);
  if (message && message.chat?.type === 'private' && message.text?.trim() === '/stop') {
    try {
      await pool.query('DELETE FROM telegram_subscribers WHERE chat_id = $1', [String(message.chat.id)]);
    } catch (error) {
      console.error('Could not remove Telegram subscriber:', error.message);
      return res.sendStatus(500);
    }
  }
  if (match) {
    try {
      const linked = await pool.query(
        'UPDATE telegram_chat_id_flows SET chat_id = $1 WHERE state = $2 AND expires_at > NOW() AND chat_id IS NULL RETURNING state',
        [String(message.chat.id), match[1]]
      );
      if (linked.rowCount) {
        await pool.query(
          `INSERT INTO telegram_subscribers (chat_id, username, first_name)
           VALUES ($1, $2, $3) ON CONFLICT (chat_id) DO UPDATE
           SET username = EXCLUDED.username, first_name = EXCLUDED.first_name, subscribed_at = NOW()`,
          [String(message.chat.id), message.from?.username || null, message.from?.first_name || '']
        );
      }
    } catch (error) {
      console.error('Could not save Telegram chat ID flow:', error.message);
      return res.sendStatus(500);
    }
  }
  return res.json({ ok: true });
});
async function configureTelegramWebhook() {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const secret = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (!token || !secret) return;
  try {
    const base = process.env.RENDER_EXTERNAL_URL || 'https://nps-computer-auth.onrender.com';
    const response = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: `${base}/api/telegram/webhook`, secret_token: secret, allowed_updates: ['message'] }),
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) console.error('Telegram webhook setup failed with status', response.status);
  } catch {
    console.error('Telegram webhook setup could not be completed.');
  }
}
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

const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
function requireAdmin(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'សូមចូលគណនី Admin ជាមុនសិន។' });
}
app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!pool || !username || !password) return res.status(400).json({ error: 'សូមបញ្ចូលឈ្មោះ និងពាក្យសម្ងាត់។' });
  try {
    const result = await pool.query('SELECT id, username, password_hash FROM admins WHERE username = $1', [username]);
    const admin = result.rows[0];
    if (!admin || !await bcrypt.compare(password, admin.password_hash)) {
      return res.status(401).json({ error: 'ឈ្មោះ Admin ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវទេ។' });
    }
    req.session.regenerate((error) => {
      if (error) return res.status(500).json({ error: 'មិនអាចចាប់ផ្ដើម session បានទេ។' });
      req.session.adminId = String(admin.id);
      req.session.save((saveError) => saveError
        ? res.status(500).json({ error: 'មិនអាចរក្សាទុក session បានទេ។' })
        : res.json({ admin: { username: admin.username } }));
    });
  } catch (error) {
    console.error('Admin login failed:', error.message);
    return res.status(503).json({ error: 'មិនអាចចូល Admin បានទេ។' });
  }
});
app.get('/api/admin/me', requireAdmin, (req, res) => res.json({ admin: true }));
app.post('/api/admin/logout', requireAdmin, (req, res) => {
  req.session.destroy((error) => {
    res.clearCookie('nps.sid', { httpOnly: true, secure: true, sameSite: 'none' });
    return error ? res.status(500).json({ error: 'មិនអាចចាកចេញបានទេ។' }) : res.json({ ok: true });
  });
});
app.get('/api/admin/posts', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, kind, title, body, media_id, created_at FROM posts ORDER BY created_at DESC LIMIT 50');
    return res.json({ posts: result.rows });
  } catch (error) { return res.status(503).json({ error: 'មិនអាចទាញយក post បានទេ។' }); }
});
app.get('/api/admin/subscribers.csv', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT chat_id, username, first_name, subscribed_at FROM telegram_subscribers ORDER BY subscribed_at DESC');
    const cell = (value) => '"' + String(value ?? '').replace(/"/g, '""') + '"';
    const csv = ['chat_id,username,first_name,subscribed_at', ...result.rows.map(row =>
      [row.chat_id, row.username ? '@' + row.username : '', row.first_name, row.subscribed_at.toISOString()].map(cell).join(',')
    )].join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="nps-telegram-subscribers.csv"');
    return res.send('\uFEFF' + csv);
  } catch (error) { return res.status(503).json({ error: 'មិនអាចនាំចេញ Chat ID បានទេ។' }); }
});
app.post('/api/admin/media', requireAdmin, (req, res, next) => {
  upload.single('file')(req, res, (error) => error
    ? res.status(400).json({ error: error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE' ? 'ឯកសារធំពេក។ អតិបរមា 25 MB។' : 'មិនអាចផ្ទុកឯកសារនេះបានទេ។' })
    : next());
}, async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'សូមជ្រើសរើសរូបភាព ឬវីដេអូ។' });
  const allowed = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm']);
  if (!allowed.has(req.file.mimetype)) return res.status(415).json({ error: 'អាចប្រើតែ JPG, PNG, WebP, GIF, MP4 ឬ WebM។' });
  try {
    const result = await pool.query(
      'INSERT INTO media_assets (content_type, original_name, data, size_bytes) VALUES ($1, $2, $3, $4) RETURNING id',
      [req.file.mimetype, req.file.originalname.slice(0, 180), req.file.buffer, req.file.size]
    );
    return res.status(201).json({ mediaId: String(result.rows[0].id), contentType: req.file.mimetype });
  } catch (error) {
    console.error('Media upload failed:', error.message);
    return res.status(503).json({ error: 'មិនអាចរក្សាទុកឯកសារបានទេ។' });
  }
});
app.get('/api/media/:id', async (req, res) => {
  if (!/^\\d+$/.test(req.params.id)) return res.sendStatus(404);
  try {
    const result = await pool.query('SELECT content_type, data FROM media_assets WHERE id = $1', [req.params.id]);
    if (!result.rowCount) return res.sendStatus(404);
    res.setHeader('Content-Type', result.rows[0].content_type);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.send(result.rows[0].data);
  } catch (error) { return res.sendStatus(503); }
});
app.get('/api/posts', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, kind, title, body, media_id, created_at FROM posts ORDER BY created_at DESC LIMIT 30');
    return res.json({ posts: result.rows });
  } catch (error) { return res.status(503).json({ error: 'មិនអាចទាញយក post បានទេ។' }); }
});
app.post('/api/admin/posts', requireAdmin, async (req, res) => {
  const kind = req.body?.kind;
  const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
  const body = typeof req.body?.body === 'string' ? req.body.body.trim() : '';
  const mediaId = req.body?.mediaId || null;
  if (!['status', 'photo', 'video'].includes(kind) || !title || title.length > 160 || body.length > 4000) {
    return res.status(400).json({ error: 'សូមពិនិត្យប្រភេទ post ចំណងជើង និងអត្ថបទ។' });
  }
  try {
    if (kind !== 'status' && !mediaId) return res.status(400).json({ error: 'សូមបញ្ចូលឯកសារមុនបង្កើត post។' });
    if (mediaId) {
      const media = await pool.query('SELECT content_type FROM media_assets WHERE id = $1', [mediaId]);
      if (!media.rowCount || (kind === 'photo' && !media.rows[0].content_type.startsWith('image/')) ||
          (kind === 'video' && !media.rows[0].content_type.startsWith('video/'))) {
        return res.status(400).json({ error: 'ប្រភេទឯកសារមិនត្រូវនឹង post ទេ។' });
      }
    }
    const result = await pool.query(
      'INSERT INTO posts (kind, title, body, media_id) VALUES ($1, $2, $3, $4) RETURNING id',
      [kind, title, body, mediaId]
    );
    return res.status(201).json({ id: String(result.rows[0].id) });
  } catch (error) {
    console.error('Post creation failed:', error.message);
    return res.status(503).json({ error: 'មិនអាចបង្កើត post បានទេ។' });
  }
});
app.get('/api/sale-products', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, description, price, media_id, created_at FROM sale_products WHERE active = TRUE ORDER BY created_at DESC LIMIT 50');
    return res.json({ products: result.rows });
  } catch (error) { return res.status(503).json({ error: 'មិនអាចទាញយកផលិតផលបានទេ។' }); }
});
app.post('/api/admin/sale-products', requireAdmin, async (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const description = typeof req.body?.description === 'string' ? req.body.description.trim() : '';
  const price = typeof req.body?.price === 'string' ? req.body.price.trim() : '';
  const mediaId = req.body?.mediaId || null;
  if (!name || name.length > 160 || description.length > 4000 || !price || price.length > 80) {
    return res.status(400).json({ error: 'សូមបញ្ចូលឈ្មោះផលិតផល និងតម្លៃត្រឹមត្រូវ។' });
  }
  try {
    if (mediaId) {
      const media = await pool.query('SELECT content_type FROM media_assets WHERE id = $1', [mediaId]);
      if (!media.rowCount || !media.rows[0].content_type.startsWith('image/')) {
        return res.status(400).json({ error: 'រូបភាពផលិតផលមិនត្រឹមត្រូវទេ។' });
      }
    }
    const result = await pool.query(
      'INSERT INTO sale_products (name, description, price, media_id) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, description, price, mediaId]
    );
    return res.status(201).json({ id: String(result.rows[0].id) });
  } catch (error) {
    console.error('Sale product creation failed:', error.message);
    return res.status(503).json({ error: 'មិនអាចបន្ថែមផលិតផលបានទេ។' });
  }
});

app.use(express.static(__dirname));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = error instanceof multer.MulterError ? 400 : 500;
  return res.status(status).json({ error: error instanceof multer.MulterError ? 'File upload failed.' : 'Unexpected server error.' });
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
    await pool.query(`CREATE TABLE IF NOT EXISTS admins (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    if (process.env.ADMIN_PASSWORD) {
      const adminUsername = process.env.ADMIN_USERNAME || 'admin';
      const adminPasswordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await pool.query(
        `INSERT INTO admins (username, password_hash) VALUES ($1, $2)
         ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
        [adminUsername, adminPasswordHash]
      );
    }
    await pool.query(`CREATE TABLE IF NOT EXISTS media_assets (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      content_type TEXT NOT NULL,
      original_name TEXT NOT NULL,
      data BYTEA NOT NULL,
      size_bytes INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS posts (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('status', 'photo', 'video')),
      title TEXT NOT NULL,
      body TEXT NOT NULL DEFAULT '',
      media_id BIGINT REFERENCES media_assets(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS sale_products (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      price TEXT NOT NULL,
      media_id BIGINT REFERENCES media_assets(id),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS telegram_subscribers (
      chat_id BIGINT PRIMARY KEY,
      username TEXT,
      first_name TEXT NOT NULL DEFAULT '',
      subscribed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS admins (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    if (process.env.ADMIN_PASSWORD) {
      const adminUsername = process.env.ADMIN_USERNAME || 'admin';
      const adminPasswordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await pool.query(
        `INSERT INTO admins (username, password_hash) VALUES ($1, $2)
         ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
        [adminUsername, adminPasswordHash]
      );
    }
    await pool.query(`CREATE TABLE IF NOT EXISTS media_assets (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      content_type TEXT NOT NULL,
      original_name TEXT NOT NULL,
      data BYTEA NOT NULL,
      size_bytes INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS posts (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('status', 'photo', 'video')),
      title TEXT NOT NULL,
      body TEXT NOT NULL DEFAULT '',
      media_id BIGINT REFERENCES media_assets(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS sale_products (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      price TEXT NOT NULL,
      media_id BIGINT REFERENCES media_assets(id),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS telegram_subscribers (
      chat_id BIGINT PRIMARY KEY,
      username TEXT,
      first_name TEXT NOT NULL DEFAULT '',
      subscribed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS telegram_chat_id_flows (
      state TEXT PRIMARY KEY,
      chat_id BIGINT,
      expires_at TIMESTAMPTZ NOT NULL
    )`);
  }
  await configureTelegramWebhook();
  app.listen(port, '0.0.0.0', () => console.log(`NPS Computer server listening on ${port}`));
};
start().catch((error) => {
  console.error('Startup failed:', error.message);
  process.exit(1);
});
