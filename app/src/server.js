const express = require('express');
const helmet = require('helmet');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const { User, Tx } = require('./models');
const { hash, verify } = require('./util');

const app = express();
app.use(helmet());                         // F-08 fix: sane default security headers
app.use(express.json());
// (F-02 fix: removed the "extended" query parser — bracket syntax like phone[$regex]
//  can no longer be turned into a query object at all)

// F-08 fix: CORS restricted to a configured origin instead of "*"
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5173';
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.set('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// F-10 fix (already live): secret from env, now with an expiry too
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

function requireAdmin(req, res, next) {           // F-03 fix
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}

// F-09 fix: rate limiting on sensitive endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'too many login attempts, try again later' },
});
const transferLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'too many transfer attempts, try again later' },
});

app.get('/health', (req, res) => {
  const dbUp = mongoose.connection.readyState === 1;
  res.status(dbUp ? 200 : 503).json({ status: dbUp ? 'ok' : 'degraded', db: dbUp });
});

// ---------- Auth ----------
const registerSchema = z.object({
  phone: z.string().min(6).max(20),
  name: z.string().min(1).max(100).optional(),
  password: z.string().min(8).max(200),
  pin: z.string().regex(/^\d{4}$/),
}).strict();

app.post('/api/auth/register', async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid input', details: parsed.error.issues });
  const { phone, name, password, pin } = parsed.data;
  const user = await User.create({ phone, name, pinHash: hash(pin), passwordHash: hash(password) });
  res.status(201).json({ id: user._id, phone: user.phone });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {       // F-09 fix applied
  const { phone, password } = req.body;
  if (typeof phone !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'invalid credentials' });
  }
  const user = await User.findOne({ phone });
  if (!user || !verify(password, user.passwordHash)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = jwt.sign(
    { id: user._id, phone: user.phone, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }                                              // F-10 fix: tokens now expire
  );
  res.json({ token });
});

// ---------- Users ----------
app.get('/api/users/me', auth, async (req, res) => {
  res.json(await User.findById(req.user.id));      // toJSON transform strips sensitive fields
});

const updateMeSchema = z.object({ name: z.string().min(1).max(100) }).strict();   // F-04 fix

app.patch('/api/users/me', auth, async (req, res) => {
  const parsed = updateMeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid fields', details: parsed.error.issues });
  const user = await User.findByIdAndUpdate(req.user.id, parsed.data, { new: true });
  res.json(user);
});

app.get('/api/users/search', auth, async (req, res) => {    // F-02 fix
  const { phone } = req.query;
  if (typeof phone !== 'string' || !/^[0-9+\-\s]{3,20}$/.test(phone)) {
    return res.status(400).json({ error: 'invalid phone query' });
  }
  const users = await User.find({ phone }).select('_id phone name');
  res.json(users);
});

const webhookSchema = z.object({ url: z.string().url() }).strict();

function isBlockedHost(hostname) {       // F-07 fix: block private/internal network ranges
  return /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0|mongo|redis)$/i.test(hostname)
    || /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(hostname);
}

app.post('/api/users/me/webhook/test', auth, async (req, res) => {
  const parsed = webhookSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid url' });
  const u = new URL(parsed.data.url);
  if (u.protocol !== 'https:') return res.status(400).json({ error: 'only https urls allowed' });
  if (isBlockedHost(u.hostname)) return res.status(400).json({ error: 'destination not permitted' });
  try {
    const r = await fetch(u.toString(), { redirect: 'manual' });
    res.json({ status: r.status });    // F-07 fix: response body no longer echoed back
  } catch {
    res.status(502).json({ error: 'request failed' });
  }
});

// ---------- Wallets ----------
function ownsOrAdmin(req, id) {        // F-01 fix
  return req.user.role === 'admin' || String(req.user.id) === String(id);
}

app.get('/api/wallets/:id', auth, async (req, res) => {
  if (!ownsOrAdmin(req, req.params.id)) return res.status(403).json({ error: 'forbidden' });
  const user = await User.findById(req.params.id).select('phone name balance');
  if (!user) return res.status(404).json({ error: 'not found' });
  res.json(user);
});

app.get('/api/wallets/:id/transactions', auth, async (req, res) => {
  if (!ownsOrAdmin(req, req.params.id)) return res.status(403).json({ error: 'forbidden' });
  const txs = await Tx.find({ $or: [{ from: req.params.id }, { to: req.params.id }] }).sort({ createdAt: -1 });
  res.json(txs);
});

// ---------- Transfers ----------
const transferSchema = z.object({
  to: z.string().min(6).max(20),
  amount: z.number().positive().finite(),      // F-06 fix: must be a positive number
  pin: z.string().regex(/^\d{4}$/),
}).strict();

app.post('/api/transfer', auth, transferLimiter, async (req, res) => {   // F-09 fix applied
  const parsed = transferSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid input', details: parsed.error.issues });
  const { to, amount, pin } = parsed.data;

  const sender = await User.findById(req.user.id);
  if (!verify(pin, sender.pinHash)) return res.status(403).json({ error: 'wrong pin' });

  const receiver = await User.findOne({ phone: to }).select('_id');
  if (!receiver) return res.status(404).json({ error: 'recipient not found' });
  if (String(receiver._id) === String(sender._id)) return res.status(400).json({ error: 'cannot transfer to self' });

  // F-11 fix: single atomic conditional debit. The $gte filter + $inc is
  // evaluated atomically by MongoDB on one document, so concurrent requests
  // cannot both pass the balance check -- only one will match and update.
  const debited = await User.findOneAndUpdate(
    { _id: sender._id, balance: { $gte: amount } },
    { $inc: { balance: -amount } },
    { new: true }
  );
  if (!debited) return res.status(400).json({ error: 'insufficient funds' });

  await User.updateOne({ _id: receiver._id }, { $inc: { balance: amount } });
  const tx = await Tx.create({ from: sender._id, to: receiver._id, amount });
  res.json({ ok: true, txId: tx._id });
});

// F-05 fix: the forgotten /api/v0/transfer legacy route is removed entirely.

// ---------- Admin ----------
app.get('/api/admin/users', auth, requireAdmin, async (req, res) => {   // F-03 fix
  res.json(await User.find());
});

const adjustSchema = z.object({
  userId: z.string().min(1),
  amount: z.number().finite(),
}).strict();

app.post('/api/admin/adjust', auth, requireAdmin, async (req, res) => {  // F-03 fix
  const parsed = adjustSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid input' });
  await User.updateOne({ _id: parsed.data.userId }, { $inc: { balance: parsed.data.amount } });
  res.json({ ok: true });
});

// F-08 fix: generic error response, full detail logged server-side only
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal server error' });
});

const port = process.env.PORT || 3000;
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => app.listen(port, '0.0.0.0', () => console.log(`listening on ${port}`)))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
