const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { User, Tx } = require('./models');
const { hash, verify } = require('./util');

const app = express();
app.set('query parser', 'extended');   // lets ?phone[$regex]=.* become an object
app.use(express.json());

// v1 flaw (API8): wildcard CORS
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', '*');
  res.set('Access-Control-Allow-Methods', '*');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// v1 flaw (API2): no token expiry, weak secret from env
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

app.get('/health', (req, res) => {
  const dbUp = mongoose.connection.readyState === 1;
  res.status(dbUp ? 200 : 503).json({ status: dbUp ? 'ok' : 'degraded', db: dbUp });
});

// ---------- Auth ----------
app.post('/api/auth/register', async (req, res) => {
  const { phone, name, password, pin } = req.body;
  if (!phone || !password || !pin) {
    return res.status(400).json({ error: 'phone, password, pin required' });
  }
  const user = await User.create({ phone, name, pin, passwordHash: hash(password) });
  res.status(201).json({ id: user._id, phone: user.phone });
});

// v1 flaw (API2): no rate limit or lockout
app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  const user = await User.findOne({ phone });
  if (!user || !verify(password, user.passwordHash)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = jwt.sign({ id: user._id, phone: user.phone, role: user.role }, process.env.JWT_SECRET);
  res.json({ token });
});

// ---------- Users ----------
app.get('/api/users/me', auth, async (req, res) => {
  res.json(await User.findById(req.user.id));
});

// v1 flaw (API3): mass assignment, client can set role and balance
app.patch('/api/users/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  Object.assign(user, req.body);
  await user.save();
  res.json(user);
});

// v1 flaws: NoSQL injection (CWE-943) + excessive data exposure (returns passwordHash and pin)
app.get('/api/users/search', auth, async (req, res) => {
  res.json(await User.find({ phone: req.query.phone }));
});

// v1 flaw (API7): SSRF, server fetches any URL and returns the body
app.post('/api/users/me/webhook/test', auth, async (req, res) => {
  const r = await fetch(req.body.url);
  res.json({ status: r.status, body: (await r.text()).slice(0, 500) });
});

// ---------- Wallets ----------
// v1 flaw (API1): BOLA, no ownership check on either route
app.get('/api/wallets/:id', auth, async (req, res) => {
  res.json(await User.findById(req.params.id).select('phone name balance'));
});

app.get('/api/wallets/:id/transactions', auth, async (req, res) => {
  const txs = await Tx.find({ $or: [{ from: req.params.id }, { to: req.params.id }] }).sort({ createdAt: -1 });
  res.json(txs);
});

// ---------- Transfers ----------
// v1 flaws (API6): check-then-update race condition, negative amounts allowed, no idempotency key,
// PIN brute-forceable (no lockout)
async function doTransfer(req, res, checkPin) {
  const { to, amount, pin } = req.body;
  const amt = Number(amount);
  if (!amt) return res.status(400).json({ error: 'invalid amount' });

  const sender = await User.findById(req.user.id);
  if (checkPin && sender.pin !== pin) return res.status(403).json({ error: 'wrong pin' });

  const receiver = await User.findOne({ phone: to });
  if (!receiver) return res.status(404).json({ error: 'recipient not found' });
  if (sender.balance < amt) return res.status(400).json({ error: 'insufficient funds' });

  await User.updateOne({ _id: sender._id }, { $inc: { balance: -amt } });
  await User.updateOne({ _id: receiver._id }, { $inc: { balance: amt } });
  const tx = await Tx.create({ from: sender._id, to: receiver._id, amount: amt });
  res.json({ ok: true, txId: tx._id });
}

app.post('/api/transfer', auth, (req, res) => doTransfer(req, res, true));

// v1 flaw (API9): forgotten legacy route, same logic with no PIN check
app.post('/api/v0/transfer', auth, (req, res) => doTransfer(req, res, false));

// ---------- Admin ----------
// v1 flaw (API5): BFLA, any logged-in user can call these
app.get('/api/admin/users', auth, async (req, res) => {
  res.json(await User.find());
});

app.post('/api/admin/adjust', auth, async (req, res) => {
  const { userId, amount } = req.body;
  await User.updateOne({ _id: userId }, { $inc: { balance: Number(amount) } });
  res.json({ ok: true });
});

// v1 flaw (API8): stack traces returned to the client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

const port = process.env.PORT || 3000;
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => app.listen(port, '0.0.0.0', () => console.log(`listening on ${port}`)))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
