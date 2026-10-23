const express = require('express'), path = require('path');
const helmet = require('helmet'), rateLimit = require('express-rate-limit'), cookieParser = require('cookie-parser');
const mongoose = require('mongoose'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');

const { MONGODB_URI, ADMIN_USER = 'admin', ADMIN_PASSWORD, JWT_SECRET } = process.env;
const PROD = process.env.NODE_ENV === 'production';
const dbOn = !!MONGODB_URI;
const adminOn = dbOn && !!ADMIN_PASSWORD && ADMIN_PASSWORD.length >= 10 && !!JWT_SECRET && JWT_SECRET.length >= 16;

const Msg = mongoose.model('Message', new mongoose.Schema({
  name: { type: String, required: true, maxlength: 80 },
  mobile: { type: String, required: true, maxlength: 20 },
  email: { type: String, maxlength: 120, default: '' },
  subject: { type: String, required: true, maxlength: 120 },
  message: { type: String, required: true, maxlength: 2000 },
  read: { type: Boolean, default: false }
}, { timestamps: true }));

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"]
} } }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const h = f => (q, s, n) => f(q, s, n).catch(e => { console.error(e.message); s.status(500).json({ error: 'Server error' }); });
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);
const cleanMsg = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, '').trim().slice(0, n);
const dbReady = () => dbOn && mongoose.connection.readyState === 1;

app.get('/api/health', (q, s) => s.json({ ok: true, database: dbReady(), admin: adminOn }));
app.get('/api/profile', (q, s) => s.json({
  name: 'Rinku', village: 'Panduwa Bara, Prayagraj, Uttar Pradesh, India', location: 'Gujarat, India',
  occupation: 'Loom Operator', company: 'Premratan Polypack', companyLocation: 'Morbi, Tankara, Savdi, Gujarat 363650', mobile: '9336178418'
}));

const contactLimit = rateLimit({ windowMs: 3600e3, limit: 5, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many messages. Please try again later.' } });
app.post('/api/contact', contactLimit, h(async (q, s) => {
  const b = q.body || {};
  if (b.website) return s.status(400).json({ error: 'Rejected' }); // honeypot field, real visitors leave it empty
  const d = { name: clean(b.name, 80), mobile: clean(b.mobile, 20), email: clean(b.email, 120), subject: clean(b.subject, 120), message: cleanMsg(b.message, 2000) };
  if (d.name.length < 2) return s.status(400).json({ error: 'Please enter your full name.' });
  if (!/^\+?[0-9][0-9\s-]{8,14}$/.test(d.mobile)) return s.status(400).json({ error: 'Please enter a valid mobile number.' });
  if (d.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email)) return s.status(400).json({ error: 'Please enter a valid email address.' });
  if (d.subject.length < 3) return s.status(400).json({ error: 'Please enter a subject.' });
  if (d.message.length < 5) return s.status(400).json({ error: 'Please write a message (at least 5 characters).' });
  if (!dbReady()) return s.status(503).json({ error: 'Message service is not available right now. Please use WhatsApp or call.' });
  await Msg.create(d);
  s.status(201).json({ ok: true });
}));

/* ----- admin ----- */
let adminHash = null;
if (adminOn) bcrypt.hash(ADMIN_PASSWORD, 10).then(x => { adminHash = x; });
const loginLimit = rateLimit({ windowMs: 15 * 60e3, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Try again later.' } });
app.post('/api/admin/login', loginLimit, h(async (q, s) => {
  if (!adminOn || !adminHash) return s.status(503).json({ error: 'Admin is not configured on the server.' });
  const b = q.body || {};
  const ok = b.username === ADMIN_USER && typeof b.password === 'string' && await bcrypt.compare(b.password, adminHash);
  if (!ok) return s.status(401).json({ error: 'Wrong username or password.' });
  s.cookie('adm', jwt.sign({ a: 1 }, JWT_SECRET, { expiresIn: '8h' }), { httpOnly: true, secure: PROD, sameSite: 'strict', maxAge: 8 * 3600e3 });
  s.json({ ok: true });
}));
app.post('/api/admin/logout', (q, s) => { s.clearCookie('adm'); s.json({ ok: true }); });
const guard = (q, s, n) => { try { jwt.verify(q.cookies.adm, JWT_SECRET); n(); } catch { s.status(401).json({ error: 'Not signed in' }); } };

app.get('/api/admin/messages', guard, h(async (q, s) => {
  const f = {}, t = clean(q.query.q, 50);
  if (t) { const re = new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'); f.$or = [{ name: re }, { subject: re }, { message: re }, { mobile: re }]; }
  const d = {};
  if (q.query.from && !isNaN(new Date(q.query.from))) d.$gte = new Date(q.query.from);
  if (q.query.to && !isNaN(new Date(q.query.to))) { const x = new Date(q.query.to); x.setHours(23, 59, 59, 999); d.$lte = x; }
  if (Object.keys(d).length) f.createdAt = d;
  const [list, total, unread] = await Promise.all([Msg.find(f).sort({ createdAt: -1 }).limit(200), Msg.countDocuments(), Msg.countDocuments({ read: false })]);
  s.json({ total, unread, messages: list });
}));
app.patch('/api/admin/messages/:id', guard, h(async (q, s) => {
  if (!mongoose.isValidObjectId(q.params.id) || typeof (q.body || {}).read !== 'boolean') return s.status(400).json({ error: 'Bad request' });
  const m = await Msg.findByIdAndUpdate(q.params.id, { read: q.body.read }, { new: true });
  m ? s.json(m) : s.status(404).json({ error: 'Not found' });
}));
app.delete('/api/admin/messages/:id', guard, h(async (q, s) => {
  if (!mongoose.isValidObjectId(q.params.id)) return s.status(400).json({ error: 'Bad request' });
  const m = await Msg.findByIdAndDelete(q.params.id);
  m ? s.json({ ok: true }) : s.status(404).json({ error: 'Not found' });
}));

/* ----- pages ----- */
const base = q => q.protocol + '://' + q.get('host');
app.get('/robots.txt', (q, s) => s.type('text/plain').send('User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: ' + base(q) + '/sitemap.xml\n'));
app.get('/sitemap.xml', (q, s) => s.type('application/xml').send('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + base(q) + '/</loc></url></urlset>'));
const page = (t, body) => '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + t + ' | Rinku</title><style>body{font-family:system-ui,sans-serif;max-width:680px;margin:0 auto;padding:24px;line-height:1.7;color:#0b1230}a{color:#2f5bff}</style></head><body><h1>' + t + '</h1>' + body + '<p><a href="/">Back to home</a></p></body></html>';
app.get('/privacy', (q, s) => s.send(page('Privacy Policy', '<p>This website collects only the details you type in the contact form (name, mobile number, optional email, subject and message). They are stored so that Rinku can reply to you and are visible only to the website administrator.</p><p>Your details are not sold or shared for advertising. To ask for your message to be deleted, contact Rinku on WhatsApp or by phone.</p>')));
app.get('/terms', (q, s) => s.send(page('Terms and Conditions', '<p>This is a personal profile website of Rinku. The information on industry processes is general and is provided for awareness only.</p><p>This website is not officially owned by or affiliated with Premratan Polypack.</p>')));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use((q, s) => s.status(404).send(page('Page not found', '<p>Sorry, this page does not exist.</p>')));

const port = process.env.PORT || 3000;
const start = () => app.listen(port, () => console.log('Server running on port ' + port));
if (dbOn) mongoose.connect(MONGODB_URI).then(start).catch(e => { console.error('MongoDB connection failed:', e.message); start(); });
else { console.warn('MONGODB_URI is not set: the contact form and admin are disabled.'); start(); }
  
