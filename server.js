const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const { Server } = require('socket.io');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const QUIZZES_FILE = path.join(DATA_DIR, 'quizzes.json');
const CREDS_FILE = path.join(DATA_DIR, 'credentials.json');
const POINTS_BASE = 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const RP_NAME = process.env.RP_NAME || 'Quiz';

app.set('trust proxy', 1);
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser);
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Storage ---------- */

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}
function load(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function save(file, data) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}
function newId() {
  return crypto.randomBytes(9).toString('base64url');
}

/* ---------- Cookies ---------- */

function cookieParser(req, res, next) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  req.cookies = out;
  next();
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.maxAge) parts.push(`Max-Age=${Math.floor(opts.maxAge / 1000)}`);
  parts.push('Path=/');
  parts.push('HttpOnly');
  parts.push('SameSite=Lax');
  // Secure flag only if behind https
  if (opts.secure) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}
function clearCookie(res, name) {
  res.append('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
}

/* ---------- Sessions ---------- */

const sessions = new Map(); // sid -> { userId, expiresAt }
const webauthnChallenges = new Map(); // wid -> { challenge, userId?, expiresAt, kind }

function createSession(userId) {
  const sid = crypto.randomBytes(32).toString('base64url');
  sessions.set(sid, { userId, expiresAt: Date.now() + SESSION_TTL_MS });
  return sid;
}
function getSession(sid) {
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (s.expiresAt < Date.now()) {
    sessions.delete(sid);
    return null;
  }
  return s;
}

function cleanupChallenges() {
  const now = Date.now();
  for (const [k, v] of webauthnChallenges.entries()) {
    if (v.expiresAt < now) webauthnChallenges.delete(k);
  }
}
setInterval(cleanupChallenges, 60 * 1000).unref();

function isSecure(req) {
  return req.secure || req.get('x-forwarded-proto') === 'https';
}

function authMiddleware(req, res, next) {
  const session = getSession(req.cookies.sid);
  if (!session) return res.status(401).json({ error: 'Nicht eingeloggt' });
  const user = findUser((u) => u.id === session.userId);
  if (!user) return res.status(401).json({ error: 'Account nicht gefunden' });
  if (!user.verified) return res.status(403).json({ error: 'E-Mail noch nicht bestätigt' });
  req.user = user;
  next();
}

/* ---------- Users ---------- */

function loadUsers() { return load(USERS_FILE, []); }
function saveUsers(u) { save(USERS_FILE, u); }
function findUser(pred) { return loadUsers().find(pred) || null; }
function updateUser(id, patch) {
  const users = loadUsers();
  const idx = users.findIndex((u) => u.id === id);
  if (idx < 0) return null;
  users[idx] = { ...users[idx], ...patch };
  saveUsers(users);
  return users[idx];
}

function normaliseEmail(email) {
  return String(email || '').trim().toLowerCase();
}
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* ---------- Mail ---------- */

let mailer = null;
let mailFrom = process.env.SMTP_FROM || 'Quiz <no-reply@localhost>';
if (process.env.SMTP_HOST) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || '').toLowerCase() === 'true',
    auth: process.env.SMTP_USER ? {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    } : undefined,
  });
}

async function sendVerifyMail(email, link) {
  if (!mailer) {
    // eslint-disable-next-line no-console
    console.log('[mail] SMTP nicht konfiguriert. Verify-Link für ' + email + ':\n  ' + link);
    return;
  }
  await mailer.sendMail({
    from: mailFrom,
    to: email,
    subject: 'Quiz: E-Mail bestätigen',
    text: 'Bitte bestätige deine E-Mail-Adresse durch Klick auf folgenden Link:\n\n' + link + '\n\nLink ist 24 Stunden gültig.',
    html: '<p>Bitte bestätige deine E-Mail-Adresse:</p><p><a href="' + link + '">' + link + '</a></p><p>Link ist 24 Stunden gültig.</p>',
  });
}

function baseUrl(req) {
  const proto = req.get('x-forwarded-proto') || req.protocol || 'http';
  const host = req.get('x-forwarded-host') || req.get('host');
  return proto + '://' + host;
}

/* ---------- Auth API ---------- */

app.post('/api/auth/register', async (req, res) => {
  const email = normaliseEmail(req.body && req.body.email);
  const password = String((req.body && req.body.password) || '');
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Ungültige E-Mail-Adresse' });
  if (password.length < 8) return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen lang sein' });
  const users = loadUsers();
  if (users.some((u) => u.email === email)) {
    return res.status(409).json({ error: 'E-Mail ist bereits registriert' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(24).toString('base64url');
  const user = {
    id: newId(),
    email,
    passwordHash,
    verified: false,
    verifyToken,
    verifyExpires: Date.now() + VERIFY_TTL_MS,
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  saveUsers(users);
  linkPendingInvitations(user);

  const link = baseUrl(req) + '/api/auth/verify?token=' + encodeURIComponent(verifyToken);
  try {
    await sendVerifyMail(email, link);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[mail] Versand fehlgeschlagen:', err.message);
  }
  res.json({
    ok: true,
    message: 'Registrierung erfolgreich. Bitte den Bestätigungslink in der E-Mail anklicken.',
    devLink: mailer ? undefined : link,
  });
});

app.get('/api/auth/verify', (req, res) => {
  const token = String(req.query.token || '');
  const users = loadUsers();
  const idx = users.findIndex((u) => u.verifyToken === token);
  if (idx < 0) return res.redirect('/login.html?verify=invalid');
  const user = users[idx];
  if (user.verifyExpires && user.verifyExpires < Date.now()) {
    return res.redirect('/login.html?verify=expired');
  }
  users[idx] = { ...user, verified: true, verifyToken: null, verifyExpires: null };
  saveUsers(users);
  res.redirect('/login.html?verify=ok');
});

app.post('/api/auth/resend', async (req, res) => {
  const email = normaliseEmail(req.body && req.body.email);
  const users = loadUsers();
  const idx = users.findIndex((u) => u.email === email);
  if (idx < 0 || users[idx].verified) {
    return res.json({ ok: true }); // do not leak info
  }
  const verifyToken = crypto.randomBytes(24).toString('base64url');
  users[idx] = { ...users[idx], verifyToken, verifyExpires: Date.now() + VERIFY_TTL_MS };
  saveUsers(users);
  const link = baseUrl(req) + '/api/auth/verify?token=' + encodeURIComponent(verifyToken);
  try { await sendVerifyMail(email, link); } catch (err) { /* eslint-disable-next-line no-console */ console.error(err); }
  res.json({ ok: true, devLink: mailer ? undefined : link });
});

app.post('/api/auth/login', async (req, res) => {
  const email = normaliseEmail(req.body && req.body.email);
  const password = String((req.body && req.body.password) || '');
  const user = findUser((u) => u.email === email);
  if (!user || !user.passwordHash) return res.status(401).json({ error: 'E-Mail oder Passwort falsch' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'E-Mail oder Passwort falsch' });
  if (!user.verified) return res.status(403).json({ error: 'Bitte E-Mail bestätigen', code: 'unverified' });
  const sid = createSession(user.id);
  setCookie(res, 'sid', sid, { maxAge: SESSION_TTL_MS, secure: isSecure(req) });
  res.json({ ok: true, user: { id: user.id, email: user.email } });
});

app.post('/api/auth/logout', (req, res) => {
  const sid = req.cookies.sid;
  if (sid) sessions.delete(sid);
  clearCookie(res, 'sid');
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const session = getSession(req.cookies.sid);
  if (!session) return res.json({ user: null });
  const user = findUser((u) => u.id === session.userId);
  if (!user || !user.verified) return res.json({ user: null });
  const creds = load(CREDS_FILE, []).filter((c) => c.userId === user.id);
  res.json({ user: { id: user.id, email: user.email, passkeys: creds.length } });
});

/* ---------- WebAuthn (Passkey) ---------- */

function rpInfo(req) {
  const host = req.get('x-forwarded-host') || req.get('host') || '';
  const hostname = host.split(':')[0];
  return { rpID: hostname || 'localhost', origin: baseUrl(req) };
}

function storeChallenge(challenge, extra) {
  const wid = crypto.randomBytes(24).toString('base64url');
  webauthnChallenges.set(wid, {
    challenge,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
    ...extra,
  });
  return wid;
}
function popChallenge(wid) {
  const c = webauthnChallenges.get(wid);
  if (!c) return null;
  webauthnChallenges.delete(wid);
  if (c.expiresAt < Date.now()) return null;
  return c;
}

// Eingeloggter User registriert einen neuen Passkey
app.post('/api/webauthn/register/options', authMiddleware, async (req, res) => {
  const { rpID } = rpInfo(req);
  const existing = load(CREDS_FILE, []).filter((c) => c.userId === req.user.id);
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID,
    userID: new TextEncoder().encode(req.user.id),
    userName: req.user.email,
    userDisplayName: req.user.email,
    attestationType: 'none',
    excludeCredentials: existing.map((c) => ({ id: c.credentialID, type: 'public-key' })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });
  const wid = storeChallenge(options.challenge, { userId: req.user.id, kind: 'register' });
  setCookie(res, 'wid', wid, { maxAge: CHALLENGE_TTL_MS, secure: isSecure(req) });
  res.json(options);
});

app.post('/api/webauthn/register/verify', authMiddleware, async (req, res) => {
  const wid = req.cookies.wid;
  const stored = popChallenge(wid);
  clearCookie(res, 'wid');
  if (!stored || stored.userId !== req.user.id || stored.kind !== 'register') {
    return res.status(400).json({ error: 'Challenge ungültig oder abgelaufen' });
  }
  const { rpID, origin } = rpInfo(req);
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  if (!verification.verified || !verification.registrationInfo) {
    return res.status(400).json({ error: 'Passkey-Verifikation fehlgeschlagen' });
  }
  const info = verification.registrationInfo;
  const creds = load(CREDS_FILE, []);
  creds.push({
    id: newId(),
    userId: req.user.id,
    credentialID: info.credentialID,
    publicKey: Buffer.from(info.credentialPublicKey).toString('base64url'),
    counter: info.counter,
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    createdAt: new Date().toISOString(),
    label: (req.body && req.body.label) ? String(req.body.label).slice(0, 40) : 'Passkey',
  });
  save(CREDS_FILE, creds);
  res.json({ ok: true });
});

app.get('/api/webauthn/credentials', authMiddleware, (req, res) => {
  const creds = load(CREDS_FILE, []).filter((c) => c.userId === req.user.id);
  res.json(creds.map((c) => ({ id: c.id, label: c.label, createdAt: c.createdAt })));
});

app.delete('/api/webauthn/credentials/:id', authMiddleware, (req, res) => {
  const creds = load(CREDS_FILE, []);
  const idx = creds.findIndex((c) => c.id === req.params.id && c.userId === req.user.id);
  if (idx < 0) return res.status(404).json({ error: 'Passkey nicht gefunden' });
  creds.splice(idx, 1);
  save(CREDS_FILE, creds);
  res.json({ ok: true });
});

// Login per Passkey
app.post('/api/webauthn/login/options', async (req, res) => {
  const email = normaliseEmail(req.body && req.body.email);
  const { rpID } = rpInfo(req);
  let allowCredentials = [];
  let userId = null;
  if (email) {
    const user = findUser((u) => u.email === email);
    if (user) {
      userId = user.id;
      allowCredentials = load(CREDS_FILE, [])
        .filter((c) => c.userId === user.id)
        .map((c) => ({ id: c.credentialID, type: 'public-key' }));
    }
  }
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: 'preferred',
  });
  const wid = storeChallenge(options.challenge, { userId, kind: 'login' });
  setCookie(res, 'wid', wid, { maxAge: CHALLENGE_TTL_MS, secure: isSecure(req) });
  res.json(options);
});

app.post('/api/webauthn/login/verify', async (req, res) => {
  const wid = req.cookies.wid;
  const stored = popChallenge(wid);
  clearCookie(res, 'wid');
  if (!stored || stored.kind !== 'login') {
    return res.status(400).json({ error: 'Challenge ungültig oder abgelaufen' });
  }
  const credId = req.body && req.body.id;
  if (!credId) return res.status(400).json({ error: 'Keine Credential-ID' });
  const creds = load(CREDS_FILE, []);
  const cred = creds.find((c) => c.credentialID === credId);
  if (!cred) return res.status(404).json({ error: 'Passkey unbekannt' });
  if (stored.userId && stored.userId !== cred.userId) {
    return res.status(400).json({ error: 'Passkey passt nicht zur E-Mail' });
  }
  const user = findUser((u) => u.id === cred.userId);
  if (!user || !user.verified) return res.status(403).json({ error: 'Account nicht aktiv' });

  const { rpID, origin } = rpInfo(req);
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
      authenticator: {
        credentialID: cred.credentialID,
        credentialPublicKey: Buffer.from(cred.publicKey, 'base64url'),
        counter: cred.counter,
      },
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  if (!verification.verified) {
    return res.status(401).json({ error: 'Passkey-Verifikation fehlgeschlagen' });
  }
  cred.counter = verification.authenticationInfo.newCounter;
  save(CREDS_FILE, creds);

  const sid = createSession(user.id);
  setCookie(res, 'sid', sid, { maxAge: SESSION_TTL_MS, secure: isSecure(req) });
  res.json({ ok: true, user: { id: user.id, email: user.email } });
});

/* ---------- Quizzes ---------- */

const QUIZ_MODES = ['open', 'questions-visible', 'count-only'];
const HOST_MODES = ['owner', 'members'];

function loadQuizzes() { return load(QUIZZES_FILE, []).map(normaliseQuiz); }
function saveQuizzes(q) { save(QUIZZES_FILE, q); }

function normaliseQuiz(quiz) {
  return {
    ...quiz,
    mode: QUIZ_MODES.includes(quiz.mode) ? quiz.mode : 'open',
    hostMode: HOST_MODES.includes(quiz.hostMode) ? quiz.hostMode : 'owner',
    memberIds: Array.isArray(quiz.memberIds) ? quiz.memberIds.filter(Boolean) : [],
    pendingEmails: Array.isArray(quiz.pendingEmails) ? quiz.pendingEmails.filter(Boolean) : [],
    questions: (quiz.questions || []).map((q) => ({
      ...q,
      authorId: q.authorId || quiz.userId,
    })),
  };
}

function getQuizRole(quiz, userId) {
  if (!quiz || !userId) return null;
  if (quiz.userId === userId) return 'owner';
  if (quiz.memberIds.includes(userId)) return 'member';
  return null;
}

function canHost(quiz, userId) {
  const role = getQuizRole(quiz, userId);
  if (role === 'owner') return true;
  if (role === 'member' && quiz.hostMode === 'members') return true;
  return false;
}

function canEditQuestion(quiz, q, userId) {
  const role = getQuizRole(quiz, userId);
  if (role === 'owner') return true;
  if (role !== 'member') return false;
  if (quiz.mode === 'open') return true;
  return q.authorId === userId;
}

function canSeeFullQuestion(quiz, q, userId) {
  const role = getQuizRole(quiz, userId);
  if (role === 'owner' || quiz.mode === 'open') return true;
  return q.authorId === userId;
}

function getAccessibleQuizzes(userId) {
  return loadQuizzes().filter((q) => getQuizRole(q, userId));
}

function linkPendingInvitations(user) {
  const list = load(QUIZZES_FILE, []);
  let changed = false;
  for (const quiz of list) {
    if (!Array.isArray(quiz.pendingEmails) || !quiz.pendingEmails.length) continue;
    const idx = quiz.pendingEmails.indexOf(user.email);
    if (idx < 0) continue;
    quiz.pendingEmails.splice(idx, 1);
    quiz.memberIds = Array.isArray(quiz.memberIds) ? quiz.memberIds : [];
    if (!quiz.memberIds.includes(user.id)) quiz.memberIds.push(user.id);
    quiz.updatedAt = new Date().toISOString();
    changed = true;
  }
  if (changed) save(QUIZZES_FILE, list);
}

function authorLookup() {
  const users = loadUsers();
  const map = new Map();
  for (const u of users) map.set(u.id, u.email);
  return (id) => map.get(id) || null;
}

function viewQuestions(quiz, userId) {
  const role = getQuizRole(quiz, userId);
  const all = quiz.questions || [];
  const own = all.filter((q) => q.authorId === userId);
  const othersCount = all.length - own.length;

  if (role === 'owner' || quiz.mode === 'open') {
    return { questions: all, othersCount: 0, ownCount: own.length, totalCount: all.length };
  }
  if (quiz.mode === 'questions-visible') {
    const visible = all.map((q) => {
      if (q.authorId === userId) return q;
      return {
        id: q.id,
        text: q.text,
        timeLimit: q.timeLimit,
        authorId: q.authorId,
        answersCount: q.answers.length,
        redacted: true,
      };
    });
    return { questions: visible, othersCount: 0, ownCount: own.length, totalCount: all.length };
  }
  // count-only
  return { questions: own, othersCount, ownCount: own.length, totalCount: all.length };
}

function memberView(quiz) {
  const lookup = authorLookup();
  return {
    ownerId: quiz.userId,
    ownerEmail: lookup(quiz.userId),
    members: quiz.memberIds.map((id) => ({ id, email: lookup(id) })).filter((m) => m.email),
    pendingEmails: quiz.pendingEmails.slice(),
  };
}

function quizListEntry(quiz, userId) {
  const role = getQuizRole(quiz, userId);
  const all = quiz.questions || [];
  const own = all.filter((q) => q.authorId === userId).length;
  return {
    id: quiz.id,
    name: quiz.name,
    description: quiz.description,
    role,
    mode: quiz.mode,
    hostMode: quiz.hostMode,
    canHost: canHost(quiz, userId),
    totalQuestions: all.length,
    ownQuestions: own,
    createdAt: quiz.createdAt,
    updatedAt: quiz.updatedAt,
  };
}

function validateQuestion(q) {
  if (!q || typeof q.text !== 'string' || !q.text.trim()) return 'Fragetext fehlt';
  if (!Array.isArray(q.answers) || q.answers.length < 2 || q.answers.length > 6) return 'Es müssen 2-6 Antworten angegeben werden';
  if (q.answers.some((a) => typeof a !== 'string' || !a.trim())) return 'Antworten dürfen nicht leer sein';
  const idx = Number(q.correctIndex);
  if (!Number.isInteger(idx) || idx < 0 || idx >= q.answers.length) return 'Index der richtigen Antwort ungültig';
  return null;
}

function getQuizForAccess(req, role) {
  const list = loadQuizzes();
  const quiz = list.find((q) => q.id === req.params.id);
  if (!quiz) return { error: 'Quiz nicht gefunden', status: 404 };
  const userRole = getQuizRole(quiz, req.user.id);
  if (!userRole) return { error: 'Quiz nicht gefunden', status: 404 };
  if (role === 'owner' && userRole !== 'owner') return { error: 'Nur der Ersteller darf das', status: 403 };
  return { quiz, list, role: userRole };
}

app.get('/api/quizzes', authMiddleware, (req, res) => {
  const mine = getAccessibleQuizzes(req.user.id)
    .map((q) => quizListEntry(q, req.user.id))
    .sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  res.json(mine);
});

app.post('/api/quizzes', authMiddleware, (req, res) => {
  const name = String((req.body && req.body.name) || '').trim();
  const description = String((req.body && req.body.description) || '').trim();
  if (!name) return res.status(400).json({ error: 'Quiz-Name fehlt' });
  const quiz = {
    id: newId(),
    userId: req.user.id,
    name: name.slice(0, 80),
    description: description.slice(0, 500),
    mode: 'open',
    hostMode: 'owner',
    memberIds: [],
    pendingEmails: [],
    questions: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const list = load(QUIZZES_FILE, []);
  list.push(quiz);
  saveQuizzes(list);
  res.json(quizListEntry(quiz, req.user.id));
});

app.get('/api/quizzes/:id', authMiddleware, (req, res) => {
  const { quiz, error, status } = getQuizForAccess(req);
  if (error) return res.status(status).json({ error });
  const view = viewQuestions(quiz, req.user.id);
  const role = getQuizRole(quiz, req.user.id);
  res.json({
    id: quiz.id,
    name: quiz.name,
    description: quiz.description,
    mode: quiz.mode,
    hostMode: quiz.hostMode,
    role,
    canHost: canHost(quiz, req.user.id),
    isOwner: role === 'owner',
    members: memberView(quiz),
    questions: view.questions,
    othersCount: view.othersCount,
    ownCount: view.ownCount,
    totalCount: view.totalCount,
    createdAt: quiz.createdAt,
    updatedAt: quiz.updatedAt,
  });
});

app.patch('/api/quizzes/:id', authMiddleware, (req, res) => {
  const { quiz, list, error, status } = getQuizForAccess(req, 'owner');
  if (error) return res.status(status).json({ error });
  if (typeof req.body.name === 'string') {
    const name = req.body.name.trim();
    if (!name) return res.status(400).json({ error: 'Quiz-Name darf nicht leer sein' });
    quiz.name = name.slice(0, 80);
  }
  if (typeof req.body.description === 'string') {
    quiz.description = req.body.description.trim().slice(0, 500);
  }
  if (typeof req.body.mode === 'string') {
    if (!QUIZ_MODES.includes(req.body.mode)) return res.status(400).json({ error: 'Unbekannter Modus' });
    quiz.mode = req.body.mode;
  }
  if (typeof req.body.hostMode === 'string') {
    if (!HOST_MODES.includes(req.body.hostMode)) return res.status(400).json({ error: 'Unbekannter Host-Modus' });
    quiz.hostMode = req.body.hostMode;
  }
  quiz.updatedAt = new Date().toISOString();
  saveQuizzes(list);
  res.json({ ok: true });
});

app.delete('/api/quizzes/:id', authMiddleware, (req, res) => {
  const list = load(QUIZZES_FILE, []);
  const idx = list.findIndex((q) => q.id === req.params.id && q.userId === req.user.id);
  if (idx < 0) return res.status(404).json({ error: 'Quiz nicht gefunden' });
  list.splice(idx, 1);
  saveQuizzes(list);
  res.json({ ok: true });
});

/* members */

app.post('/api/quizzes/:id/members', authMiddleware, (req, res) => {
  const { quiz, list, error, status } = getQuizForAccess(req, 'owner');
  if (error) return res.status(status).json({ error });
  const email = normaliseEmail(req.body && req.body.email);
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Ungültige E-Mail' });
  if (email === normaliseEmail(req.user.email)) return res.status(400).json({ error: 'Du bist selbst der Ersteller' });
  const user = findUser((u) => u.email === email);
  if (user) {
    if (quiz.memberIds.includes(user.id)) return res.status(409).json({ error: 'Bereits Mitwirkender' });
    quiz.memberIds.push(user.id);
  } else {
    if (quiz.pendingEmails.includes(email)) return res.status(409).json({ error: 'Einladung bereits gespeichert' });
    quiz.pendingEmails.push(email);
  }
  quiz.updatedAt = new Date().toISOString();
  saveQuizzes(list);
  res.json({ ok: true, pending: !user, members: memberView(quiz) });
});

app.delete('/api/quizzes/:id/members/:key', authMiddleware, (req, res) => {
  const list = loadQuizzes();
  const quiz = list.find((q) => q.id === req.params.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz nicht gefunden' });
  const key = String(req.params.key || '');
  const isOwner = quiz.userId === req.user.id;
  const isSelf = key === req.user.id;
  if (!isOwner && !isSelf) return res.status(403).json({ error: 'Nicht erlaubt' });
  const beforeM = quiz.memberIds.length;
  const beforeP = quiz.pendingEmails.length;
  quiz.memberIds = quiz.memberIds.filter((id) => id !== key);
  if (isOwner) {
    quiz.pendingEmails = quiz.pendingEmails.filter((e) => e !== normaliseEmail(key));
  }
  if (quiz.memberIds.length === beforeM && quiz.pendingEmails.length === beforeP) {
    return res.status(404).json({ error: 'Nicht gefunden' });
  }
  quiz.updatedAt = new Date().toISOString();
  saveQuizzes(list);
  res.json({ ok: true, members: memberView(quiz) });
});

/* questions */

app.post('/api/quizzes/:id/questions', authMiddleware, (req, res) => {
  const { quiz, list, error, status } = getQuizForAccess(req);
  if (error) return res.status(status).json({ error });
  const err = validateQuestion(req.body);
  if (err) return res.status(400).json({ error: err });
  const time = Number(req.body.timeLimit) || 20;
  const q = {
    id: newId(),
    authorId: req.user.id,
    text: req.body.text.trim(),
    answers: req.body.answers.map((a) => a.trim()),
    correctIndex: Number(req.body.correctIndex),
    timeLimit: Math.max(5, Math.min(120, time)),
  };
  quiz.questions = quiz.questions || [];
  quiz.questions.push(q);
  quiz.updatedAt = new Date().toISOString();
  saveQuizzes(list);
  res.json(q);
});

app.patch('/api/quizzes/:id/questions/:qid', authMiddleware, (req, res) => {
  const { quiz, list, error, status } = getQuizForAccess(req);
  if (error) return res.status(status).json({ error });
  const idx = (quiz.questions || []).findIndex((q) => q.id === req.params.qid);
  if (idx < 0) return res.status(404).json({ error: 'Frage nicht gefunden' });
  const current = quiz.questions[idx];
  if (!canEditQuestion(quiz, current, req.user.id)) {
    return res.status(403).json({ error: 'Du darfst diese Frage nicht bearbeiten' });
  }
  const merged = {
    ...current,
    text: req.body.text !== undefined ? String(req.body.text).trim() : current.text,
    answers: Array.isArray(req.body.answers) ? req.body.answers.map((a) => String(a).trim()) : current.answers,
    correctIndex: req.body.correctIndex !== undefined ? Number(req.body.correctIndex) : current.correctIndex,
    timeLimit: req.body.timeLimit !== undefined ? Math.max(5, Math.min(120, Number(req.body.timeLimit) || 20)) : current.timeLimit,
  };
  const err = validateQuestion(merged);
  if (err) return res.status(400).json({ error: err });
  quiz.questions[idx] = merged;
  quiz.updatedAt = new Date().toISOString();
  saveQuizzes(list);
  res.json(merged);
});

app.delete('/api/quizzes/:id/questions/:qid', authMiddleware, (req, res) => {
  const { quiz, list, error, status } = getQuizForAccess(req);
  if (error) return res.status(status).json({ error });
  const idx = (quiz.questions || []).findIndex((q) => q.id === req.params.qid);
  if (idx < 0) return res.status(404).json({ error: 'Frage nicht gefunden' });
  const current = quiz.questions[idx];
  if (!canEditQuestion(quiz, current, req.user.id)) {
    return res.status(403).json({ error: 'Du darfst diese Frage nicht löschen' });
  }
  quiz.questions.splice(idx, 1);
  quiz.updatedAt = new Date().toISOString();
  saveQuizzes(list);
  res.json({ ok: true });
});

/* ---------- Socket.IO: Game ---------- */

const games = new Map(); // pin -> game

function makePin() {
  let pin;
  do { pin = String(Math.floor(100000 + Math.random() * 900000)); } while (games.has(pin));
  return pin;
}

function publicPlayers(game) {
  return Array.from(game.players.values()).map((p) => ({ id: p.id, name: p.name, score: p.score }));
}
function leaderboard(game) {
  return publicPlayers(game).sort((a, b) => b.score - a.score);
}
function broadcastLobby(game) {
  io.to(game.pin).emit('lobby:update', {
    pin: game.pin,
    quizName: game.quizName,
    quizDescription: game.quizDescription,
    players: publicPlayers(game),
    totalQuestions: game.questions.length,
  });
}

function startQuestion(game) {
  const q = game.questions[game.currentIndex];
  if (!q) return finishGame(game);
  game.state = 'question';
  game.questionStart = Date.now();
  game.answers = new Map();
  const deadline = game.questionStart + q.timeLimit * 1000;
  io.to(game.pin).emit('question:start', {
    index: game.currentIndex,
    total: game.questions.length,
    text: q.text,
    answers: q.answers,
    timeLimit: q.timeLimit,
    deadline,
  });
  if (game.timer) clearTimeout(game.timer);
  game.timer = setTimeout(() => endQuestion(game, 'timeout'), q.timeLimit * 1000);
}

function endQuestion(game, reason) {
  if (game.state !== 'question') return;
  if (game.timer) { clearTimeout(game.timer); game.timer = null; }
  const q = game.questions[game.currentIndex];
  const totalTime = q.timeLimit * 1000;
  const perPlayer = [];
  for (const player of game.players.values()) {
    const ans = game.answers.get(player.id);
    let correct = false;
    let gained = 0;
    let choice = null;
    if (ans) {
      choice = ans.choice;
      correct = ans.choice === q.correctIndex;
      if (correct) {
        const remaining = Math.max(0, totalTime - (ans.at - game.questionStart));
        const speed = remaining / totalTime;
        gained = Math.round(POINTS_BASE * (0.5 + 0.5 * speed));
        player.score += gained;
      }
    }
    perPlayer.push({ id: player.id, name: player.name, correct, gained, choice });
  }
  const counts = q.answers.map(() => 0);
  for (const ans of game.answers.values()) {
    if (typeof ans.choice === 'number' && counts[ans.choice] !== undefined) counts[ans.choice] += 1;
  }
  game.state = 'review';
  io.to(game.pin).emit('question:end', {
    reason,
    correctIndex: q.correctIndex,
    counts,
    perPlayer,
    leaderboard: leaderboard(game),
    hasNext: game.currentIndex + 1 < game.questions.length,
  });
  for (const player of game.players.values()) {
    const me = perPlayer.find((p) => p.id === player.id);
    io.to(player.socketId).emit('question:result', {
      correct: me ? me.correct : false,
      gained: me ? me.gained : 0,
      score: player.score,
      correctIndex: q.correctIndex,
    });
  }
}

function finishGame(game) {
  game.state = 'finished';
  if (game.timer) { clearTimeout(game.timer); game.timer = null; }
  io.to(game.pin).emit('game:end', { leaderboard: leaderboard(game) });
}

function disposeGame(game) {
  if (game.timer) clearTimeout(game.timer);
  games.delete(game.pin);
}

io.use((socket, next) => {
  // Parse session cookie on the websocket handshake
  const header = socket.handshake.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  const session = getSession(cookies.sid);
  socket.data.userId = session ? session.userId : null;
  next();
});

io.on('connection', (socket) => {
  socket.data.role = null;

  socket.on('host:create', async ({ quizId, origin } = {}, cb) => {
    if (!socket.data.userId) return cb && cb({ error: 'Bitte einloggen' });
    const quiz = loadQuizzes().find((q) => q.id === quizId);
    if (!quiz || !getQuizRole(quiz, socket.data.userId)) return cb && cb({ error: 'Quiz nicht gefunden' });
    if (!canHost(quiz, socket.data.userId)) return cb && cb({ error: 'Du darfst dieses Quiz nicht starten' });
    if (!quiz.questions || !quiz.questions.length) {
      return cb && cb({ error: 'Quiz hat keine Fragen' });
    }
    const shuffled = quiz.questions.slice().sort(() => Math.random() - 0.5);
    const pin = makePin();
    const game = {
      pin,
      hostSocketId: socket.id,
      hostUserId: socket.data.userId,
      players: new Map(),
      quizName: quiz.name,
      quizDescription: quiz.description,
      questions: shuffled,
      currentIndex: -1,
      state: 'lobby',
      answers: new Map(),
      timer: null,
      questionStart: 0,
    };
    games.set(pin, game);
    socket.join(pin);
    socket.data.role = 'host';
    socket.data.pin = pin;

    const baseOrigin = (typeof origin === 'string' && /^https?:\/\//.test(origin))
      ? origin
      : (socket.handshake.headers.origin || '');
    const joinUrl = baseOrigin
      ? `${baseOrigin}/play.html?pin=${pin}`
      : `/play.html?pin=${pin}`;
    let qrDataUrl = null;
    try {
      qrDataUrl = await QRCode.toDataURL(joinUrl, { margin: 1, width: 320 });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[qr] generation failed', err.message);
    }

    cb && cb({
      pin,
      totalQuestions: shuffled.length,
      quizName: quiz.name,
      joinUrl,
      qr: qrDataUrl,
    });
    broadcastLobby(game);
  });

  socket.on('player:join', ({ pin, name }, cb) => {
    const game = games.get(String(pin || '').trim());
    if (!game) return cb && cb({ error: 'Game-PIN unbekannt' });
    if (game.state !== 'lobby') return cb && cb({ error: 'Spiel hat bereits begonnen' });
    const clean = String(name || '').trim().slice(0, 20);
    if (!clean) return cb && cb({ error: 'Bitte einen Namen eingeben' });
    for (const p of game.players.values()) {
      if (p.name.toLowerCase() === clean.toLowerCase()) return cb && cb({ error: 'Name ist bereits vergeben' });
    }
    const player = { id: socket.id, socketId: socket.id, name: clean, score: 0 };
    game.players.set(socket.id, player);
    socket.join(game.pin);
    socket.data.role = 'player';
    socket.data.pin = game.pin;
    cb && cb({ ok: true, pin: game.pin, name: clean, quizName: game.quizName });
    broadcastLobby(game);
  });

  socket.on('host:start', (_p, cb) => {
    const game = games.get(socket.data.pin);
    if (!game || game.hostSocketId !== socket.id) return cb && cb({ error: 'Nur der Host darf starten' });
    if (game.players.size === 0) return cb && cb({ error: 'Mindestens ein Spieler nötig' });
    if (game.state !== 'lobby') return cb && cb({ error: 'Spiel läuft bereits' });
    game.currentIndex = 0;
    startQuestion(game);
    cb && cb({ ok: true });
  });

  socket.on('host:next', (_p, cb) => {
    const game = games.get(socket.data.pin);
    if (!game || game.hostSocketId !== socket.id) return cb && cb({ error: 'Nur der Host darf weiter' });
    if (game.state !== 'review') return cb && cb({ error: 'Aktuell läuft eine Frage' });
    game.currentIndex += 1;
    if (game.currentIndex >= game.questions.length) finishGame(game);
    else startQuestion(game);
    cb && cb({ ok: true });
  });

  socket.on('player:answer', ({ choice }, cb) => {
    const game = games.get(socket.data.pin);
    if (!game || game.state !== 'question') return cb && cb({ error: 'Keine aktive Frage' });
    const q = game.questions[game.currentIndex];
    if (!Number.isInteger(choice) || choice < 0 || choice >= q.answers.length) return cb && cb({ error: 'Ungültige Antwort' });
    if (game.answers.has(socket.id)) return cb && cb({ error: 'Schon beantwortet' });
    game.answers.set(socket.id, { choice, at: Date.now() });
    cb && cb({ ok: true });
    io.to(game.hostSocketId).emit('host:answerProgress', {
      answered: game.answers.size,
      total: game.players.size,
    });
    if (game.answers.size >= game.players.size) endQuestion(game, 'all-answered');
  });

  socket.on('disconnect', () => {
    const pin = socket.data.pin;
    if (!pin) return;
    const game = games.get(pin);
    if (!game) return;
    if (socket.data.role === 'host') {
      io.to(pin).emit('game:cancelled', { reason: 'Host hat das Spiel verlassen' });
      disposeGame(game);
      return;
    }
    if (socket.data.role === 'player' && game.players.has(socket.id)) {
      game.players.delete(socket.id);
      game.answers.delete(socket.id);
      broadcastLobby(game);
      if (game.state === 'question' && game.players.size > 0 && game.answers.size >= game.players.size) {
        endQuestion(game, 'all-answered');
      }
    }
  });
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log('Quiz läuft auf Port ' + PORT);
  if (!mailer) {
    // eslint-disable-next-line no-console
    console.log('[mail] Kein SMTP konfiguriert – Verify-Links erscheinen in dieser Konsole.');
  }
});
