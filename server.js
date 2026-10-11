const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ImapFlow } = require("imapflow");
const nodemailer = require("nodemailer");
const { simpleParser } = require("mailparser");
const { Readable } = require("node:stream");

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || "/data";
const SESSION_SECRET = process.env.SESSION_SECRET;
const ENCRYPTION_SECRET = process.env.ENCRYPTION_KEY;
const REGISTRATION_CODE = process.env.REGISTRATION_CODE;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be set to a random value of at least 32 characters.");
  process.exit(1);
}
if (!ENCRYPTION_SECRET || ENCRYPTION_SECRET.length < 32) {
  console.error("ENCRYPTION_KEY must be set to a separate random value of at least 32 characters.");
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });
const encryptionKey = crypto.createHash("sha256").update(ENCRYPTION_SECRET).digest();
const db = new Database(path.join(DATA_DIR, "okg-webmail.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    imap_host TEXT NOT NULL,
    imap_port INTEGER NOT NULL,
    smtp_host TEXT NOT NULL,
    smtp_port INTEGER NOT NULL,
    credentials_enc TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return [iv.toString("base64"), cipher.getAuthTag().toString("base64"), data.toString("base64")].join(".");
}
function decrypt(value) {
  const [iv, tag, data] = value.split(".").map(part => Buffer.from(part, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8"));
}
function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[ch]);
}
function page(title, content, user = null, notice = "") {
  const nav = user
    ? `<header><a class="brand" href="/">OKG<span>Mail</span></a><div class="nav-right"><span class="user-tag">${escapeHtml(user.username)}</span><form method="post" action="/logout"><button class="button ghost" type="submit">Log out</button></form></div></header>`
    : `<header><a class="brand" href="/">OKG<span>Mail</span></a><span class="user-tag">One inbox. Your account.</span></header>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark"><title>${escapeHtml(title)} · OKG Mail</title><link rel="stylesheet" href="/style.css"></head><body>${nav}<main>${notice ? `<div class="notice">${escapeHtml(notice)}</div>` : ""}${content}</main><footer>OKG Webmail · Connects to your existing mail provider</footer></body></html>`;
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}
function getUser(req) {
  return db.prepare("SELECT id, username FROM users WHERE id = ?").get(req.session.userId);
}
function getMailbox(req, mailboxId) {
  return db.prepare("SELECT * FROM mailboxes WHERE id = ? AND user_id = ?").get(Number(mailboxId), req.session.userId);
}
function mailConfig(box) {
  const credentials = decrypt(box.credentials_enc);
  return { box, credentials };
}
async function withImap(box, fn) {
  const { credentials } = mailConfig(box);
  const client = new ImapFlow({
    host: box.imap_host,
    port: box.imap_port,
    secure: box.imap_port === 993,
    auth: { user: box.email, pass: credentials.password },
    logger: false,
    greetingTimeout: 12000,
    socketTimeout: 20000
  });
  try {
    await client.connect();
    return await fn(client);
  } finally {
    try { await client.logout(); } catch {}
  }
}
function streamToBuffer(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", chunk => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}
function mailboxCard(box) {
  return `<div class="mailbox-card"><div><strong>${escapeHtml(box.email)}</strong><small>${escapeHtml(box.imap_host)} · IMAP ${box.imap_port}</small></div><div class="actions"><a class="button" href="/mail/${box.id}">Open inbox</a><form method="post" action="/mailboxes/${box.id}/delete" onsubmit="return confirm('Remove this connected mailbox?')"><button class="button danger" type="submit">Remove</button></form></div></div>`;
}
function dashboard(req, notice = "") {
  const user = getUser(req);
  const boxes = db.prepare("SELECT * FROM mailboxes WHERE user_id = ? ORDER BY id DESC").all(user.id);
  const cards = boxes.length ? boxes.map(mailboxCard).join("") : '<div class="empty"><div class="empty-icon">✉</div><h2>No inbox connected yet</h2><p>Connect your FounderMail mailbox to get started.</p></div>';
  const content = `<section class="hero"><div class="eyebrow">YOUR OKG WORKSPACE</div><h1>Email, without the chaos.</h1><p>Connect your existing inboxes and manage them here.</p><a class="button primary" href="/connect">＋ Connect mailbox</a></section><section class="section-head"><div><h2>Your mailboxes</h2><p>Only you can access the mailboxes connected to your account.</p></div><span class="count">${boxes.length} connected</span></section><section class="mailbox-list">${cards}</section>`;
  res.send(page("Dashboard", content, user, notice));
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(session({
  name: "okg.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 8 * 60 * 60 * 1000 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: "draft-8", legacyHeaders: false });
app.use("/style.css", express.static(path.join(__dirname, "public"), { maxAge: "1h" }));
app.get("/health", (_req, res) => res.status(200).json({ ok: true, service: "okg-webmail" }));

app.get("/", (req, res) => req.session.userId ? dashboard(req) : res.redirect("/login"));
app.get("/register", (_req, res) => {
  const content = `<section class="auth-card"><div class="eyebrow">GET STARTED</div><h1>Create your account</h1><p>Make your own private OKG Webmail login.</p><form method="post" action="/register"><label>Username<input name="username" minlength="3" maxlength="32" pattern="[A-Za-z0-9_.-]+" required autocomplete="username"></label><label>Password<input name="password" type="password" minlength="12" maxlength="128" required autocomplete="new-password"><small>Use at least 12 characters.</small></label><label>Staff registration code<input name="code" type="password" required autocomplete="off"></label><button class="button primary full" type="submit">Create account</button></form><p class="switch">Already registered? <a href="/login">Log in</a></p></section>`;
  res.send(page("Register", content, null, REGISTRATION_CODE ? "" : "Registration is currently disabled until the owner sets REGISTRATION_CODE on the server."));
});
app.post("/register", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const code = String(req.body.code || "");
  const suppliedCode = Buffer.from(code);
  const expectedCode = Buffer.from(REGISTRATION_CODE || "");
  if (!REGISTRATION_CODE || suppliedCode.length !== expectedCode.length || !crypto.timingSafeEqual(suppliedCode, expectedCode)) {
    return res.status(403).send(page("Registration unavailable", '<section class="auth-card"><h1>Registration unavailable</h1><p>Ask the OKG owner for the correct registration setup.</p><a href="/login">Back to login</a></section>'));
  }
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username) || password.length < 12 || password.length > 128) {
    return res.status(400).send(page("Check details", '<section class="auth-card"><h1>Check your details</h1><p>Use a 3–32 character username and a password of 12–128 characters.</p><a href="/register">Try again</a></section>'));
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
    req.session.regenerate(err => {
      if (err) return res.status(500).send("Could not start session.");
      req.session.userId = Number(result.lastInsertRowid);
      res.redirect("/");
    });
  } catch {
    res.status(409).send(page("Account exists", '<section class="auth-card"><h1>Username unavailable</h1><p>That username may already be taken.</p><a href="/register">Try another</a></section>'));
  }
});
app.get("/login", (req, res) => {
  if (req.session.userId) return res.redirect("/");
  const content = `<section class="auth-card"><div class="eyebrow">OKG WORKSPACE</div><h1>Welcome back.</h1><p>Log in to your private mail workspace.</p><form method="post" action="/login"><label>Username<input name="username" required autocomplete="username"></label><label>Password<input name="password" type="password" required autocomplete="current-password"></label><button class="button primary full" type="submit">Log in</button></form><p class="switch">New here? <a href="/register">Create an account</a></p></section>`;
  res.send(page("Login", content));
});
app.post("/login", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).send(page("Login failed", '<section class="auth-card"><h1>Login failed</h1><p>Username or password was incorrect.</p><a href="/login">Try again</a></section>'));
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).send("Could not start session.");
    req.session.userId = user.id;
    res.redirect("/");
  });
});
app.post("/logout", requireAuth, (req, res) => req.session.destroy(() => res.redirect("/login")));

app.get("/connect", requireAuth, (req, res) => {
  const content = `<section class="form-card"><a class="back" href="/">← Dashboard</a><div class="eyebrow">MAILBOX SETUP</div><h1>Connect a mailbox</h1><p>Use the email address and mailbox password from your email provider. These are not your OKG Webmail password.</p><form method="post" action="/connect"><label>Email address<input name="email" type="email" maxlength="254" required autocomplete="email" placeholder="staff@example.com"></label><label>Mailbox password<input name="password" type="password" maxlength="512" required autocomplete="off"></label><div class="form-grid"><label>IMAP server<input name="imapHost" value="imap.foundermail.mx" required maxlength="253"></label><label>IMAP port<input name="imapPort" type="number" value="993" min="1" max="65535" required></label><label>SMTP server<input name="smtpHost" value="smtp.foundermail.mx" required maxlength="253"></label><label>SMTP port<input name="smtpPort" type="number" value="587" min="1" max="65535" required></label></div><p class="hint">Default settings are prefilled for FounderMail. If your provider gave you different server settings, use those instead.</p><button class="button primary full" type="submit">Test and connect</button></form></section>`;
  res.send(page("Connect mailbox", content, getUser(req)));
});
app.post("/connect", requireAuth, authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const imapHost = String(req.body.imapHost || "").trim();
  const smtpHost = String(req.body.smtpHost || "").trim();
  const imapPort = Number(req.body.imapPort);
  const smtpPort = Number(req.body.smtpPort);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password || password.length > 512 ||
      !/^[a-z0-9.-]+$/i.test(imapHost) || !/^[a-z0-9.-]+$/i.test(smtpHost) ||
      !Number.isInteger(imapPort) || imapPort < 1 || imapPort > 65535 ||
      !Number.isInteger(smtpPort) || smtpPort < 1 || smtpPort > 65535) {
    return res.status(400).send(page("Invalid settings", '<section class="auth-card"><h1>Check the mailbox settings</h1><p>One or more fields are invalid.</p><a href="/connect">Try again</a></section>', getUser(req)));
  }
  try {
    const client = new ImapFlow({
      host: imapHost, port: imapPort, secure: imapPort === 993,
      auth: { user: email, pass: password }, logger: false,
      greetingTimeout: 10000, socketTimeout: 15000
    });
    await client.connect();
    await client.logout();
    db.prepare("INSERT INTO mailboxes (user_id, email, imap_host, imap_port, smtp_host, smtp_port, credentials_enc) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(req.session.userId, email, imapHost, imapPort, smtpHost, smtpPort, encrypt({ password }));
    dashboard(req, "Mailbox connected successfully.");
  } catch (err) {
    console.error("Mailbox connection failed:", err.message);
    res.status(400).send(page("Connection failed", '<section class="auth-card"><h1>Could not connect</h1><p>Check the email address, mailbox password, IMAP hostname, and port. No mailbox was saved.</p><a href="/connect">Try again</a></section>', getUser(req)));
  }
});
app.post("/mailboxes/:id/delete", requireAuth, (req, res) => {
  db.prepare("DELETE FROM mailboxes WHERE id = ? AND user_id = ?").run(Number(req.params.id), req.session.userId);
  res.redirect("/");
});

app.get("/mail/:id", requireAuth, async (req, res) => {
  const box = getMailbox(req, req.params.id);
  if (!box) return res.status(404).send(page("Not found", "<h1>Mailbox not found</h1>", getUser(req)));
  try {
    const messages = await withImap(box, async client => {
      await client.mailboxOpen("INBOX", { readOnly: true });
      const uids = await client.search({ all: true }, { uid: true });
      const recent = (uids || []).slice(-50).reverse();
      if (!recent.length) return [];
      const out = [];
      for await (const msg of client.fetch(recent.join(","), { uid: true, envelope: true, flags: true, internalDate: true }, { uid: true })) {
        out.push({
          uid: msg.uid,
          subject: msg.envelope?.subject || "(no subject)",
          from: msg.envelope?.from?.map(x => x.name ? x.name + " <" + x.address + ">" : x.address).join(", ") || "Unknown sender",
          date: msg.internalDate ? new Date(msg.internalDate).toLocaleString() : "",
          seen: msg.flags?.has("\\Seen") || false
        });
      }
      return out.sort((a, b) => b.uid - a.uid);
    });
    const rows = messages.length ? messages.map(m => `<a class="message-row ${m.seen ? "" : "unread"}" href="/mail/${box.id}/message/${m.uid}"><span class="sender">${escapeHtml(m.from)}</span><span class="subject">${escapeHtml(m.subject)}</span><time>${escapeHtml(m.date)}</time></a>`).join("") : '<div class="empty"><h2>Your inbox is empty</h2><p>New mail will show up here.</p></div>';
    const content = `<a class="back" href="/">← All mailboxes</a><section class="inbox-head"><div><div class="eyebrow">INBOX</div><h1>${escapeHtml(box.email)}</h1><p>Latest messages</p></div><a class="button primary" href="/mail/${box.id}/compose">＋ Compose</a></section><section class="message-list">${rows}</section>`;
    res.send(page("Inbox", content, getUser(req)));
  } catch (err) {
    console.error("Inbox load failed:", err.message);
    res.status(502).send(page("Inbox unavailable", `<section class="auth-card"><h1>Could not load inbox</h1><p>Check your provider's IMAP settings or reconnect the mailbox.</p><a href="/">Back to dashboard</a></section>`, getUser(req)));
  }
});
app.get("/mail/:id/message/:uid", requireAuth, async (req, res) => {
  const box = getMailbox(req, req.params.id);
  const uid = Number(req.params.uid);
  if (!box || !Number.isSafeInteger(uid) || uid < 1) return res.status(404).send(page("Not found", "<h1>Message not found</h1>", getUser(req)));
  try {
    const parsed = await withImap(box, async client => {
      await client.mailboxOpen("INBOX");
      const downloaded = await client.download(uid, undefined, { uid: true });
      return simpleParser(await streamToBuffer(downloaded.content));
    });
    const from = parsed.from?.text || "Unknown sender";
    const replyTo = parsed.from?.value?.[0]?.address || "";
    const to = parsed.to?.text || "";
    const date = parsed.date ? parsed.date.toLocaleString() : "";
    const body = parsed.text ? escapeHtml(parsed.text) : "This message has no plain-text body.";
    const content = `<a class="back" href="/mail/${box.id}">← Back to inbox</a><article class="email-view"><div class="email-actions"><a class="button" href="/mail/${box.id}/compose?to=${encodeURIComponent(replyTo)}&subject=${encodeURIComponent("Re: " + (parsed.subject || ""))}">Reply</a></div><h1>${escapeHtml(parsed.subject || "(no subject)")}</h1><div class="email-meta"><strong>From:</strong> ${escapeHtml(from)}<br><strong>To:</strong> ${escapeHtml(to)}<br><strong>Date:</strong> ${escapeHtml(date)}</div><pre class="email-body">${body}</pre></article>`;
    res.send(page("Message", content, getUser(req)));
  } catch (err) {
    console.error("Message load failed:", err.message);
    res.status(502).send(page("Message unavailable", '<section class="auth-card"><h1>Could not open message</h1><p>The message may have moved or the connection failed.</p><a href="/">Back to dashboard</a></section>', getUser(req)));
  }
});
app.get("/mail/:id/compose", requireAuth, (req, res) => {
  const box = getMailbox(req, req.params.id);
  if (!box) return res.status(404).send(page("Not found", "<h1>Mailbox not found</h1>", getUser(req)));
  const to = String(req.query.to || "").slice(0, 254);
  const subject = String(req.query.subject || "").slice(0, 200);
  const content = `<a class="back" href="/mail/${box.id}">← Back to inbox</a><section class="form-card"><div class="eyebrow">NEW MESSAGE</div><h1>Compose email</h1><p>Sending from <strong>${escapeHtml(box.email)}</strong></p><form method="post" action="/mail/${box.id}/send"><label>To<input name="to" type="email" maxlength="254" value="${escapeHtml(to)}" required></label><label>Subject<input name="subject" maxlength="200" value="${escapeHtml(subject)}" required></label><label>Message<textarea name="text" rows="10" maxlength="50000" required></textarea></label><button class="button primary full" type="submit">Send email</button></form></section>`;
  res.send(page("Compose", content, getUser(req)));
});
app.post("/mail/:id/send", requireAuth, authLimiter, async (req, res) => {
  const box = getMailbox(req, req.params.id);
  if (!box) return res.status(404).send(page("Not found", "<h1>Mailbox not found</h1>", getUser(req)));
  const to = String(req.body.to || "").trim();
  const subject = String(req.body.subject || "").trim().slice(0, 200);
  const text = String(req.body.text || "").slice(0, 50000);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to) || !subject || !text) {
    return res.status(400).send(page("Invalid message", '<section class="auth-card"><h1>Check your message</h1><p>Recipient, subject, and message are required.</p><a href="/mail/' + box.id + '/compose">Try again</a></section>', getUser(req)));
  }
  try {
    const { credentials } = mailConfig(box);
    const transporter = nodemailer.createTransport({
      host: box.smtp_host, port: box.smtp_port, secure: box.smtp_port === 465,
      requireTLS: box.smtp_port === 587,
      auth: { user: box.email, pass: credentials.password },
      connectionTimeout: 12000, greetingTimeout: 12000, socketTimeout: 20000
    });
    await transporter.sendMail({ from: box.email, to, subject, text });
    res.send(page("Email sent", `<section class="auth-card"><div class="success-icon">✓</div><h1>Email sent</h1><p>Your message was handed to the mail provider.</p><a class="button primary full" href="/mail/${box.id}">Back to inbox</a></section>`, getUser(req)));
  } catch (err) {
    console.error("Send failed:", err.message);
    res.status(502).send(page("Send failed", `<section class="auth-card"><h1>Could not send email</h1><p>Check your SMTP hostname, port, and mailbox credentials with your email provider.</p><a href="/mail/${box.id}/compose">Try again</a></section>`, getUser(req)));
  }
});

app.use((err, _req, res, _next) => {
  console.error("Request error:", err.message);
  res.status(500).send("Something went wrong. Please try again.");
});
app.listen(PORT, "0.0.0.0", () => console.log(`OKG Webmail listening on port ${PORT}`));
