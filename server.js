const { randomBytes, scryptSync, timingSafeEqual } = require("node:crypto");
const { existsSync, readFileSync } = require("node:fs");
const { promises: fs } = require("node:fs");
const { createServer } = require("node:http");
const { join } = require("node:path");

const root = __dirname;
const dataDirectory = process.env.DATA_DIR || join(root, ".data");
const dataPath = join(dataDirectory, "tracker.json");
const sessionCookie = "ace_portal";
const sessionLifetime = 12 * 60 * 60 * 1000;
const attemptWindow = 15 * 60 * 1000;
const maxAttempts = 8;
const maxRequestBytes = 2 * 1024 * 1024;
const statuses = ["New", "Reviewing", "Actioned", "Resolved"];
const severities = ["Low", "Medium", "High", "Critical"];
const actions = ["None", "Warning", "Content removed", "Temporary mute", "Temporary ban", "Permanent ban", "Other"];
const sessions = new Map();
const loginAttempts = new Map();

function loadLocalEnvironment() {
  const filePath = join(root, ".env");
  if (!existsSync(filePath)) return;
  for (const line of readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, "$2");
  }
}

loadLocalEnvironment();

function loadStore() {
  if (!existsSync(dataPath)) return { admin: null, members: [], cases: [] };
  try {
    const saved = JSON.parse(readFileSync(dataPath, "utf8"));
    return {
      admin: saved.admin || null,
      members: Array.isArray(saved.members) ? saved.members : [],
      cases: Array.isArray(saved.cases) ? saved.cases : []
    };
  } catch (error) {
    console.error(`Could not read ${dataPath}: ${error.message}`);
    process.exit(1);
  }
}

const store = loadStore();
let adminWasBootstrapped = false;
if (!store.admin && process.env.PORTAL_PASSCODE) {
  if (!validPasscode(process.env.PORTAL_PASSCODE)) {
    console.error("PORTAL_PASSCODE must contain at least 12 characters.");
    process.exit(1);
  }
  store.admin = passwordRecord(process.env.PORTAL_PASSCODE);
  adminWasBootstrapped = true;
}
let saveQueue = Promise.resolve();

function persistStore() {
  saveQueue = saveQueue.catch(() => {}).then(async () => {
    await fs.mkdir(dataDirectory, { recursive: true });
    const temporaryPath = `${dataPath}.${randomBytes(6).toString("hex")}.tmp`;
    await fs.writeFile(temporaryPath, JSON.stringify(store, null, 2), { mode: 0o600 });
    await fs.rename(temporaryPath, dataPath);
  });
  return saveQueue;
}

const startup = adminWasBootstrapped ? persistStore() : Promise.resolve();

function send(res, status, body, contentType, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    ...extraHeaders
  });
  res.end(body);
}

function sendJson(res, status, value, headers = {}) {
  send(res, status, JSON.stringify(value), "application/json; charset=utf-8", headers);
}

function redirect(res, location, extraHeaders = {}) {
  res.writeHead(303, { Location: location, "Cache-Control": "no-store", ...extraHeaders });
  res.end();
}

function readSession(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${sessionCookie}=([A-Za-z0-9_-]+)`));
  if (!match) return null;
  const session = sessions.get(match[1]);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(match[1]);
    return null;
  }
  return session;
}

function setSessionCookie(token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${sessionCookie}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionLifetime / 1000}${secure}`;
}

function clearSessionCookie() {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${sessionCookie}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secure}`;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", chunk => {
      size += chunk.length;
      if (size > maxRequestBytes) {
        tooLarge = true;
        chunks.length = 0;
      } else if (!tooLarge) chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) return reject(new Error("Request is too large."));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); }
      catch { reject(new Error("Invalid request.")); }
    });
    req.on("error", reject);
  });
}

function originAllowed(req) {
  if (!req.headers.origin) return true;
  try {
    const origin = new URL(req.headers.origin);
    return process.env.PUBLIC_ORIGIN
      ? origin.origin === new URL(process.env.PUBLIC_ORIGIN).origin
      : origin.host === req.headers.host;
  }
  catch { return false; }
}

function passwordRecord(passcode) {
  const salt = randomBytes(16);
  const hash = scryptSync(passcode, salt, 64);
  return { salt: salt.toString("base64url"), hash: hash.toString("base64url") };
}

function passwordMatches(passcode, record) {
  if (typeof passcode !== "string" || passcode.length > 1024 || !record?.salt || !record?.hash) return false;
  try {
    const expected = Buffer.from(record.hash, "base64url");
    const actual = scryptSync(passcode, Buffer.from(record.salt, "base64url"), expected.length);
    return expected.length > 0 && timingSafeEqual(expected, actual);
  } catch { return false; }
}

function validPasscode(passcode) {
  return typeof passcode === "string" && passcode.length >= 12 && passcode.length <= 1024;
}

function loginLimit(ip) {
  const now = Date.now();
  let attempt = loginAttempts.get(ip);
  if (!attempt || now - attempt.startedAt >= attemptWindow) {
    attempt = { startedAt: now, count: 0 };
    loginAttempts.set(ip, attempt);
  }
  return attempt;
}

function createSession(res, role, username = null) {
  const token = randomBytes(32).toString("base64url");
  for (const [existingToken, existingSession] of sessions) {
    if (existingSession.expiresAt <= Date.now()) sessions.delete(existingToken);
  }
  const session = { role, username, expiresAt: Date.now() + sessionLifetime };
  sessions.set(token, session);
  sendJson(res, 200, { authenticated: true, role, username }, { "Set-Cookie": setSessionCookie(token) });
}

function requireRole(res, session, role) {
  if (session?.role === role) return true;
  sendJson(res, session ? 403 : 401, { error: session ? "Not allowed." : "Sign in to continue." });
  return false;
}

function normalizeUsername(username) {
  return username.trim().toLowerCase();
}

function validText(value, maximum) {
  return typeof value === "string" && value.length <= maximum;
}

function makeCaseId() {
  const datePart = new Date().toISOString().slice(2, 10).replaceAll("-", "");
  return `ACE-${datePart}-${randomBytes(3).toString("hex").toUpperCase()}`;
}

function normalizeCase(input, existing = null) {
  if (!input || typeof input !== "object") throw new Error("Invalid case data.");
  const username = typeof input.username === "string" ? input.username.trim() : "";
  const category = typeof input.category === "string" ? input.category.trim() : "";
  const status = statuses.includes(input.status) ? input.status : "New";
  const severity = severities.includes(input.severity) ? input.severity : "Medium";
  const date = typeof input.date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(input.date) ? input.date : "";
  if (!username || username.length > 80 || !category || category.length > 120 || !date) {
    throw new Error("Member, violation type, and a valid report date are required.");
  }
  const id = typeof input.id === "string" && input.id.trim() ? input.id.trim().slice(0, 80) : makeCaseId();
  if (id.length > 80) throw new Error("Case ID is too long.");
  const field = (key, maximum) => validText(input[key], maximum) ? input[key].trim() : (existing?.[key] || "");
  return {
    id,
    username,
    category,
    severity,
    date,
    status,
    moderator: field("moderator", 80),
    notes: field("notes", 1200),
    actionTaken: actions.includes(input.actionTaken) ? input.actionTaken : "None",
    memberMessage: field("memberMessage", 1200)
  };
}

function publicCase(item) {
  return {
    id: item.id,
    username: item.username,
    category: item.category,
    severity: item.severity,
    date: item.date,
    status: item.status,
    actionTaken: item.actionTaken || "None",
    memberMessage: item.memberMessage || ""
  };
}

async function servePage(res, fileName) {
  try {
    const content = await fs.readFile(join(root, fileName));
    send(res, 200, content, "text/html; charset=utf-8");
  } catch {
    send(res, 500, "Page unavailable.", "text/plain; charset=utf-8");
  }
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const session = readSession(req);

  if (req.method === "GET" && url.pathname === "/api/session") {
    sendJson(res, 200, { authenticated: Boolean(session), role: session?.role || null, username: session?.username || null, setupRequired: !store.admin });
    return;
  }

  if (req.method === "POST" && ["/api/setup", "/api/login"].includes(url.pathname)) {
    if (!originAllowed(req)) {
      sendJson(res, 403, { error: "Request origin not allowed." });
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/setup") {
    if (store.admin) {
      sendJson(res, 409, { error: "Initial setup is already complete." });
      return;
    }
    try {
      const body = await readJson(req);
      if (!validPasscode(body.passcode)) throw new Error("Choose a passcode with at least 12 characters.");
      store.admin = passwordRecord(body.passcode);
      await persistStore();
      createSession(res, "admin");
    } catch (error) {
      if (!res.headersSent) sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/login") {
    const ip = req.socket.remoteAddress || "unknown";
    const attempt = loginLimit(ip);
    if (attempt.count >= maxAttempts) {
      const secondsRemaining = Math.ceil((attemptWindow - (Date.now() - attempt.startedAt)) / 1000);
      sendJson(res, 429, { error: "Too many attempts. Try again later." }, { "Retry-After": String(secondsRemaining) });
      return;
    }
    try {
      const body = await readJson(req);
      let authenticated = false;
      let username = null;
      if (body.role === "admin") authenticated = passwordMatches(body.passcode, store.admin);
      if (body.role === "member" && typeof body.username === "string") {
        const member = store.members.find(item => item.usernameKey === normalizeUsername(body.username));
        authenticated = passwordMatches(body.passcode, member);
        if (authenticated) username = member.username;
      }
      if (!authenticated) {
        attempt.count += 1;
        sendJson(res, 401, { error: "Those sign-in details did not match." });
        return;
      }
      loginAttempts.delete(ip);
      createSession(res, body.role, username);
    } catch (error) {
      if (!res.headersSent) sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/logout") {
    const cookieHeader = req.headers.cookie || "";
    const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${sessionCookie}=([A-Za-z0-9_-]+)`));
    if (match) sessions.delete(match[1]);
    redirect(res, "/", { "Set-Cookie": clearSessionCookie() });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/cases") {
    if (!session) return sendJson(res, 401, { error: "Sign in to continue." });
    const visibleCases = session.role === "admin"
      ? store.cases
      : store.cases.filter(item => normalizeUsername(item.username) === normalizeUsername(session.username)).map(publicCase);
    sendJson(res, 200, { cases: visibleCases });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/cases") {
    if (!requireRole(res, session, "admin")) return;
    try {
      const item = normalizeCase(await readJson(req));
      if (store.cases.some(record => record.id === item.id)) throw new Error("That case ID already exists.");
      store.cases.push(item);
      await persistStore();
      sendJson(res, 201, { case: item });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/cases/import") {
    if (!requireRole(res, session, "admin")) return;
    try {
      const body = await readJson(req);
      if (!Array.isArray(body.cases) || body.cases.length > 5000) throw new Error("CSV must contain no more than 5,000 cases.");
      const byId = new Map(store.cases.map(item => [item.id, item]));
      let added = 0;
      for (const input of body.cases) {
        const item = normalizeCase(input);
        if (!byId.has(item.id)) added += 1;
        byId.set(item.id, item);
      }
      store.cases = [...byId.values()];
      await persistStore();
      sendJson(res, 200, { added, updated: body.cases.length - added, cases: store.cases });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (req.method === "PATCH" && url.pathname.startsWith("/api/cases/")) {
    if (!requireRole(res, session, "admin")) return;
    try {
      const id = decodeURIComponent(url.pathname.slice("/api/cases/".length));
      const item = store.cases.find(record => record.id === id);
      if (!item) return sendJson(res, 404, { error: "Case not found." });
      const body = await readJson(req);
      if (body.status && statuses.includes(body.status)) item.status = body.status;
      if (body.actionTaken && actions.includes(body.actionTaken)) item.actionTaken = body.actionTaken;
      if (typeof body.memberMessage === "string" && body.memberMessage.length <= 1200) item.memberMessage = body.memberMessage.trim();
      await persistStore();
      sendJson(res, 200, { case: item });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/cases/")) {
    if (!requireRole(res, session, "admin")) return;
    try {
      const id = decodeURIComponent(url.pathname.slice("/api/cases/".length));
      const index = store.cases.findIndex(record => record.id === id);
      if (index < 0) return sendJson(res, 404, { error: "Case not found." });
      store.cases.splice(index, 1);
      await persistStore();
      sendJson(res, 200, { deleted: true, id });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (url.pathname === "/api/members" && req.method === "GET") {
    if (!requireRole(res, session, "admin")) return;
    sendJson(res, 200, { members: store.members.map(({ username }) => ({ username })) });
    return;
  }

  if (url.pathname === "/api/members" && req.method === "POST") {
    if (!requireRole(res, session, "admin")) return;
    try {
      const body = await readJson(req);
      const username = typeof body.username === "string" ? body.username.trim() : "";
      if (username.length < 2 || username.length > 80) throw new Error("Member name must be between 2 and 80 characters.");
      if (!validPasscode(body.passcode)) throw new Error("Member passcode must have at least 12 characters.");
      const usernameKey = normalizeUsername(username);
      if (store.members.some(member => member.usernameKey === usernameKey)) throw new Error("A member account with that name already exists.");
      store.members.push({ username, usernameKey, ...passwordRecord(body.passcode) });
      await persistStore();
      sendJson(res, 201, { member: { username } });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (url.pathname.startsWith("/api/members/") && req.method === "PUT") {
    if (!requireRole(res, session, "admin")) return;
    try {
      const usernameKey = normalizeUsername(decodeURIComponent(url.pathname.slice("/api/members/".length)));
      const member = store.members.find(item => item.usernameKey === usernameKey);
      if (!member) return sendJson(res, 404, { error: "Member not found." });
      const body = await readJson(req);
      if (!validPasscode(body.passcode)) throw new Error("Member passcode must have at least 12 characters.");
      Object.assign(member, passwordRecord(body.passcode));
      for (const [token, activeSession] of sessions) {
        if (activeSession.role === "member" && normalizeUsername(activeSession.username) === usernameKey) sessions.delete(token);
      }
      await persistStore();
      sendJson(res, 200, { member: { username: member.username } });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/") {
    if (session?.role === "admin") return redirect(res, "/tracker");
    if (session?.role === "member") return redirect(res, "/member");
    await servePage(res, "portal.html");
    return;
  }

  if (req.method === "GET" && url.pathname === "/tracker") {
    if (session?.role === "admin") return servePage(res, "index.html");
    return redirect(res, session?.role === "member" ? "/member" : "/");
  }

  if (req.method === "GET" && url.pathname === "/member") {
    if (session?.role === "member") return servePage(res, "member.html");
    return redirect(res, session?.role === "admin" ? "/tracker" : "/");
  }

  send(res, 404, "Not found.", "text/plain; charset=utf-8");
}

const server = createServer((req, res) => {
  startup.then(() => handleRequest(req, res)).catch(error => {
    console.error(error);
    if (!res.headersSent) sendJson(res, 500, { error: "The request could not be completed." });
  });
});

const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || "0.0.0.0";
server.listen(port, host, () => {
  console.log(`Violation tracker portal listening on http://${host}:${server.address().port}`);
});