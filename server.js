const { createHash, randomBytes, timingSafeEqual } = require("node:crypto");
const { existsSync, readFileSync } = require("node:fs");
const { createServer } = require("node:http");
const { join } = require("node:path");

const root = __dirname;
const sessionCookie = "ace_portal";
const sessionLifetime = 12 * 60 * 60 * 1000;
const attemptWindow = 15 * 60 * 1000;
const maxAttempts = 5;
const sessions = new Map();
const loginAttempts = new Map();

function loadLocalEnvironment() {
  const filePath = join(root, ".env");
  if (!existsSync(filePath)) return;
  for (const line of readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    const value = match[2].replace(/^(["'])(.*)\1$/, "$2");
    process.env[match[1]] = value;
  }
}

loadLocalEnvironment();

const portalPasscode = process.env.PORTAL_PASSCODE;
if (!portalPasscode || portalPasscode.length < 12) {
  console.error("Set PORTAL_PASSCODE to a passphrase at least 12 characters long in .env or the environment.");
  process.exit(1);
}

const passcodeDigest = createHash("sha256").update(portalPasscode).digest();
const cookieSecure = process.env.NODE_ENV === "production";

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

function redirect(res, location) {
  res.writeHead(303, { Location: location, "Cache-Control": "no-store" });
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
  const secure = cookieSecure ? "; Secure" : "";
  return `${sessionCookie}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionLifetime / 1000}${secure}`;
}

function clearSessionCookie() {
  const secure = cookieSecure ? "; Secure" : "";
  return `${sessionCookie}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secure}`;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > 4096) {
        reject(new Error("Request is too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(JSON.parse(body || "{}")); }
      catch { reject(new Error("Invalid request.")); }
    });
    req.on("error", reject);
  });
}

function isPasscodeMatch(candidate) {
  if (typeof candidate !== "string") return false;
  const candidateDigest = createHash("sha256").update(candidate).digest();
  return timingSafeEqual(passcodeDigest, candidateDigest);
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

async function servePage(res, fileName) {
  const { readFile } = require("node:fs/promises");
  try {
    const content = await readFile(join(root, fileName));
    send(res, 200, content, "text/html; charset=utf-8");
  } catch {
    send(res, 500, "Page unavailable.", "text/plain; charset=utf-8");
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const session = readSession(req);

  if (req.method === "GET" && url.pathname === "/api/session") {
    sendJson(res, 200, { authenticated: Boolean(session) });
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
    if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) {
      sendJson(res, 403, { error: "Request origin not allowed." });
      return;
    }
    try {
      const body = await readJson(req);
      if (!isPasscodeMatch(body.passcode)) {
        attempt.count += 1;
        sendJson(res, 401, { error: "That passcode did not match." });
        return;
      }
      loginAttempts.delete(ip);
      const token = randomBytes(32).toString("base64url");
      for (const [existingToken, existingSession] of sessions) {
        if (existingSession.expiresAt <= Date.now()) sessions.delete(existingToken);
      }
      sessions.set(token, { expiresAt: Date.now() + sessionLifetime });
      sendJson(res, 200, { authenticated: true }, { "Set-Cookie": setSessionCookie(token) });
    } catch (error) {
      if (!res.destroyed && !res.headersSent) sendJson(res, 400, { error: error.message });
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

  if (req.method === "GET" && url.pathname === "/") {
    if (session) redirect(res, "/tracker");
    else await servePage(res, "portal.html");
    return;
  }

  if (req.method === "GET" && url.pathname === "/tracker") {
    if (!session) {
      redirect(res, "/");
      return;
    }
    await servePage(res, "index.html");
    return;
  }

  send(res, 404, "Not found.", "text/plain; charset=utf-8");
});

const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || "0.0.0.0";
server.listen(port, host, () => {
  console.log(`Violation tracker portal listening on http://${host}:${server.address().port}`);
});