const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const crypto = require("crypto");          // ✅ built-in Node module — no install needed

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",   // ✅ FIX #1 — browser will NOT attach this cookie on
                          //            any cross-origin request (form, fetch, img, etc.)
                          //            This alone kills most CSRF vectors.
  },
}));

// ── Fake DB ───────────────────────────────────────────────────────────────────
const users = {
  alice: {
    password: "password123",
    email: "alice@example.com",
    bio: "Hello, I'm Alice!",
    phone: "+1 555-0100",
  },
};

// ── Helper: generate a CSRF token and store it in the session ─────────────────
//
//   Called once per login (or per GET /profile).
//   The token is a 32-byte random hex string — essentially unguessable.
//   It lives server-side in req.session.csrfToken.
//   The client gets a copy embedded as a hidden field in every form.
//   On every state-changing POST we compare the two — if they don't match → 403.
//
function generateCsrfToken(req) {
  const token = crypto.randomBytes(32).toString("hex");
  req.session.csrfToken = token;
  return token;
}

// ── Helper: validate incoming requests ───────────────────────────────────────
//
//   Two checks run in order:
//
//   1. Origin / Referer check
//      The browser always sends an Origin header for cross-origin POST requests.
//      If Origin is present and does NOT match our host → reject.
//      Referer is used as a fallback when Origin is absent.
//      An attacker page on a different origin will always fail this check.
//
//   2. CSRF token check
//      Compares the token embedded in the form body (_csrf) against
//      the one stored in req.session.csrfToken.
//      Uses crypto.timingSafeEqual to prevent timing attacks.
//
function validateRequest(req, res) {
  const host = req.headers.host;                   // e.g. "localhost:3000"
  const origin  = req.headers["origin"];           // sent on cross-origin requests
  const referer = req.headers["referer"];          // fallback

  // ── FIX #2: Origin / Referer validation ──────────────────────────────────
  if (origin) {
    // Origin header format: "http://localhost:3000"
    const allowedOrigin = `${req.protocol}://${host}`;
    if (origin !== allowedOrigin) {
      res.status(403).json({
        error: "CSRF blocked",
        reason: `Origin mismatch. Got: ${origin}, Expected: ${allowedOrigin}`,
      });
      return false;
    }
  } else if (referer) {
    // Referer header format: "http://localhost:3000/profile"
    const allowedBase = `${req.protocol}://${host}/`;
    if (!referer.startsWith(allowedBase)) {
      res.status(403).json({
        error: "CSRF blocked",
        reason: `Referer mismatch. Got: ${referer}`,
      });
      return false;
    }
  }
  // Note: if neither header is present (rare, some privacy browsers strip them)
  // we fall through to the CSRF token check below as the second line of defence.

  // ── FIX #3: CSRF token validation ────────────────────────────────────────
  const tokenFromForm    = req.body._csrf;
  const tokenFromSession = req.session.csrfToken;

  if (!tokenFromForm || !tokenFromSession) {
    res.status(403).json({
      error: "CSRF blocked",
      reason: "CSRF token missing from form or session.",
    });
    return false;
  }

  // crypto.timingSafeEqual prevents timing-based token guessing attacks
  const a = Buffer.from(tokenFromForm,    "utf8");
  const b = Buffer.from(tokenFromSession, "utf8");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    res.status(403).json({
      error: "CSRF blocked",
      reason: "CSRF token does not match session token.",
    });
    return false;
  }

  return true; // ✅ all checks passed
}

// ── GET / ─────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/profile" : "/login");
});

// ── GET /login ────────────────────────────────────────────────────────────────
app.get("/login", (req, res) => res.send(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign In — MyApp (Patched)</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f0fdf4; display: flex; align-items: center;
      justify-content: center; min-height: 100vh;
    }
    .card {
      background: #fff; width: 380px; border-radius: 12px;
      box-shadow: 0 4px 24px rgba(0,0,0,.08); padding: 2.5rem 2rem;
    }
    .logo { font-size: 1.6rem; font-weight: 700; color: #16a34a;
            text-align: center; margin-bottom: 1.8rem; }
    .badge {
      display: inline-block; font-size: .72rem; font-weight: 700;
      background: #dcfce7; color: #15803d; padding: .15rem .5rem;
      border-radius: 4px; vertical-align: middle; margin-left: .4rem;
    }
    h2 { font-size: 1.2rem; color: #111; margin-bottom: 1.5rem; text-align: center; }
    label { display: block; font-size: .82rem; font-weight: 600;
            color: #444; margin-bottom: .35rem; }
    input {
      width: 100%; padding: .65rem .9rem; font-size: .95rem;
      border: 1.5px solid #ddd; border-radius: 7px;
      margin-bottom: 1.1rem; outline: none; transition: border .2s;
    }
    input:focus { border-color: #16a34a; }
    button {
      width: 100%; padding: .75rem; background: #16a34a; color: #fff;
      font-size: 1rem; font-weight: 600; border: none; border-radius: 7px;
      cursor: pointer; transition: background .2s;
    }
    button:hover { background: #15803d; }
    .footer { margin-top: 1.2rem; text-align: center; font-size: .82rem; color: #888; }
  </style>
</head><body>
  <div class="card">
    <div class="logo">⬡ MyApp <span class="badge">PATCHED</span></div>
    <h2>Welcome back</h2>
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" placeholder="Enter username" autocomplete="off" required />
      <label>Password</label>
      <input type="password" name="password" placeholder="Enter password" required />
      <button type="submit">Sign In</button>
    </form>
    <p class="footer">Demo → alice / password123</p>
  </div>
</body></html>`));

// ── POST /login ───────────────────────────────────────────────────────────────
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (user && user.password === password) {
    req.session.regenerate(() => {       // regenerate session on login (prevents fixation)
      req.session.user = username;
      generateCsrfToken(req);            // ✅ create a fresh CSRF token after login
      res.redirect("/profile");
    });
    return;
  }
  res.send(`<p style="font-family:sans-serif;color:red;padding:1rem">
    Invalid credentials. <a href="/login">Go back</a></p>`);
});

// ── GET /profile ──────────────────────────────────────────────────────────────
app.get("/profile", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  // Refresh the CSRF token on every profile page load.
  // This means each page visit generates a new token —
  // even if an attacker somehow got an old token it's already invalid.
  const csrfToken = generateCsrfToken(req);

  res.send(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>My Profile — MyApp (Patched)</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f0fdf4; min-height: 100vh;
    }
    nav {
      background: #fff; padding: .9rem 2rem;
      display: flex; align-items: center; justify-content: space-between;
      box-shadow: 0 1px 4px rgba(0,0,0,.07);
    }
    .nav-logo { font-size: 1.3rem; font-weight: 700; color: #16a34a; }
    .badge {
      font-size: .7rem; font-weight: 700; background: #dcfce7; color: #15803d;
      padding: .15rem .5rem; border-radius: 4px; margin-left: .4rem;
    }
    .nav-right { display: flex; align-items: center; gap: 1rem; }
    .nav-user { font-size: .88rem; color: #555; }
    .nav-logout {
      font-size: .82rem; color: #ef4444; text-decoration: none;
      border: 1px solid #ef4444; padding: .3rem .8rem; border-radius: 6px;
    }
    .nav-logout:hover { background: #ef4444; color: #fff; }
    .page { max-width: 640px; margin: 2.5rem auto; padding: 0 1rem; }
    h2 { font-size: 1.4rem; color: #111; margin-bottom: 1.5rem; }
    .card {
      background: #fff; border-radius: 12px;
      box-shadow: 0 2px 12px rgba(0,0,0,.07); margin-bottom: 1.5rem; overflow: hidden;
    }
    .card-header {
      padding: .9rem 1.4rem; border-bottom: 1px solid #f0f0f0;
      font-weight: 600; font-size: .95rem; color: #333;
      display: flex; align-items: center; justify-content: space-between;
    }
    .card-body { padding: 1.2rem 1.4rem; }
    .info-row {
      display: flex; justify-content: space-between; align-items: center;
      padding: .6rem 0; border-bottom: 1px solid #f5f5f5; font-size: .92rem;
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: #888; font-size: .82rem; min-width: 90px; }
    .info-value { color: #222; font-weight: 500; }
    label { display: block; font-size: .82rem; font-weight: 600;
            color: #444; margin-bottom: .35rem; margin-top: 1rem; }
    label:first-of-type { margin-top: 0; }
    input, textarea {
      width: 100%; padding: .62rem .9rem; font-size: .95rem;
      border: 1.5px solid #ddd; border-radius: 7px; outline: none; transition: border .2s;
    }
    input:focus, textarea:focus { border-color: #16a34a; }
    textarea { resize: vertical; height: 90px; font-family: inherit; }
    .btn-save {
      margin-top: 1.2rem; padding: .65rem 1.6rem; background: #16a34a;
      color: #fff; font-size: .95rem; font-weight: 600; border: none;
      border-radius: 7px; cursor: pointer; transition: background .2s;
    }
    .btn-save:hover { background: #15803d; }
    #msg { margin-top: .7rem; font-size: .88rem; }
    .ok  { color: #16a34a; }
    .err { color: #dc2626; }

    /* ── Protection badge panel ── */
    .shield-panel {
      background: #f0fdf4; border: 1.5px solid #86efac;
      border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: 1.5rem;
    }
    .shield-title { font-weight: 700; color: #15803d; margin-bottom: .5rem; font-size: .9rem; }
    .shield-row { display: flex; align-items: center; gap: .5rem;
                  font-size: .82rem; color: #166534; margin-bottom: .25rem; }
    .shield-row:last-child { margin-bottom: 0; }
  </style>
</head><body>

  <nav>
    <span class="nav-logo">⬡ MyApp <span class="badge">PATCHED</span></span>
    <div class="nav-right">
      <span class="nav-user" id="nav-username">…</span>
      <a href="/logout" class="nav-logout">Logout</a>
    </div>
  </nav>

  <div class="page">
    <h2>My Profile</h2>

    <!-- Active protections at a glance -->
    <div class="shield-panel">
      <div class="shield-title">🛡️ Active CSRF Protections</div>
      <div class="shield-row">✅ <strong>SameSite=Strict</strong> — cookie is never sent on cross-origin requests</div>
      <div class="shield-row">✅ <strong>CSRF Token</strong> — hidden field in every form, validated server-side</div>
      <div class="shield-row">✅ <strong>Origin / Referer check</strong> — request origin is validated before processing</div>
    </div>

    <!-- Current info -->
    <div class="card">
      <div class="card-header">Account Details</div>
      <div class="card-body">
        <div class="info-row">
          <span class="info-label">Username</span>
          <span class="info-value" id="disp-username">…</span>
        </div>
        <div class="info-row">
          <span class="info-label">Email</span>
          <span class="info-value" id="disp-email">…</span>
        </div>
        <div class="info-row">
          <span class="info-label">Phone</span>
          <span class="info-value" id="disp-phone">…</span>
        </div>
        <div class="info-row">
          <span class="info-label">Bio</span>
          <span class="info-value" id="disp-bio">…</span>
        </div>
      </div>
    </div>

    <!-- Edit form — CSRF token embedded as hidden field -->
    <div class="card">
      <div class="card-header">
        Edit Profile
        <span style="font-size:.75rem;color:#16a34a;font-weight:500">🔒 Token protected</span>
      </div>
      <div class="card-body">
        <form id="update-form">

          <!--
            ✅ FIX #3 — CSRF Token hidden field
            This value was generated by the server (crypto.randomBytes) and stored
            in req.session.csrfToken.  The server injects it here at page-render time.
            The attacker's page on a different origin CANNOT read this value
            (Same-Origin Policy blocks it), so any forged POST will be missing it → 403.
          -->
          <input type="hidden" name="_csrf" value="${csrfToken}" />

          <label>Email</label>
          <input type="email" id="email" name="email" required />
          <label>Phone</label>
          <input type="text" id="phone" name="phone" />
          <label>Bio</label>
          <textarea id="bio" name="bio"></textarea>
          <button type="submit" class="btn-save">Save Changes</button>
        </form>
        <div id="msg"></div>
      </div>
    </div>
  </div>

  <script>
    // Load current profile data
    fetch("/profile/data")
      .then(r => r.json())
      .then(d => {
        document.getElementById("nav-username").textContent  = d.username;
        document.getElementById("disp-username").textContent = d.username;
        document.getElementById("disp-email").textContent    = d.email;
        document.getElementById("disp-phone").textContent    = d.phone;
        document.getElementById("disp-bio").textContent      = d.bio;
        document.getElementById("email").value = d.email;
        document.getElementById("phone").value = d.phone;
        document.getElementById("bio").value   = d.bio;
      });

    // Legitimate form submit
    document.getElementById("update-form").addEventListener("submit", async e => {
      e.preventDefault();
      const form = e.target;
      const body = new URLSearchParams({
        _csrf:  form.querySelector('[name="_csrf"]').value,  // token travels with request
        email:  document.getElementById("email").value,
        phone:  document.getElementById("phone").value,
        bio:    document.getElementById("bio").value,
      });
      const res  = await fetch("/profile/update", {
        method: "POST",
        body,
        // fetch from same origin → Origin header = http://localhost:3000 → passes check
      });
      const data = await res.json();
      const msg  = document.getElementById("msg");
      if (data.success) {
        msg.className = "ok";
        msg.textContent = "✅ Profile updated successfully!";
        document.getElementById("disp-email").textContent = data.email;
        document.getElementById("disp-phone").textContent = data.phone;
        document.getElementById("disp-bio").textContent   = data.bio;
      } else {
        msg.className = "err";
        msg.textContent = "❌ " + (data.reason || "Update failed.");
      }
    });
  </script>
</body></html>`);
});

// ── GET /profile/data ─────────────────────────────────────────────────────────
app.get("/profile/data", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  const u = users[req.session.user];
  res.json({ username: req.session.user, email: u.email, bio: u.bio, phone: u.phone });
});

// ── POST /profile/update ← PATCHED ───────────────────────────────────────────
app.post("/profile/update", (req, res) => {
  if (!req.session.user) return res.status(401).send("Not logged in");

  // Run all three CSRF checks — any failure returns 403 immediately
  if (!validateRequest(req, res)) return;

  // All checks passed → safe to apply changes
  const u = users[req.session.user];
  const { email, bio, phone } = req.body;
  if (email) u.email = email;
  if (bio)   u.bio   = bio;
  if (phone) u.phone = phone;

  // Rotate the CSRF token after every successful state change
  // (per-request tokens — highest security level)
  generateCsrfToken(req);

  res.json({ success: true, email: u.email, bio: u.bio, phone: u.phone });
});

// ── GET /logout ───────────────────────────────────────────────────────────────
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(3001, () => {                     // ← port 3001 so it can run alongside server.js
  console.log("\n🛡️  Patched server → http://localhost:3001");
  console.log("   Creds          → alice / password123");
  console.log("\n   Try the CSRF attack — it will fail with 403.");
  console.log("   Reason will be printed in the server log.\n");
});
