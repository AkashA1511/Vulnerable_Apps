const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");

const app = express();

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // ⚠️  SameSite is NOT set → browser sends cookie on cross-origin POSTs
    //     This is the exact reason CSRF is possible here.
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

// ── GET / ─────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/profile" : "/login");
});

// ── GET /login ────────────────────────────────────────────────────────────────
app.get("/login", (req, res) => res.send(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign In — MyApp</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fb;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #fff;
      width: 380px;
      border-radius: 12px;
      box-shadow: 0 4px 24px rgba(0,0,0,.08);
      padding: 2.5rem 2rem;
    }
    .logo {
      font-size: 1.6rem; font-weight: 700; color: #4f46e5;
      text-align: center; margin-bottom: 1.8rem; letter-spacing: -.5px;
    }
    h2 { font-size: 1.2rem; color: #111; margin-bottom: 1.5rem; text-align: center; }
    label { display: block; font-size: .82rem; font-weight: 600;
            color: #444; margin-bottom: .35rem; }
    input {
      width: 100%; padding: .65rem .9rem; font-size: .95rem;
      border: 1.5px solid #ddd; border-radius: 7px;
      margin-bottom: 1.1rem; outline: none; transition: border .2s;
    }
    input:focus { border-color: #4f46e5; }
    button {
      width: 100%; padding: .75rem; background: #4f46e5;
      color: #fff; font-size: 1rem; font-weight: 600;
      border: none; border-radius: 7px; cursor: pointer; transition: background .2s;
    }
    button:hover { background: #4338ca; }
    .footer { margin-top: 1.2rem; text-align: center; font-size: .82rem; color: #888; }
  </style>
</head><body>
  <div class="card">
    <div class="logo">⬡ MyApp</div>
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
    req.session.user = username;
    return res.redirect("/profile");
  }
  res.send(`<p style="font-family:sans-serif;color:red;padding:1rem">
    Invalid credentials. <a href="/login">Go back</a></p>`);
});

// ── GET /profile ──────────────────────────────────────────────────────────────
app.get("/profile", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  res.send(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>My Profile — MyApp</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fb; min-height: 100vh;
    }

    /* ── Navbar ── */
    nav {
      background: #fff; padding: .9rem 2rem;
      display: flex; align-items: center; justify-content: space-between;
      box-shadow: 0 1px 4px rgba(0,0,0,.07);
    }
    .nav-logo { font-size: 1.3rem; font-weight: 700; color: #4f46e5; }
    .nav-right { display: flex; align-items: center; gap: 1rem; }
    .nav-user { font-size: .88rem; color: #555; }
    .nav-logout {
      font-size: .82rem; color: #ef4444; text-decoration: none;
      border: 1px solid #ef4444; padding: .3rem .8rem; border-radius: 6px;
    }
    .nav-logout:hover { background: #ef4444; color: #fff; }

    /* ── Page layout ── */
    .page { max-width: 640px; margin: 2.5rem auto; padding: 0 1rem; }
    h2 { font-size: 1.4rem; color: #111; margin-bottom: 1.5rem; }

    /* ── Cards ── */
    .card {
      background: #fff; border-radius: 12px;
      box-shadow: 0 2px 12px rgba(0,0,0,.07);
      margin-bottom: 1.5rem; overflow: hidden;
    }
    .card-header {
      padding: .9rem 1.4rem;
      border-bottom: 1px solid #f0f0f0;
      font-weight: 600; font-size: .95rem; color: #333;
    }
    .card-body { padding: 1.2rem 1.4rem; }

    /* ── Info rows ── */
    .info-row {
      display: flex; justify-content: space-between; align-items: center;
      padding: .6rem 0; border-bottom: 1px solid #f5f5f5;
      font-size: .92rem;
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: #888; font-size: .82rem; min-width: 90px; }
    .info-value { color: #222; font-weight: 500; }

    /* ── Form ── */
    label { display: block; font-size: .82rem; font-weight: 600;
            color: #444; margin-bottom: .35rem; margin-top: 1rem; }
    label:first-of-type { margin-top: 0; }
    input, textarea {
      width: 100%; padding: .62rem .9rem; font-size: .95rem;
      border: 1.5px solid #ddd; border-radius: 7px; outline: none; transition: border .2s;
    }
    input:focus, textarea:focus { border-color: #4f46e5; }
    textarea { resize: vertical; height: 90px; font-family: inherit; }
    .btn-save {
      margin-top: 1.2rem; padding: .65rem 1.6rem;
      background: #4f46e5; color: #fff; font-size: .95rem; font-weight: 600;
      border: none; border-radius: 7px; cursor: pointer; transition: background .2s;
    }
    .btn-save:hover { background: #4338ca; }

    #msg { margin-top: .7rem; font-size: .88rem; }
    .ok  { color: #16a34a; }
    .err { color: #dc2626; }
  </style>
</head><body>

  <nav>
    <span class="nav-logo">⬡ MyApp</span>
    <div class="nav-right">
      <span class="nav-user" id="nav-username">…</span>
      <a href="/logout" class="nav-logout">Logout</a>
    </div>
  </nav>

  <div class="page">
    <h2>My Profile</h2>

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

    <!-- Update form — NO CSRF token -->
    <div class="card">
      <div class="card-header">Edit Profile</div>
      <div class="card-body">
        <form id="update-form">
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
    // Load current data
    fetch("/profile/data")
      .then(r => r.json())
      .then(d => {
        document.getElementById("nav-username").textContent = d.username;
        document.getElementById("disp-username").textContent = d.username;
        document.getElementById("disp-email").textContent    = d.email;
        document.getElementById("disp-phone").textContent    = d.phone;
        document.getElementById("disp-bio").textContent      = d.bio;
        document.getElementById("email").value = d.email;
        document.getElementById("phone").value = d.phone;
        document.getElementById("bio").value   = d.bio;
      });

    // Submit form via fetch (legitimate update)
    document.getElementById("update-form").addEventListener("submit", async e => {
      e.preventDefault();
      const body = new URLSearchParams({
        email: document.getElementById("email").value,
        phone: document.getElementById("phone").value,
        bio:   document.getElementById("bio").value,
      });
      const res  = await fetch("/profile/update", { method: "POST", body });
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
        msg.textContent = "❌ Update failed.";
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

// ── POST /profile/update  ← VULNERABLE (no CSRF token check) ─────────────────
app.post("/profile/update", (req, res) => {
  if (!req.session.user) return res.status(401).send("Not logged in");
  const u = users[req.session.user];
  const { email, bio, phone } = req.body;

  // Blindly applies whatever values arrive in the body
  // as long as a valid session cookie is present
  if (email) u.email = email;
  if (bio)   u.bio   = bio;
  if (phone) u.phone = phone;

  res.json({ success: true, email: u.email, bio: u.bio, phone: u.phone });
});

// ── GET /logout ───────────────────────────────────────────────────────────────
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(3000, () => {
  console.log("\n✅  Server  →  http://localhost:3000");
  console.log("   Creds   →  alice / password123");
  console.log("\n   Vulnerable endpoint: POST /profile/update");
  console.log("   No CSRF token — forge with Burp or a hidden form.\n");
});
