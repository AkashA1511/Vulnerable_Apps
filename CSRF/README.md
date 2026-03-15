# CSRF Vulnerability Demo

A minimal educational demo showing how a CSRF attack works on a profile update form.

---

## Setup

```bash
npm install
node server.js
```

Server starts at → http://localhost:3000

---

## How to Run the Attack


---

## Why It Works

```
Victim is logged in
       │
       ▼
Browser holds session cookie for localhost:3000
       │
Victim visits attacker page → hidden form fires POST /profile/update
       │
Browser automatically attaches the session cookie to the request
       │
Server sees valid session → trusts the request → updates profile
       │
       ▼
Account data changed without victim's knowledge (for attacker)
```

The server never checks **where** the request came from.

---

## The Fix — CSRF Token

Add a random token to every form and validate it server-side:

### Server side
```js
const csrf = require('csurf');
app.use(csrf());

app.get('/profile', (req, res) => {
  res.render('profile', { csrfToken: req.csrfToken() });
});

// POST /profile/update now automatically validated by csurf middleware
```

### Template side
```html
<form method="POST" action="/profile/update">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
  ...
</form>
```

The attacker page **cannot** read this token (same-origin policy), so its forged
request will be rejected with `403 Forbidden`.

Other mitigations:
- `SameSite=Strict` or `SameSite=Lax` on session cookies
- Check `Origin` / `Referer` headers
- Double-submit cookie pattern
