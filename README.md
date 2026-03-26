# DHC-3446 — OWASP Juice Shop (Security Patched)
### Cybersecurity Internship 2026 | Developershub

This repository is a **security-hardened fork of [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)** — the industry-standard intentionally vulnerable web application used for cybersecurity training.

Over 3 weeks we identified the most critical vulnerabilities in Juice Shop's source code and patched them one by one, moving from a **"trust everyone"** model to a **"verify everything"** model.

---

## 📁 What Was Changed (Patched Files)

| File | Original Vulnerability | Our Fix |
|---|---|---|
| `routes/login.ts` | Raw SQL string → SQL Injection | Parameterized query + bcrypt.compare + JWT |
| `routes/search.ts` | Unsanitized query → Reflected XSS | `validator.escape()` on all search input |
| `models/user.ts` | Plaintext passwords in DB | bcrypt `beforeCreate` / `beforeUpdate` hooks |
| `middleware/authenticateToken.ts` | No auth on sensitive routes | JWT checkpoint gatekeeper |
| `server.ts` | No security headers, no logging | Helmet.js CSP + Winston audit trail |

---

## 🚀 Setup

```bash
git clone https://github.com/YOUR_USERNAME/juice-shop-dhc3446-patched.git
cd juice-shop-dhc3446-patched
npm install
cp .env.example .env        # Set your JWT_SECRET here
npm start
```

Server starts at **http://localhost:3000**

---

## 🔴 Week 1 — Vulnerabilities Found in Juice Shop

### 1. SQL Injection — "The Master Key" 🔴 Critical
**File:** `routes/login.ts`

The original Juice Shop login builds a raw SQL string directly from user input:
```sql
SELECT * FROM Users WHERE email = '{req.body.email}' AND password = '{hash}'
```
**Attack:** Enter `' OR 1=1 --` as the email. The WHERE clause becomes always-true. Admin access granted with no password.

---

### 2. Reflected XSS — "The Script Injection" 🟠 High
**File:** `routes/search.ts`

The search query is passed directly into the HTML response without escaping.

**Attack:** Search for `<iframe src="javascript:alert('XSS')">`. The browser executes it — attacker can steal session cookies.

---

### 3. Missing Security Headers 🟡 Medium
**File:** `server.ts`

No Content Security Policy (CSP), no `X-Frame-Options`. The app was "naked" against:
- Clickjacking (invisible overlay buttons)
- MIME-sniffing attacks
- Unauthorized script injection

---

### 4. Plaintext Passwords 🔴 Critical
**File:** `models/user.ts`

Passwords stored in plain English. A single database breach exposes every user's real password.

---

## 🟢 Week 2 — Fixes Implemented

### Fix 1: SQL Injection → `routes/login.ts`
```typescript
// BEFORE (vulnerable raw query):
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)

// AFTER (parameterized — injection impossible):
const user = await UserModel.findOne({ where: { email: sanitizedEmail } })
// ' OR 1=1 -- is now just a string that matches no email address
```

### Fix 2: XSS → `routes/search.ts`
```typescript
// validator.escape() converts all dangerous characters to HTML entities
const safeQuery = validator.escape(rawQuery.trim())
// <iframe src="javascript:alert('XSS')"> → &lt;iframe...&gt; — prints as text, never runs
```

### Fix 3: Password Hashing → `models/user.ts`
```typescript
// bcrypt hook — runs automatically before every new user is saved
beforeCreate: async (user) => {
  user.password = await bcrypt.hash(user.password, 12)
}
// Database now stores: $2b$12$3x8Kq... — useless gibberish to any attacker
```

### Fix 4: JWT "VIP Pass" → `routes/login.ts`
```typescript
const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' })
// Signed token, expires in 1 hour, checked before every sensitive action
```

### Fix 5: JWT Checkpoint → `middleware/authenticateToken.ts`
Locks down:
- ✅ `POST /api/Products` — creating products requires token
- ✅ `GET /api/Users` — admin list requires token
- ✅ `GET /api/Feedbacks` — feedback logs require token
- ✅ `DELETE /api/Addresss/:id` — only the owner can delete their own address

### Fix 6: Helmet.js → `server.ts`
```typescript
app.use(helmet({ contentSecurityPolicy: { directives: { frameSrc: ["'none'"] } } }))
// CSP + X-Frame-Options: DENY + noSniff + HSTS — all in one line
```

---

## 🔵 Week 3 — Penetration Testing Results

| Attack | Payload | Result |
|---|---|---|
| SQL Injection | `' OR 1=1 --` in login | ✅ **Blocked** — treated as harmless string, no match |
| Reflected XSS | `<iframe src="javascript:alert('XSS')">` in search | ✅ **Blocked** — rendered as plain text |
| JWT tampering | Modified token payload | ✅ **Rejected** — 403 Forbidden |
| No-token admin access | Request without Authorization header | ✅ **Blocked** — 401 Unauthorized |

### Winston "Black Box" — `logs/security.log`
```
[2026-03-02 10:00:00] INFO: DHC-3446 patched Juice Shop running on port 3000
[2026-03-02 10:01:10] INFO: POST /rest/user/login — IP: 127.0.0.1
[2026-03-02 10:01:11] WARN: Failed login — unknown email: attacker@evil.com
[2026-03-02 10:02:05] INFO: Successful login: alice@juice-sh.op
[2026-03-02 10:03:30] WARN: Unauthorized access attempt — no token — GET /api/Users
```

---

## 📋 Final Security Checklist

| Best Practice | Status | Detail |
|---|---|---|
| Input Validation | ✅ Passed | `validator` library on all user inputs — XSS blocked |
| Secure Passwords | ✅ Passed | `bcrypt` hooks in `models/user.ts` — 12 salt rounds |
| Token-Based Auth | ✅ Passed | JWT signed tokens, 1-hour expiry, checked on every protected route |
| Layered Defense | ✅ Passed | `helmet` enforces CSP + blocks clickjacking in `server.ts` |
| Audit Logging | ✅ Passed | `winston` writing to `logs/security.log` |

---

## 📚 References
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — original vulnerable application
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP](https://www.zaproxy.org/) — used for automated scanning in Week 1
