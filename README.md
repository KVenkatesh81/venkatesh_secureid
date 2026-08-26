# SecureID — Registration + Login Journeys

**Part 1 — Registration:** Registration → Email OTP → SMS OTP → MFA setup (Authenticator/SMS/Email) → Registration Success

**Part 2 — Login:** Login (credentials) → Choose MFA method → OTP/TOTP verification → Session cookie created → also a separate JWT auth flow

Built per the mock screens and `Implementation_Guidelines.md`.

## Stack
- Backend: Node.js + Express (in-memory store — swap for a real DB later)
- OTP: server-generated, SHA-256 hashed at rest, expiring, attempt-limited, single-use
- MFA: real TOTP via `speakeasy` + QR code via `qrcode` (scannable in Google Authenticator/Authy), or OTP-based SMS/Email MFA
- Passwords: hashed with `bcryptjs`
- Sessions: HttpOnly + Secure + SameSite cookie, server-side session store
- JWT: `jsonwebtoken`, short-lived (15 min), verified server-side on every protected call, **never stored in localStorage**
- Frontend: plain HTML/CSS/JS (no framework) — every line is readable/editable by hand

## Run locally
```bash
npm install
npm start
# Registration: http://localhost:3000/register.html
# Login:        http://localhost:3000/login.html
# Dashboard:    http://localhost:3000/dashboard.html (redirects to login if not authenticated)
```

Watch the terminal — every simulated OTP is printed there, e.g.:
```
[SIMULATED EMAIL]
To: priya@test.com
OTP: 482913
```

## Evaluator test endpoint
Since email/SMS delivery is simulated:
```
GET /api/test/otp/:challengeId
```
Returns `{ success, challengeId, channel, otp, expiresAt }`. **Test-only** — remove or gate behind an env flag before any real deployment.

## API endpoints

### Part 1 — Registration
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/register` | Create pending account, hash password, send email OTP |
| POST | `/api/verify-email-otp` | Verify email code, auto-triggers SMS OTP |
| POST | `/api/send-email-otp` | Resend email OTP (25s cooldown) |
| POST | `/api/send-sms-otp` | Resend / start SMS OTP |
| POST | `/api/verify-sms-otp` | Verify mobile code (max 3 attempts, then locked) |
| POST | `/api/mfa/setup` | Choose MFA method — returns QR (authenticator) or sends OTP (sms/email) |
| POST | `/api/mfa/verify` | Verify TOTP or OTP, marks `mfaEnabled` + `registrationComplete` |

### Part 2 — Login, Sessions, JWT
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/login` | Validate credentials; reports lockout status and whether MFA is required |
| POST | `/api/login/select-method` | User picks email / sms / authenticator; sends OTP if applicable |
| POST | `/api/verify-login-otp` | Verify the MFA code, create the session (sets HttpOnly cookie) |
| GET | `/api/me` | Current authenticated user (session-cookie based) |
| POST | `/api/logout` | Invalidate the server-side session, clear the cookie |
| POST | `/api/token` | Re-validate credentials, issue a short-lived JWT (independent of the session flow) |
| GET | `/api/protected` | Requires `Authorization: Bearer <JWT>` — demonstrates server-side JWT verification |

### Test-only
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/test/otp/:challengeId` | Fetch the current OTP for grading |

## Security notes
- OTPs are never generated in the browser and never returned by `verify-*` responses — only the test-only endpoint exposes one.
- Each OTP is single-use: `verified`/`locked` is set immediately after a correct check, so it can't be replayed.
- Passwords are hashed with bcrypt; plaintext is never stored or logged.
- Login uses a generic "Invalid email or password" error for both unknown emails and wrong passwords, so login can't be used to enumerate registered accounts.
- 5 failed login attempts locks the account for 15 minutes.
- Session cookie is `HttpOnly`, `Secure`, `SameSite=Lax` — inaccessible to JavaScript, not sent cross-site.
- JWTs expire in 15 minutes and are verified server-side on every call to `/api/protected`; the dashboard keeps the token in a JS variable only (never `localStorage`/`sessionStorage`), so it's gone on page refresh — by design, per the assignment's requirement.

## Deploying to Vercel
`vercel.json` routes all requests to `server.js` (which also serves `/public` statically).

**Important:** set a real `JWT_SECRET` environment variable in Vercel (Project → Settings → Environment Variables) before relying on the JWT flow for anything beyond a demo — the code falls back to a dev-only secret otherwise.

**Known limitation:** this uses in-memory storage (`Map`s) for users, OTP challenges, and sessions, so the whole journey depends on server state surviving between requests. Vercel serverless functions can spin up a fresh, empty instance after idle periods — fine for back-to-back testing, but a long-idle demo may "forget" a session or challenge mid-flow. For a fully robust graded deployment, swap the `Map`s for a real store (Vercel KV / Redis / a small DB) — happy to wire that up if useful.

## Fixing the "just registered, but login says invalid credentials" issue on Vercel

This happens because Vercel serverless functions don't share memory between requests — a plain in-memory store can be empty again by the very next request. The fix: connect a persistent Redis store to your project (a few clicks, no code changes needed).

1. In your Vercel project dashboard, go to the **Storage** tab (or **Marketplace** → search "Redis").
2. Install **Upstash for Redis** and create a database (the free tier is enough for this).
3. Connect it to this project — Vercel will automatically inject `KV_REST_API_URL` and `KV_REST_API_TOKEN` as environment variables.
4. Redeploy (Vercel usually does this automatically after connecting storage; if not, push any small commit or hit "Redeploy" in the dashboard).
5. Check `https://your-app.vercel.app/api/health` — it should now report `"storage":"vercel-kv"` instead of `"storage":"in-memory"`.

Once that's connected, registered accounts will persist properly and login will work as expected — no matter which serverless instance handles the request.

Running locally with `npm start` never needs this — it automatically uses in-memory storage when no Redis env vars are present.
