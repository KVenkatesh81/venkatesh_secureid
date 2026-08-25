# SecureID — Part 1: Registration Journey

Implements: **Registration → Email OTP → SMS OTP → MFA setup (Authenticator/SMS/Email) → Registration Success**, per the mock screens and `Implementation_Guidelines.md`.

## Stack
- Backend: Node.js + Express (in-memory store — swap for a real DB later)
- OTP: server-generated, SHA-256 hashed at rest, expiring, attempt-limited, single-use
- MFA: real TOTP via `speakeasy` + QR code via `qrcode` (scannable in Google Authenticator/Authy), or OTP-based SMS/Email MFA
- Passwords: hashed with `bcryptjs`
- Frontend: plain HTML/CSS/JS (no framework) — you can read every line, and it's easy to hand-modify for the "understand HTML/CSS/JS without AI" requirement

## Run locally
```bash
npm install
npm start
# open http://localhost:3000/register.html
```

Watch the terminal — every simulated OTP is printed there, e.g.:
```
[SIMULATED EMAIL]
To: priya@test.com
OTP: 482913
```

## Evaluator test endpoint (as required by the assignment)
Since email/SMS delivery is simulated, use this to fetch the current OTP for a challenge instead of digging through server logs:
```
GET /api/test/otp/:challengeId
```
Returns `{ success, challengeId, channel, otp, expiresAt }`. **This endpoint exists only for grading** — remove it (or gate it behind an env flag) before any real deployment.

## API endpoints (Part 1)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/register` | Create pending account, hash password, send email OTP |
| POST | `/api/verify-email-otp` | Verify email code, auto-triggers SMS OTP |
| POST | `/api/send-email-otp` | Resend email OTP (25s cooldown) |
| POST | `/api/send-sms-otp` | Resend / start SMS OTP |
| POST | `/api/verify-sms-otp` | Verify mobile code (max 3 attempts, then locked) |
| POST | `/api/mfa/setup` | Choose MFA method — returns QR (authenticator) or sends OTP (sms/email) |
| POST | `/api/mfa/verify` | Verify TOTP or OTP, marks `mfaEnabled` + `registrationComplete` |
| GET | `/api/test/otp/:challengeId` | **Test-only**: fetch current OTP for grading |

## Security notes
- OTPs are never generated in the browser and never returned by `verify-*` responses — only the test-only endpoint above exposes one, and it's clearly marked as such.
- Each OTP is single-use: `verified`/`locked` is set immediately after a correct check, so it can't be replayed.
- Passwords are hashed with bcrypt before storage; the plaintext is never stored or logged.

## Deploying to Vercel
`vercel.json` is included and routes all requests to `server.js` (which also serves `/public` statically).

```bash
npm i -g vercel
vercel --prod
```

**Important limitation to know about:** this uses in-memory storage (`Map`s) so the whole multi-step journey (email OTP → SMS OTP → MFA) depends on state surviving between requests. Vercel serverless functions can spin up a fresh, empty instance between calls, especially after idle periods — so a long-idle demo may randomly "forget" a challenge mid-flow. It behaves fine for back-to-back testing (warm instance), but for a fully reliable graded demo, either:
1. Swap the in-memory `Map`s for a real store (e.g. Vercel KV / Redis / a small Postgres/Mongo instance) — a few hours of work, or
2. Deploy the backend to a persistent Node host (Render, Railway, Fly.io) and keep only the static frontend on Vercel.

I can wire up option 1 (e.g. Vercel KV) if you want the graded deployment to be fully robust — just say the word.

## What's next (Part 2)
Login journey, sessions + cookies, and JWT — the registration success screen already links to `/login.html`, which Part 2 will add.
