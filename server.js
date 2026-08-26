/**
 * SecureID — Registration + Login Journeys
 * ------------------------------------------------------------
 * Part 1 (Registration):
 *   Register (details) -> Email OTP -> SMS OTP -> Set up MFA
 *   -> Authenticator QR setup -> MFA verification -> Registration Success
 *
 * Part 2 (Login):
 *   Login (credentials) -> Choose MFA method -> OTP/TOTP verification
 *   -> Session cookie created (session auth) + separate JWT auth flow
 *
 * Everything security-sensitive happens on the server:
 *   - password hashing (bcrypt)
 *   - OTP generation, hashing, expiry, attempt limiting
 *   - TOTP secret generation + verification (speakeasy)
 *   - session cookies are HttpOnly + Secure + SameSite, never in localStorage
 *   - JWTs are short-lived and verified server-side on every protected call
 *
 * Storage is in-memory (Maps) for assignment/demo purposes.
 * Swap `db.js`-style module for a real DB in production.
 */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------------------------------------------------------
// In-memory "database"
// ---------------------------------------------------------------------------
const users = new Map(); // userId -> user object
const usersByEmail = new Map(); // email(lowercase) -> userId
const challenges = new Map(); // challengeId -> challenge object
const sessions = new Map(); // sessionId -> session object

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const OTP_LENGTH = 6;
const OTP_EXPIRY_SECONDS = 165; // 02:45 shown in the mock screens
const OTP_RESEND_COOLDOWN_SECONDS = 25; // 00:25 resend cooldown
const OTP_MAX_ATTEMPTS = 3; // "You have 2 attempts left" after 1st wrong try

const MAX_FAILED_LOGINS = 5;
const LOGIN_LOCKOUT_MINUTES = 15;

const SESSION_COOKIE_NAME = "sid";
const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours (normal login)
const SESSION_TTL_REMEMBER_MS = 30 * 24 * 60 * 60 * 1000; // 30 days ("Remember me")

// In production, set JWT_SECRET as a real env var (Vercel → Project → Settings → Environment Variables).
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-secret-change-me";
const JWT_EXPIRES_IN = "15m";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}

function generateOtp() {
  // 6-digit numeric OTP, zero-padded
  return crypto.randomInt(0, 10 ** OTP_LENGTH).toString().padStart(OTP_LENGTH, "0");
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}

function createChallenge({ userId, channel, destination }) {
  const otp = generateOtp();
  const challengeId = newId("chal");
  const now = Date.now();

  const challenge = {
    challengeId,
    userId,
    channel, // 'email' | 'sms'
    destination, // masked-safe display value (email or phone)
    otpHash: hashOtp(otp),
    createdAt: now,
    expiresAt: now + OTP_EXPIRY_SECONDS * 1000,
    resendAvailableAt: now + OTP_RESEND_COOLDOWN_SECONDS * 1000,
    attempts: 0,
    maxAttempts: OTP_MAX_ATTEMPTS,
    verified: false,
    locked: false,
  };

  challenges.set(challengeId, challenge);

  // Simulated delivery — this is where a real email/SMS provider would be called.
  console.log(
    `\n[SIMULATED ${channel.toUpperCase()}]\nTo: ${destination}\nOTP: ${otp}\n(expires in ${OTP_EXPIRY_SECONDS}s, challengeId=${challengeId})\n`
  );

  return { challenge, otp };
}

function regenerateOtp(challenge) {
  const otp = generateOtp();
  const now = Date.now();
  challenge.otpHash = hashOtp(otp);
  challenge.createdAt = now;
  challenge.expiresAt = now + OTP_EXPIRY_SECONDS * 1000;
  challenge.resendAvailableAt = now + OTP_RESEND_COOLDOWN_SECONDS * 1000;
  challenge.attempts = 0;
  challenge.verified = false;
  challenge.locked = false;

  console.log(
    `\n[SIMULATED ${challenge.channel.toUpperCase()} - RESEND]\nTo: ${challenge.destination}\nOTP: ${otp}\n(expires in ${OTP_EXPIRY_SECONDS}s, challengeId=${challenge.challengeId})\n`
  );

  return otp;
}

function publicChallengeView(challenge) {
  return {
    challengeId: challenge.challengeId,
    channel: challenge.channel,
    destination: challenge.destination,
    expiresAt: challenge.expiresAt,
    resendAvailableAt: challenge.resendAvailableAt,
    attemptsRemaining: Math.max(challenge.maxAttempts - challenge.attempts, 0),
    maxAttempts: challenge.maxAttempts,
    locked: challenge.locked,
  };
}

function publicUserView(user) {
  return {
    userId: user.id,
    fullName: user.fullName,
    email: user.email,
    mobile: user.mobile,
    emailVerified: user.emailVerified,
    mobileVerified: user.mobileVerified,
    mfaEnabled: user.mfaEnabled,
    mfaMethod: user.mfaMethod,
    registrationComplete: user.registrationComplete,
  };
}

const PASSWORD_RULE = {
  minLength: 8,
  hasUpper: /[A-Z]/,
  hasNumber: /[0-9]/,
  hasSpecial: /[^A-Za-z0-9]/,
};

function validatePassword(password) {
  const errors = [];
  if (!password || password.length < PASSWORD_RULE.minLength) errors.push("At least 8 characters");
  if (!PASSWORD_RULE.hasUpper.test(password || "")) errors.push("1 uppercase letter");
  if (!PASSWORD_RULE.hasNumber.test(password || "")) errors.push("1 number");
  if (!PASSWORD_RULE.hasSpecial.test(password || "")) errors.push("1 special character");
  return errors;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || "");
}

function isValidMobile(mobile) {
  return /^[0-9]{7,15}$/.test((mobile || "").replace(/\D/g, ""));
}

// ---------------------------------------------------------------------------
// POST /api/register — Step 1: create the (pending) account, send email OTP
// ---------------------------------------------------------------------------
app.post("/api/register", (req, res) => {
  const { fullName, email, mobile, password, agreeToTerms } = req.body || {};

  const errors = {};
  if (!fullName || !fullName.trim()) errors.fullName = "Full name is required";
  if (!isValidEmail(email)) errors.email = "Enter a valid email address";
  if (!isValidMobile(mobile)) errors.mobile = "Enter a valid mobile number";
  const pwErrors = validatePassword(password);
  if (pwErrors.length) errors.password = `Password must include: ${pwErrors.join(", ")}`;
  if (!agreeToTerms) errors.agreeToTerms = "You must agree to the Terms & Conditions";

  if (Object.keys(errors).length) {
    return res.status(400).json({ success: false, errors });
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (usersByEmail.has(normalizedEmail)) {
    return res.status(409).json({
      success: false,
      errors: { email: "An account with this email already exists" },
    });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const userId = newId("user");

  const user = {
    id: userId,
    fullName: fullName.trim(),
    email: normalizedEmail,
    mobile: mobile.trim(),
    passwordHash,
    emailVerified: false,
    mobileVerified: false,
    mfaEnabled: false,
    mfaMethod: null,
    mfaSecret: null,
    registrationComplete: false,
    createdAt: Date.now(),
  };

  users.set(userId, user);
  usersByEmail.set(normalizedEmail, userId);

  const { challenge } = createChallenge({
    userId,
    channel: "email",
    destination: user.email,
  });

  return res.status(201).json({
    success: true,
    userId,
    challenge: publicChallengeView(challenge),
  });
});

// ---------------------------------------------------------------------------
// Generic OTP verify handler (shared by email + sms)
// ---------------------------------------------------------------------------
function verifyOtpChallenge(req, res, expectedChannel, onSuccess) {
  const { challengeId, otp } = req.body || {};
  const challenge = challenges.get(challengeId);

  if (!challenge || challenge.channel !== expectedChannel) {
    return res.status(404).json({ success: false, error: "Invalid or expired verification request." });
  }

  if (challenge.locked) {
    return res.status(429).json({
      success: false,
      error: "Maximum attempts reached. Please request a new code.",
      challenge: publicChallengeView(challenge),
    });
  }

  if (Date.now() > challenge.expiresAt) {
    return res.status(410).json({
      success: false,
      error: "This code has expired.",
      expired: true,
      challenge: publicChallengeView(challenge),
    });
  }

  if (!otp || hashOtp(otp) !== challenge.otpHash) {
    challenge.attempts += 1;
    if (challenge.attempts >= challenge.maxAttempts) {
      challenge.locked = true;
    }
    return res.status(400).json({
      success: false,
      error: challenge.locked
        ? "Maximum attempts reached. Please request a new code."
        : "Incorrect code. Please try again.",
      challenge: publicChallengeView(challenge),
    });
  }

  // Correct + single-use: invalidate immediately
  challenge.verified = true;
  challenge.locked = true; // prevents replay of the same code

  const user = users.get(challenge.userId);
  return onSuccess(user, challenge, res);
}

// ---------------------------------------------------------------------------
// POST /api/verify-email-otp — Step 2
// ---------------------------------------------------------------------------
app.post("/api/verify-email-otp", (req, res) => {
  verifyOtpChallenge(req, res, "email", (user, challenge, res) => {
    user.emailVerified = true;

    // Automatically kick off SMS OTP, per the flow: Email OTP -> SMS OTP
    const { challenge: smsChallenge } = createChallenge({
      userId: user.id,
      channel: "sms",
      destination: user.mobile,
    });

    return res.json({
      success: true,
      user: publicUserView(user),
      nextStep: "sms-otp",
      challenge: publicChallengeView(smsChallenge),
    });
  });
});

// ---------------------------------------------------------------------------
// POST /api/send-email-otp — (re)send / start an email OTP challenge
// ---------------------------------------------------------------------------
app.post("/api/send-email-otp", (req, res) => {
  const { challengeId } = req.body || {};
  const challenge = challenges.get(challengeId);

  if (!challenge || challenge.channel !== "email") {
    return res.status(404).json({ success: false, error: "Verification request not found." });
  }
  if (Date.now() < challenge.resendAvailableAt) {
    return res.status(429).json({
      success: false,
      error: "Please wait before requesting a new code.",
      challenge: publicChallengeView(challenge),
    });
  }

  regenerateOtp(challenge);
  return res.json({ success: true, challenge: publicChallengeView(challenge) });
});

// ---------------------------------------------------------------------------
// POST /api/send-sms-otp — (re)send / start an SMS OTP challenge
// ---------------------------------------------------------------------------
app.post("/api/send-sms-otp", (req, res) => {
  const { challengeId, userId } = req.body || {};

  // Allow resend via existing challengeId, or a fresh start via userId
  let challenge = challengeId ? challenges.get(challengeId) : null;

  if (challenge && challenge.channel === "sms") {
    if (Date.now() < challenge.resendAvailableAt) {
      return res.status(429).json({
        success: false,
        error: "Please wait before requesting a new code.",
        challenge: publicChallengeView(challenge),
      });
    }
    regenerateOtp(challenge);
    return res.json({ success: true, challenge: publicChallengeView(challenge) });
  }

  const user = users.get(userId);
  if (!user) {
    return res.status(404).json({ success: false, error: "User not found." });
  }
  if (!user.emailVerified) {
    return res.status(400).json({ success: false, error: "Verify your email before requesting SMS OTP." });
  }

  const { challenge: newChallenge } = createChallenge({
    userId: user.id,
    channel: "sms",
    destination: user.mobile,
  });

  return res.status(201).json({ success: true, challenge: publicChallengeView(newChallenge) });
});

// ---------------------------------------------------------------------------
// POST /api/verify-sms-otp — Step 3
// ---------------------------------------------------------------------------
app.post("/api/verify-sms-otp", (req, res) => {
  verifyOtpChallenge(req, res, "sms", (user, challenge, res) => {
    user.mobileVerified = true;
    return res.json({
      success: true,
      user: publicUserView(user),
      nextStep: "mfa-setup",
    });
  });
});

// ---------------------------------------------------------------------------
// POST /api/mfa/setup — Step 4/5: choose MFA method
//   method: 'authenticator' | 'sms' | 'email'
// ---------------------------------------------------------------------------
app.post("/api/mfa/setup", async (req, res) => {
  const { userId, method } = req.body || {};
  const user = users.get(userId);

  if (!user) return res.status(404).json({ success: false, error: "User not found." });
  if (!user.emailVerified || !user.mobileVerified) {
    return res.status(400).json({ success: false, error: "Complete email and mobile verification first." });
  }
  if (!["authenticator", "sms", "email"].includes(method)) {
    return res.status(400).json({ success: false, error: "Invalid MFA method." });
  }

  user.mfaMethod = method;

  if (method === "authenticator") {
    const secret = speakeasy.generateSecret({
      name: `SecureID (${user.email})`,
      length: 20,
    });
    user.mfaSecret = secret.base32;

    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return res.json({
      success: true,
      method,
      qrCodeDataUrl: qrDataUrl,
      manualSetupKey: secret.base32,
      nextStep: "mfa-verify",
    });
  }

  // SMS or Email MFA: just send a fresh OTP over that channel
  const destination = method === "sms" ? user.mobile : user.email;
  const { challenge } = createChallenge({ userId: user.id, channel: method === "sms" ? "sms" : "email", destination });

  return res.json({
    success: true,
    method,
    challenge: publicChallengeView(challenge),
    nextStep: "mfa-verify",
  });
});

// ---------------------------------------------------------------------------
// POST /api/mfa/verify — Step 6: verify TOTP code or OTP, complete registration
// ---------------------------------------------------------------------------
app.post("/api/mfa/verify", (req, res) => {
  const { userId, code, challengeId } = req.body || {};
  const user = users.get(userId);

  if (!user) return res.status(404).json({ success: false, error: "User not found." });

  const finalize = () => {
    user.mfaEnabled = true;
    user.registrationComplete = true;
    return res.json({ success: true, user: publicUserView(user), nextStep: "success" });
  };

  if (user.mfaMethod === "authenticator") {
    if (!user.mfaSecret) {
      return res.status(400).json({ success: false, error: "Authenticator has not been set up yet." });
    }
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token: (code || "").trim(),
      window: 1, // allow ~30s clock drift
    });

    if (!verified) {
      return res.status(400).json({ success: false, error: "Invalid code. Please try again." });
    }
    return finalize();
  }

  // sms / email MFA path reuses the OTP challenge machinery
  return verifyOtpChallenge(
    { body: { challengeId, otp: code } },
    res,
    user.mfaMethod,
    () => finalize()
  );
});

// =============================================================================
// PART 2 — LOGIN JOURNEY
// =============================================================================

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------
function createSession(userId, rememberMe) {
  const sessionId = newId("sess");
  const now = Date.now();
  const ttl = rememberMe ? SESSION_TTL_REMEMBER_MS : SESSION_TTL_MS;
  sessions.set(sessionId, { sessionId, userId, createdAt: now, expiresAt: now + ttl });
  return { sessionId, ttl };
}

function setSessionCookie(res, sessionId, ttl) {
  res.cookie(SESSION_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: true, // requires HTTPS (Vercel serves HTTPS; on plain http://localhost some browsers still accept this in dev)
    sameSite: "lax",
    maxAge: ttl,
    path: "/",
  });
}

function getSessionUser(req) {
  const sessionId = req.cookies && req.cookies[SESSION_COOKIE_NAME];
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return users.get(session.userId) || null;
}

function requireSession(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Not authenticated." });
  req.sessionUser = user;
  next();
}

function requireJwt(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const [scheme, token] = authHeader.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ success: false, error: "Missing or malformed Authorization header." });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.get(payload.sub);
    if (!user) return res.status(401).json({ success: false, error: "Invalid token." });
    req.jwtUser = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Invalid or expired token." });
  }
}

// ---------------------------------------------------------------------------
// POST /api/login — Step 1: validate credentials, report MFA requirement
// ---------------------------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};

  if (!isValidEmail(email) || !password) {
    return res.status(400).json({ success: false, error: "Enter a valid email/username and password." });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const userId = usersByEmail.get(normalizedEmail);
  const user = userId ? users.get(userId) : null;

  // Deliberately use the same generic error for "no such user" and "wrong
  // password" so login can't be used to enumerate registered emails.
  const genericError = "Invalid email or password. Please try again.";

  if (!user) {
    return res.status(401).json({ success: false, error: genericError });
  }

  if (user.lockUntil && Date.now() < user.lockUntil) {
    const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
    return res.status(423).json({
      success: false,
      error: `Too many failed attempts. Account temporarily locked. Try again in ${minutesLeft} minute(s).`,
      lockedUntil: user.lockUntil,
    });
  }

  const passwordOk = bcrypt.compareSync(password, user.passwordHash);
  if (!passwordOk) {
    user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
    if (user.failedLoginAttempts >= MAX_FAILED_LOGINS) {
      user.lockUntil = Date.now() + LOGIN_LOCKOUT_MINUTES * 60 * 1000;
      user.failedLoginAttempts = 0;
      return res.status(423).json({
        success: false,
        error: `Too many failed attempts. Account locked for ${LOGIN_LOCKOUT_MINUTES} minutes.`,
        lockedUntil: user.lockUntil,
      });
    }
    return res.status(401).json({ success: false, error: genericError });
  }

  // Credentials valid — reset the failed-attempt counter.
  user.failedLoginAttempts = 0;
  user.lockUntil = null;

  if (!user.mfaEnabled) {
    // Shouldn't normally happen since registration always enables MFA, but
    // handle it defensively rather than assuming.
    const { sessionId, ttl } = createSession(user.id, false);
    setSessionCookie(res, sessionId, ttl);
    return res.json({ success: true, mfaRequired: false, user: publicUserView(user) });
  }

  const availableMethods = ["email", "sms"];
  if (user.mfaSecret) availableMethods.push("authenticator");

  return res.json({
    success: true,
    mfaRequired: true,
    userId: user.id,
    availableMethods,
    defaultMethod: user.mfaMethod && availableMethods.includes(user.mfaMethod) ? user.mfaMethod : availableMethods[0],
  });
});

// ---------------------------------------------------------------------------
// POST /api/login/select-method — Step 2: user picks how to receive the code
// ---------------------------------------------------------------------------
app.post("/api/login/select-method", async (req, res) => {
  const { userId, method } = req.body || {};
  const user = users.get(userId);

  if (!user) return res.status(404).json({ success: false, error: "User not found." });
  if (!["email", "sms", "authenticator"].includes(method)) {
    return res.status(400).json({ success: false, error: "Invalid method." });
  }
  if (method === "authenticator" && !user.mfaSecret) {
    return res.status(400).json({ success: false, error: "Authenticator app is not set up for this account." });
  }

  if (method === "authenticator") {
    // No OTP to send — the frontend just shows a code-entry screen.
    return res.json({ mfaRequired: true, method: "authenticator", userId: user.id });
  }

  const destination = method === "sms" ? user.mobile : user.email;
  const { challenge } = createChallenge({ userId: user.id, channel: method, destination });

  return res.json({
    mfaRequired: true,
    method,
    userId: user.id,
    challenge: publicChallengeView(challenge),
  });
});

// ---------------------------------------------------------------------------
// POST /api/verify-login-otp — Step 3: verify code, create the session
// ---------------------------------------------------------------------------
app.post("/api/verify-login-otp", (req, res) => {
  const { userId, method, code, challengeId, rememberMe } = req.body || {};
  const user = users.get(userId);
  if (!user) return res.status(404).json({ success: false, error: "User not found." });

  const finalizeLogin = () => {
    const { sessionId, ttl } = createSession(user.id, !!rememberMe);
    setSessionCookie(res, sessionId, ttl);
    return res.json({ success: true, user: publicUserView(user) });
  };

  if (method === "authenticator") {
    if (!user.mfaSecret) {
      return res.status(400).json({ success: false, error: "Authenticator app is not set up for this account." });
    }
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token: (code || "").trim(),
      window: 1,
    });
    if (!verified) {
      return res.status(400).json({ success: false, error: "Invalid code. Please try again." });
    }
    return finalizeLogin();
  }

  return verifyOtpChallenge({ body: { challengeId, otp: code } }, res, method, () => finalizeLogin());
});

// ---------------------------------------------------------------------------
// GET /api/me — current authenticated user (session-cookie based)
// ---------------------------------------------------------------------------
app.get("/api/me", requireSession, (req, res) => {
  res.json({ success: true, user: publicUserView(req.sessionUser) });
});

// ---------------------------------------------------------------------------
// POST /api/logout — invalidate the server-side session
// ---------------------------------------------------------------------------
app.post("/api/logout", (req, res) => {
  const sessionId = req.cookies && req.cookies[SESSION_COOKIE_NAME];
  if (sessionId) sessions.delete(sessionId);
  res.clearCookie(SESSION_COOKIE_NAME, { path: "/" });
  res.json({ success: true });
});

// ---------------------------------------------------------------------------
// POST /api/token — issue a short-lived JWT (separate, stateless auth flow)
// ---------------------------------------------------------------------------
app.post("/api/token", (req, res) => {
  const { email, password } = req.body || {};
  if (!isValidEmail(email) || !password) {
    return res.status(400).json({ success: false, error: "Enter a valid email and password." });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const userId = usersByEmail.get(normalizedEmail);
  const user = userId ? users.get(userId) : null;

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ success: false, error: "Invalid email or password." });
  }

  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  return res.json({ success: true, token, tokenType: "Bearer", expiresIn: JWT_EXPIRES_IN });
});

// ---------------------------------------------------------------------------
// GET /api/protected — demonstrates server-side JWT verification
// ---------------------------------------------------------------------------
app.get("/api/protected", requireJwt, (req, res) => {
  res.json({
    success: true,
    message: "This data is only reachable with a valid, unexpired JWT.",
    user: publicUserView(req.jwtUser),
  });
});

// ---------------------------------------------------------------------------
// Evaluator-only test endpoint: retrieve the *current* OTP for a challenge.
// NEVER do this in a real product — included here only because the
// assignment explicitly asks for a test-only mechanism to fetch simulated OTPs.
// ---------------------------------------------------------------------------
app.get("/api/test/otp/:challengeId", (req, res) => {
  const challenge = challenges.get(req.params.challengeId);
  if (!challenge) return res.status(404).json({ success: false, error: "Challenge not found." });

  // We only store a hash, so regenerate a fresh OTP for the evaluator and
  // reset the challenge to match it (keeps this test-only path honest about
  // "never return the real stored OTP" while still being useful to grade).
  const otp = regenerateOtp(challenge);
  return res.json({
    success: true,
    challengeId: challenge.challengeId,
    channel: challenge.channel,
    otp, // TEST-ONLY. Never exposed on non-test endpoints.
    expiresAt: challenge.expiresAt,
  });
});

// Health check
app.get("/api/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\nSecureID (Registration + Login) running on http://localhost:${PORT}\n`);
});

module.exports = app;
