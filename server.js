/**
 * SecureID — Part 1: Registration Journey
 * ------------------------------------------------------------
 * Flow implemented (matches the provided screens):
 *   Register (details) -> Email OTP -> SMS OTP -> Set up MFA
 *   -> Authenticator QR setup -> MFA verification -> Registration Success
 *
 * Everything security-sensitive happens on the server:
 *   - password hashing (bcrypt)
 *   - OTP generation, hashing, expiry, attempt limiting
 *   - TOTP secret generation + verification (speakeasy)
 *
 * Storage is in-memory (Maps) for assignment/demo purposes.
 * Swap `db.js`-style module for a real DB in production.
 */

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------------------------------------------------------
// In-memory "database"
// ---------------------------------------------------------------------------
const users = new Map(); // userId -> user object
const usersByEmail = new Map(); // email(lowercase) -> userId
const challenges = new Map(); // challengeId -> challenge object

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const OTP_LENGTH = 6;
const OTP_EXPIRY_SECONDS = 165; // 02:45 shown in the mock screens
const OTP_RESEND_COOLDOWN_SECONDS = 25; // 00:25 resend cooldown
const OTP_MAX_ATTEMPTS = 3; // "You have 2 attempts left" after 1st wrong try

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
  console.log(`\nSecureID (Part 1 — Registration) running on http://localhost:${PORT}\n`);
});

module.exports = app;
