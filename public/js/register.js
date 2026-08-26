(() => {
  "use strict";

  const API = ""; // same-origin

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------
  const state = {
    userId: null,
    email: "",
    mobile: "",
    emailChallengeId: null,
    smsChallengeId: null,
    mfaMethod: "authenticator",
    mfaChallengeId: null, // only used for sms/email MFA
  };

  const timers = {}; // named interval handles

  // ---------------------------------------------------------------------
  // Small DOM helpers
  // ---------------------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const showStep = (id) => {
    document.querySelectorAll(".card > section").forEach((s) => s.classList.add("hidden"));
    $(id).classList.remove("hidden");
  };
  const showToast = (msg) => {
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(timers.toast);
    timers.toast = setTimeout(() => t.classList.remove("show"), 2600);
  };

  async function api(path, body) {
    const res = await fetch(API + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  }

  function fmtTime(ms) {
    const s = Math.max(0, Math.ceil(ms / 1000));
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
  }

  // ---------------------------------------------------------------------
  // OTP box widget — builds N inputs, handles auto-advance/backspace/paste
  // ---------------------------------------------------------------------
  function buildOtpBoxes(containerId, length, onComplete) {
    const container = $(containerId);
    container.innerHTML = "";
    const inputs = [];
    for (let i = 0; i < length; i++) {
      const inp = document.createElement("input");
      inp.type = "text";
      inp.inputMode = "numeric";
      inp.maxLength = 1;
      inp.autocomplete = "one-time-code";
      container.appendChild(inp);
      inputs.push(inp);
    }

    inputs.forEach((inp, idx) => {
      inp.addEventListener("input", () => {
        inp.value = inp.value.replace(/\D/g, "").slice(-1);
        if (inp.value && idx < length - 1) inputs[idx + 1].focus();
        maybeComplete();
      });
      inp.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" && !inp.value && idx > 0) {
          inputs[idx - 1].focus();
        }
      });
      inp.addEventListener("paste", (e) => {
        e.preventDefault();
        const text = (e.clipboardData.getData("text") || "").replace(/\D/g, "");
        if (!text) return;
        text
          .slice(0, length)
          .split("")
          .forEach((ch, i) => {
            if (inputs[i]) inputs[i].value = ch;
          });
        const next = Math.min(text.length, length) - 1;
        if (inputs[next]) inputs[next].focus();
        maybeComplete();
      });
    });

    function maybeComplete() {
      const val = inputs.map((i) => i.value).join("");
      if (val.length === length && onComplete) onComplete(val);
    }

    return {
      inputs,
      getValue: () => inputs.map((i) => i.value).join(""),
      clear: () => {
        inputs.forEach((i) => {
          i.value = "";
          i.classList.remove("error-box");
        });
        inputs[0].focus();
      },
      markError: () => inputs.forEach((i) => i.classList.add("error-box")),
      clearError: () => inputs.forEach((i) => i.classList.remove("error-box")),
    };
  }

  // ---------------------------------------------------------------------
  // Generic countdown timer
  // ---------------------------------------------------------------------
  function startCountdown({ key, targetTs, tickEl, onTick, onExpire }) {
    clearInterval(timers[key]);
    const update = () => {
      const remaining = targetTs - Date.now();
      if (tickEl) tickEl.textContent = fmtTime(remaining);
      if (onTick) onTick(remaining);
      if (remaining <= 0) {
        clearInterval(timers[key]);
        if (onExpire) onExpire();
      }
    };
    update();
    timers[key] = setInterval(update, 1000);
  }

  function startResendCooldown({ key, targetTs, btn, baseLabel }) {
    clearInterval(timers[key]);
    const update = () => {
      const remaining = targetTs - Date.now();
      if (remaining <= 0) {
        clearInterval(timers[key]);
        btn.disabled = false;
        btn.textContent = baseLabel;
        return;
      }
      btn.disabled = true;
      btn.textContent = `${baseLabel} (${Math.ceil(remaining / 1000)})`;
    };
    update();
    timers[key] = setInterval(update, 1000);
  }

  // ---------------------------------------------------------------------
  // STEP 1 — Registration form
  // ---------------------------------------------------------------------
  const pwRuleTests = {
    len: (v) => v.length >= 8,
    upper: (v) => /[A-Z]/.test(v),
    num: (v) => /[0-9]/.test(v),
    special: (v) => /[^A-Za-z0-9]/.test(v),
  };

  $("password").addEventListener("input", (e) => {
    const v = e.target.value;
    document.querySelectorAll("#pwRules .rule").forEach((li) => {
      const rule = li.dataset.rule;
      li.classList.toggle("met", pwRuleTests[rule](v));
    });
  });

  $("togglePw").addEventListener("click", () => {
    const inp = $("password");
    inp.type = inp.type === "password" ? "text" : "password";
  });

  function clearFieldErrors() {
    document.querySelectorAll(".field-error").forEach((el) => {
      el.textContent = "";
      el.classList.remove("show");
    });
    document.querySelectorAll("input").forEach((el) => el.classList.remove("invalid"));
  }

  function showFieldErrors(errors) {
    Object.entries(errors).forEach(([field, msg]) => {
      const el = $(`err-${field}`);
      if (el) {
        el.textContent = msg;
        el.classList.add("show");
      }
      const inputEl = $(field);
      if (inputEl) inputEl.classList.add("invalid");
    });
  }

  $("registerForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    clearFieldErrors();

    const btn = $("createAccountBtn");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Creating...`;

    const payload = {
      fullName: $("fullName").value.trim(),
      email: $("email").value.trim(),
      mobile: `${$("countryCode").value}${$("mobile").value.trim()}`,
      password: $("password").value,
      agreeToTerms: $("agreeToTerms").checked,
    };

    const { ok, data } = await api("/api/register", payload);

    btn.disabled = false;
    btn.textContent = "Create Account";

    if (!ok) {
      showFieldErrors(data.errors || { fullName: data.error || "Something went wrong." });
      return;
    }

    state.userId = data.userId;
    state.email = payload.email;
    state.mobile = payload.mobile;
    state.emailChallengeId = data.challenge.challengeId;

    enterEmailOtpStep(data.challenge);
  });

  // ---------------------------------------------------------------------
  // STEP 2 — Email OTP
  // ---------------------------------------------------------------------
  let emailBoxes;

  function enterEmailOtpStep(challenge) {
    $("emailDestination").textContent = state.email;
    $("emailOtpStatus").textContent = "";
    $("emailOtpStatus").className = "otp-status";
    $("emailTimerRow").classList.remove("hidden");

    emailBoxes = buildOtpBoxes("emailOtpBoxes", 6);

    startCountdown({
      key: "emailExpiry",
      targetTs: challenge.expiresAt,
      tickEl: $("emailTimer"),
      onExpire: () => {
        $("emailOtpStatus").textContent = "This code has expired.";
        $("emailOtpStatus").className = "otp-status error";
        $("emailTimerRow").classList.add("hidden");
        $("verifyEmailBtn").disabled = true;
      },
    });

    startResendCooldown({
      key: "emailResend",
      targetTs: challenge.resendAvailableAt,
      btn: $("resendEmailBtn"),
      baseLabel: "Resend code",
    });

    $("verifyEmailBtn").disabled = false;
    showStep("step-email-otp");
  }

  $("verifyEmailBtn").addEventListener("click", async () => {
    const otp = emailBoxes.getValue();
    if (otp.length !== 6) {
      emailBoxes.markError();
      $("emailOtpStatus").textContent = "Enter all 6 digits.";
      $("emailOtpStatus").className = "otp-status error";
      return;
    }

    const { ok, data } = await api("/api/verify-email-otp", {
      challengeId: state.emailChallengeId,
      otp,
    });

    if (!ok) {
      emailBoxes.markError();
      $("emailOtpStatus").textContent =
        data.error + (data.challenge ? ` You have ${data.challenge.attemptsRemaining} attempts left.` : "");
      $("emailOtpStatus").className = "otp-status error";
      if (data.expired) {
        $("emailTimerRow").classList.add("hidden");
        $("verifyEmailBtn").disabled = true;
      }
      return;
    }

    state.smsChallengeId = data.challenge.challengeId;
    enterSmsOtpStep(data.challenge);
  });

  $("resendEmailBtn").addEventListener("click", async () => {
    const { ok, data } = await api("/api/send-email-otp", { challengeId: state.emailChallengeId });
    if (!ok) {
      showToast(data.error || "Please wait before resending.");
      return;
    }
    emailBoxes.clear();
    $("emailOtpStatus").textContent = "";
    $("verifyEmailBtn").disabled = false;
    $("emailTimerRow").classList.remove("hidden");
    startCountdown({
      key: "emailExpiry",
      targetTs: data.challenge.expiresAt,
      tickEl: $("emailTimer"),
      onExpire: () => {
        $("emailOtpStatus").textContent = "This code has expired.";
        $("emailOtpStatus").className = "otp-status error";
        $("verifyEmailBtn").disabled = true;
      },
    });
    startResendCooldown({
      key: "emailResend",
      targetTs: data.challenge.resendAvailableAt,
      btn: $("resendEmailBtn"),
      baseLabel: "Resend code",
    });
    showToast("A new code has been sent.");
  });

  // ---------------------------------------------------------------------
  // STEP 3 — SMS OTP
  // ---------------------------------------------------------------------
  let smsBoxes;

  function enterSmsOtpStep(challenge) {
    $("smsDestination").textContent = state.mobile;
    $("smsOtpStatus").textContent = "";
    $("smsOtpStatus").className = "otp-status";
    $("smsTimerRow").classList.remove("hidden");
    $("verifySmsBtn").disabled = false;

    smsBoxes = buildOtpBoxes("smsOtpBoxes", 6);

    startCountdown({
      key: "smsExpiry",
      targetTs: challenge.expiresAt,
      tickEl: $("smsTimer"),
      onExpire: () => {
        $("smsOtpStatus").textContent = "This code has expired.";
        $("smsOtpStatus").className = "otp-status error";
        $("verifySmsBtn").disabled = true;
      },
    });

    startResendCooldown({
      key: "smsResend",
      targetTs: challenge.resendAvailableAt,
      btn: $("resendSmsBtn"),
      baseLabel: "Resend code",
    });

    showStep("step-sms-otp");
  }

  $("verifySmsBtn").addEventListener("click", async () => {
    const otp = smsBoxes.getValue();
    if (otp.length !== 6) {
      smsBoxes.markError();
      $("smsOtpStatus").textContent = "Enter all 6 digits.";
      $("smsOtpStatus").className = "otp-status error";
      return;
    }

    const { ok, data } = await api("/api/verify-sms-otp", {
      challengeId: state.smsChallengeId,
      otp,
    });

    if (!ok) {
      smsBoxes.markError();
      if (data.challenge && data.challenge.locked) {
        $("smsLockedDestination").textContent = state.mobile;
        showStep("step-sms-locked");
        return;
      }
      $("smsOtpStatus").textContent =
        data.error + (data.challenge ? ` You have ${data.challenge.attemptsRemaining} attempts left.` : "");
      $("smsOtpStatus").className = "otp-status error";
      return;
    }

    enterMfaSetupStep();
  });

  $("resendSmsBtn").addEventListener("click", async () => resendSms());
  $("smsLockedResendBtn").addEventListener("click", async () => resendSms());

  async function resendSms() {
    const { ok, data } = await api("/api/send-sms-otp", { challengeId: state.smsChallengeId });
    if (!ok) {
      showToast(data.error || "Please wait before resending.");
      return;
    }
    enterSmsOtpStep(data.challenge);
    showToast("A new code has been sent.");
  }

  // ---------------------------------------------------------------------
  // STEP 4 — Choose MFA method
  // ---------------------------------------------------------------------
  function enterMfaSetupStep() {
    showStep("step-mfa-setup");
  }

  document.querySelectorAll(".mfa-option").forEach((opt) => {
    opt.addEventListener("click", () => {
      document.querySelectorAll(".mfa-option").forEach((o) => o.classList.remove("selected"));
      opt.classList.add("selected");
      opt.querySelector("input[type=radio]").checked = true;
      state.mfaMethod = opt.dataset.method;
    });
  });

  $("mfaContinueBtn").addEventListener("click", async () => {
    const btn = $("mfaContinueBtn");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Please wait...`;

    const { ok, data } = await api("/api/mfa/setup", { userId: state.userId, method: state.mfaMethod });

    btn.disabled = false;
    btn.textContent = "Continue";

    if (!ok) {
      showToast(data.error || "Something went wrong.");
      return;
    }

    if (state.mfaMethod === "authenticator") {
      $("qrImage").src = data.qrCodeDataUrl;
      $("manualKey").textContent = data.manualSetupKey;
      $("manualKeyRow").classList.add("hidden");
      showStep("step-authenticator-setup");
    } else {
      state.mfaChallengeId = data.challenge.challengeId;
      enterMfaVerifyStep(data.challenge);
    }
  });

  $("showManualKeyBtn").addEventListener("click", () => {
    $("manualKeyRow").classList.toggle("hidden");
  });

  $("authenticatorContinueBtn").addEventListener("click", () => {
    enterMfaVerifyStep(null);
  });

  // ---------------------------------------------------------------------
  // STEP 6 — MFA verification
  // ---------------------------------------------------------------------
  let mfaBoxes;

  function enterMfaVerifyStep(challenge) {
    $("mfaOtpStatus").textContent = "";
    $("mfaOtpStatus").className = "otp-status";
    mfaBoxes = buildOtpBoxes("mfaOtpBoxes", 6);
    $("verifyMfaBtn").disabled = false;

    if (state.mfaMethod === "authenticator") {
      $("mfaVerifySubtitle").textContent = "Enter the code from your authenticator app";
      $("mfaAccessHelp").textContent = "Can't access your app?";
      $("mfaTimerRow").classList.add("hidden");
      $("mfaVerifyBack").dataset.back = "step-authenticator-setup";
    } else {
      const channelLabel = state.mfaMethod === "sms" ? "your phone" : "your email";
      $("mfaVerifySubtitle").textContent = `Enter the code sent to ${channelLabel}`;
      $("mfaAccessHelp").textContent = "Didn't receive the code?";
      $("mfaTimerRow").classList.remove("hidden");
      $("mfaVerifyBack").dataset.back = "step-mfa-setup";
      startCountdown({
        key: "mfaExpiry",
        targetTs: challenge.expiresAt,
        tickEl: $("mfaTimer"),
        onExpire: () => {
          $("mfaOtpStatus").textContent = "This code has expired.";
          $("mfaOtpStatus").className = "otp-status error";
          $("verifyMfaBtn").disabled = true;
        },
      });
    }

    showStep("step-mfa-verify");
  }

  $("verifyMfaBtn").addEventListener("click", async () => {
    const code = mfaBoxes.getValue();
    if (code.length !== 6) {
      mfaBoxes.markError();
      $("mfaOtpStatus").textContent = "Enter all 6 digits.";
      $("mfaOtpStatus").className = "otp-status error";
      return;
    }

    const { ok, data } = await api("/api/mfa/verify", {
      userId: state.userId,
      code,
      challengeId: state.mfaChallengeId,
    });

    if (!ok) {
      mfaBoxes.markError();
      $("mfaOtpStatus").textContent =
        (data.error || "Invalid code. Please try again.") +
        (data.challenge ? ` You have ${data.challenge.attemptsRemaining} attempts left.` : "");
      $("mfaOtpStatus").className = "otp-status error";
      return;
    }

    showStep("step-success");
  });

  // ---------------------------------------------------------------------
  // Back buttons
  // ---------------------------------------------------------------------
  document.querySelectorAll("[data-back]").forEach((btn) => {
    btn.addEventListener("click", () => showStep(btn.dataset.back));
  });

  $("continueToLoginBtn").addEventListener("click", () => {
    window.location.href = "/login.html";
  });
})();
