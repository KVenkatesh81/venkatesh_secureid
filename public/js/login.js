(() => {
  "use strict";

  const API = "";

  const state = {
    userId: null,
    method: null,
    challengeId: null,
    destination: "",
    rememberMe: false,
  };

  const timers = {};

  // ---------------------------------------------------------------------
  // Shared helpers (mirrors register.js — kept separate on purpose so each
  // page's script is self-contained and easy to read independently)
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

  async function api(path, body, method = "POST") {
    const res = await fetch(API + path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      credentials: "include", // send/receive the session cookie
      body: body ? JSON.stringify(body) : undefined,
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

  function buildOtpBoxes(containerId, length) {
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
      });
      inp.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" && !inp.value && idx > 0) inputs[idx - 1].focus();
      });
      inp.addEventListener("paste", (e) => {
        e.preventDefault();
        const text = (e.clipboardData.getData("text") || "").replace(/\D/g, "");
        if (!text) return;
        text.slice(0, length).split("").forEach((ch, i) => { if (inputs[i]) inputs[i].value = ch; });
        const next = Math.min(text.length, length) - 1;
        if (inputs[next]) inputs[next].focus();
      });
    });
    return {
      getValue: () => inputs.map((i) => i.value).join(""),
      clear: () => { inputs.forEach((i) => { i.value = ""; i.classList.remove("error-box"); }); inputs[0].focus(); },
      markError: () => inputs.forEach((i) => i.classList.add("error-box")),
    };
  }

  function startCountdown({ key, targetTs, tickEl, onExpire }) {
    clearInterval(timers[key]);
    const update = () => {
      const remaining = targetTs - Date.now();
      if (tickEl) tickEl.textContent = fmtTime(remaining);
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
  // STEP 1 — Login form
  // ---------------------------------------------------------------------
  $("toggleLoginPw").addEventListener("click", () => {
    const inp = $("loginPassword");
    inp.type = inp.type === "password" ? "text" : "password";
  });

  $("googleBtn").addEventListener("click", () => {
    showToast("Google sign-in isn't wired up in this demo.");
  });

  $("forgotPasswordLink").addEventListener("click", (e) => {
    e.preventDefault();
    showToast("Password reset isn't part of this demo yet.");
  });

  function clearLoginErrors() {
    ["loginEmail", "loginPassword", "loginGeneral"].forEach((f) => {
      const el = $(`err-${f}`);
      el.textContent = "";
      el.classList.remove("show");
    });
    $("loginEmail").classList.remove("invalid");
    $("loginPassword").classList.remove("invalid");
  }

  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    clearLoginErrors();

    const email = $("loginEmail").value.trim();
    const password = $("loginPassword").value;
    state.rememberMe = $("rememberMe").checked;

    if (!email || !password) {
      if (!email) { $("err-loginEmail").textContent = "Required"; $("err-loginEmail").classList.add("show"); $("loginEmail").classList.add("invalid"); }
      if (!password) { $("err-loginPassword").textContent = "Required"; $("err-loginPassword").classList.add("show"); $("loginPassword").classList.add("invalid"); }
      return;
    }

    const btn = $("loginBtn");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Logging in...`;

    const { ok, data } = await api("/api/login", { email, password });

    btn.disabled = false;
    btn.textContent = "Login";

    if (!ok) {
      $("err-loginGeneral").textContent = data.error || "Invalid email or password. Please try again.";
      $("err-loginGeneral").classList.add("show");
      $("loginEmail").classList.add("invalid");
      $("loginPassword").classList.add("invalid");
      return;
    }

    if (!data.mfaRequired) {
      window.location.href = "/dashboard.html";
      return;
    }

    state.userId = data.userId;
    enterChooseMethodStep(data.availableMethods, data.defaultMethod);
  });

  // ---------------------------------------------------------------------
  // STEP 3 — Choose MFA method
  // ---------------------------------------------------------------------
  const METHOD_META = {
    email: { icon: "✉️", label: "Email OTP", desc: "Receive a code on your email" },
    sms: { icon: "💬", label: "SMS OTP", desc: "Receive a code on your mobile" },
    authenticator: { icon: "🔑", label: "Authenticator App", desc: "Use code from authenticator app" },
  };

  function enterChooseMethodStep(availableMethods, defaultMethod) {
    const container = $("loginMfaOptions");
    container.innerHTML = "";
    state.method = defaultMethod;

    availableMethods.forEach((method) => {
      const meta = METHOD_META[method];
      const opt = document.createElement("label");
      opt.className = "mfa-option" + (method === defaultMethod ? " selected" : "");
      opt.dataset.method = method;
      opt.innerHTML = `
        <span class="mfa-icon">${meta.icon}</span>
        <span class="mfa-text"><strong>${meta.label}</strong><span>${meta.desc}</span></span>
        <input type="radio" name="loginMfaMethod" value="${method}" ${method === defaultMethod ? "checked" : ""} />
      `;
      opt.addEventListener("click", () => {
        container.querySelectorAll(".mfa-option").forEach((o) => o.classList.remove("selected"));
        opt.classList.add("selected");
        opt.querySelector("input").checked = true;
        state.method = method;
      });
      container.appendChild(opt);
    });

    showStep("step-choose-method");
  }

  $("chooseMethodContinueBtn").addEventListener("click", async () => {
    const btn = $("chooseMethodContinueBtn");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Please wait...`;

    const { ok, data } = await api("/api/login/select-method", { userId: state.userId, method: state.method });

    btn.disabled = false;
    btn.textContent = "Continue";

    if (!ok) {
      showToast(data.error || "Something went wrong.");
      return;
    }

    enterOtpStep(data);
  });

  // ---------------------------------------------------------------------
  // STEP 4/5/6 — OTP / TOTP verification
  // ---------------------------------------------------------------------
  let loginOtpBoxes;

  function enterOtpStep(data) {
    const { method } = data;
    state.method = method;
    state.challengeId = data.challenge ? data.challenge.challengeId : null;

    $("loginOtpStatus").textContent = "";
    $("loginOtpStatus").className = "otp-status";
    $("verifyLoginOtpBtn").disabled = false;
    loginOtpBoxes = buildOtpBoxes("loginOtpBoxes", 6);

    if (method === "authenticator") {
      $("loginOtpIcon").textContent = "🛡️";
      $("loginOtpTitle").textContent = "Enter authenticator code";
      $("loginOtpSubtitle").textContent = "Enter the 6-digit code from your authenticator app";
      $("loginOtpDestination").textContent = "";
      $("loginOtpTimerRow").classList.add("hidden");
      $("resendLoginOtpBtn").parentElement.classList.add("hidden");
    } else {
      const isEmail = method === "email";
      $("loginOtpIcon").textContent = isEmail ? "✉️" : "📱";
      $("loginOtpTitle").textContent = isEmail ? "Email Verification" : "Mobile Verification";
      $("loginOtpSubtitle").textContent = "Enter the 6-digit code sent to";
      $("loginOtpDestination").textContent = data.challenge.destination;
      $("loginOtpTimerRow").classList.remove("hidden");
      $("resendLoginOtpBtn").parentElement.classList.remove("hidden");

      startCountdown({
        key: "loginOtpExpiry",
        targetTs: data.challenge.expiresAt,
        tickEl: $("loginOtpTimer"),
        onExpire: () => {
          $("loginOtpStatus").textContent = "Code expired.";
          $("loginOtpStatus").className = "otp-status error";
          $("verifyLoginOtpBtn").disabled = true;
        },
      });
      startResendCooldown({
        key: "loginOtpResend",
        targetTs: data.challenge.resendAvailableAt,
        btn: $("resendLoginOtpBtn"),
        baseLabel: "Resend code",
      });
    }

    showStep("step-login-otp");
  }

  $("verifyLoginOtpBtn").addEventListener("click", async () => {
    const code = loginOtpBoxes.getValue();
    if (code.length !== 6) {
      loginOtpBoxes.markError();
      $("loginOtpStatus").textContent = "Enter all 6 digits.";
      $("loginOtpStatus").className = "otp-status error";
      return;
    }

    const { ok, data } = await api("/api/verify-login-otp", {
      userId: state.userId,
      method: state.method,
      code,
      challengeId: state.challengeId,
      rememberMe: state.rememberMe,
    });

    if (!ok) {
      loginOtpBoxes.markError();
      $("loginOtpStatus").textContent =
        (data.error || "Invalid code. Please try again.") +
        (data.challenge ? ` You have ${data.challenge.attemptsRemaining} attempts left.` : "");
      $("loginOtpStatus").className = "otp-status error";
      return;
    }

    window.location.href = "/dashboard.html";
  });

  $("resendLoginOtpBtn").addEventListener("click", async () => {
    const { ok, data } = await api("/api/login/select-method", { userId: state.userId, method: state.method });
    if (!ok) {
      showToast(data.error || "Please wait before resending.");
      return;
    }
    loginOtpBoxes.clear();
    enterOtpStep(data);
    showToast("A new code has been sent.");
  });

  document.querySelectorAll("[data-back]").forEach((btn) => {
    btn.addEventListener("click", () => showStep(btn.dataset.back));
  });
})();
