(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  async function api(path, options = {}) {
    const res = await fetch(path, { credentials: "include", ...options });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  }

  // In-memory only — deliberately never written to localStorage/sessionStorage.
  let currentJwt = null;

  async function init() {
    const { ok, data } = await api("/api/me");
    $("loadingCard").classList.add("hidden");

    if (!ok) {
      $("notLoggedInCard").classList.remove("hidden");
      return;
    }

    const user = data.user;
    $("welcomeName").textContent = user.fullName ? `, ${user.fullName.split(" ")[0]}!` : "!";
    $("infoEmail").textContent = user.email;
    $("infoMobile").textContent = user.mobile;
    $("infoMfa").textContent = user.mfaMethod
      ? user.mfaMethod.charAt(0).toUpperCase() + user.mfaMethod.slice(1)
      : "—";
    $("dashboardCard").classList.remove("hidden");
  }

  $("goToLoginBtn").addEventListener("click", () => {
    window.location.href = "/login.html";
  });

  $("logoutBtn").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" });
    window.location.href = "/login.html";
  });

  $("getTokenBtn").addEventListener("click", async () => {
    const password = $("jwtPassword").value;
    if (!password) {
      $("jwtPassword").classList.add("invalid");
      return;
    }
    $("jwtPassword").classList.remove("invalid");

    const meRes = await api("/api/me");
    if (!meRes.ok) return;

    const btn = $("getTokenBtn");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Requesting token...`;

    const tokenRes = await api("/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: meRes.data.user.email, password }),
    });

    if (!tokenRes.ok) {
      btn.disabled = false;
      btn.textContent = "Get JWT & call /api/protected";
      $("jwtPassword").classList.add("invalid");
      return;
    }

    currentJwt = tokenRes.data.token;

    const protectedRes = await api("/api/protected", {
      headers: { Authorization: `Bearer ${currentJwt}` },
    });

    $("jwtToken").textContent = currentJwt;
    $("protectedResponse").textContent = JSON.stringify(protectedRes.data, null, 2);
    $("jwtResult").classList.remove("hidden");

    btn.disabled = false;
    btn.textContent = "Get JWT & call /api/protected";
    $("jwtPassword").value = "";
  });

  init();
})();
