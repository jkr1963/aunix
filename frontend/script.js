// AUNIX frontend
const API_BASE =
  (window.AUNIX_CONFIG && window.AUNIX_CONFIG.apiBase) ||
  "http://127.0.0.1:8000/api";

const TOKEN_KEY = "aunix_jwt";
const USER_KEY = "aunix_user";

// State
let allKeys = [];
let allTargets = [];
let policyFindings = [];
let fleetSummary = null;

// Charts
let algorithmChart = null;

// ---------- Auth helpers ----------
function getToken() { return localStorage.getItem(TOKEN_KEY); }
function getUser() {
  try { return JSON.parse(localStorage.getItem(USER_KEY) || "null"); }
  catch { return null; }
}
function setSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}
function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (response.status === 401) {
    clearSession();
    showLoginScreen();
    throw new Error("Unauthorized");
  }
  return response;
}

window.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);

  // -- DOM cache --
  const loginScreen = $("loginScreen");
  const appContainer = $("appContainer");
  const loginSection = $("loginSection");
  const otpSection = $("otpSection");
  const registerSection = $("registerSection");
  const mfaSetupSection = $("mfaSetupSection");
  const loginForm = $("loginForm");
  const otpForm = $("otpForm");
  const registerForm = $("registerForm");
  const mfaVerifyForm = $("mfaVerifyForm");
  const loginError = $("loginError");
  const otpError = $("otpError");
  const registerMessage = $("registerMessage");
  const mfaMessage = $("mfaMessage");
  const mfaQrImage = $("mfaQrImage");
  const showRegisterLink = $("showRegisterLink");
  const showLoginLink = $("showLoginLink");
  const backToLoginLink = $("backToLoginLink");
  const welcomeUser = $("welcomeUser");

  const sidebar = $("sidebar");
  const sidebarOverlay = $("sidebarOverlay");
  const hamburgerBtn = $("hamburgerBtn");
  const logoutBtn = $("logoutBtn");

  const targetSelect = $("targetSelect");
  const refreshDataBtn = $("refreshDataBtn");

  const downloadReportBtn = $("downloadReportBtn");
  const scanModal = $("scanModal");
  const scanTargetBtn = $("scanTargetBtn");
  const closeModalBtn = $("closeModalBtn");
  const scanTargetForm = $("scanTargetForm");
  const scanMessage = $("scanMessage");
  const installerModal = $("installerModal");
  const downloadInstallerBtn = $("downloadInstallerBtn");
  const closeInstallerModalBtn = $("closeInstallerModalBtn");
  const installerMessage = $("installerMessage");
  const installerHeadline = $("installerHeadline");
  const installCommand = $("installCommand");
  const copyInstallCmdBtn = $("copyInstallCmdBtn");
  const emptyState = $("emptyState");

  let pendingLoginEmail = "";
  let pendingLoginPassword = "";
  let pendingRegistrationEmail = "";
  let pendingRegistrationPassword = "";
  let activeAgentTargetId = null;
  let activeAgentInstallCmd = "";

  // ---------- Helpers ----------
  function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }
  function formatDate(isoString) {
    if (!isoString) return "never";
    try { return new Date(isoString).toLocaleString(); }
    catch { return isoString; }
  }
  function clearAuthMessages() {
    loginError.textContent = ""; loginError.style.color = "";
    otpError.textContent = "";
    registerMessage.textContent = "";
    mfaMessage.textContent = "";
  }
  function showOnlyAuthSection(section) {
    [loginSection, otpSection, registerSection, mfaSetupSection]
      .forEach(s => s.classList.add("hidden"));
    clearAuthMessages();
    if (section) section.classList.remove("hidden");
  }
  function showLoginScreen() {
    loginScreen.style.display = "flex";
    appContainer.style.display = "none";
    showOnlyAuthSection(loginSection);
  }
  function showDashboard() {
    const user = getUser();
    if (!user) { showLoginScreen(); return; }
    loginScreen.style.display = "none";
    appContainer.style.display = "block";
    welcomeUser.textContent = `Welcome, ${user.name || user.email}`;
    const profileName = $("profileName");
    const profileEmail = $("profileEmail");
    const profileMfa = $("profileMfa");
    if (profileName) profileName.textContent = user.name || "-";
    if (profileEmail) profileEmail.textContent = user.email || "-";
    if (profileMfa) profileMfa.textContent = user.mfa_enabled ? "Enabled" : "Disabled";

    showSection("overviewSection");
    refreshAll();
  }
  function logout() {
    clearSession();
    pendingLoginEmail = ""; pendingLoginPassword = "";
    pendingRegistrationEmail = ""; pendingRegistrationPassword = "";
    [loginForm, otpForm, registerForm, mfaVerifyForm].forEach(f => f && f.reset());
    mfaQrImage.src = "";
    // Close sidebar so it doesn't linger over the login screen
    sidebar.classList.remove("open");
    sidebarOverlay.classList.remove("show");
    showLoginScreen();
  }

  // ---------- Initial mount ----------
  if (getToken() && getUser()) showDashboard();
  else showLoginScreen();

  // ---------- Auth section toggles ----------
  showRegisterLink.addEventListener("click", e => { e.preventDefault(); registerForm.reset(); showOnlyAuthSection(registerSection); });
  showLoginLink.addEventListener("click", e => { e.preventDefault(); showOnlyAuthSection(loginSection); });
  backToLoginLink.addEventListener("click", e => {
    e.preventDefault();
    pendingLoginEmail = ""; pendingLoginPassword = "";
    otpForm.reset(); showOnlyAuthSection(loginSection);
  });

  // ---------- Login flow ----------
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault(); clearAuthMessages();
    const email = $("usernameInput").value.trim();
    const password = $("passwordInput").value;
    if (!email || !password) { loginError.textContent = "Enter email and password."; return; }
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { loginError.textContent = data.detail || "Login failed."; return; }
      pendingLoginEmail = email; pendingLoginPassword = password;
      otpForm.reset(); showOnlyAuthSection(otpSection);
    } catch (err) { loginError.textContent = "Network error during login."; console.error(err); }
  });

  otpForm.addEventListener("submit", async (e) => {
    e.preventDefault(); clearAuthMessages();
    const otpCode = $("otpInput").value.trim();
    if (!pendingLoginEmail || !pendingLoginPassword) {
      otpError.textContent = "Session expired. Log in again.";
      showOnlyAuthSection(loginSection); return;
    }
    if (!otpCode) { otpError.textContent = "Enter the code."; return; }
    try {
      const res = await fetch(`${API_BASE}/auth/login-mfa`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: pendingLoginEmail, password: pendingLoginPassword, otp_code: otpCode }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { otpError.textContent = data.detail || "OTP verification failed."; return; }
      setSession(data.access_token, data.user);
      pendingLoginEmail = ""; pendingLoginPassword = "";
      showDashboard();
    } catch (err) { otpError.textContent = "Network error verifying code."; console.error(err); }
  });

  // ---------- Register + MFA ----------
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault(); clearAuthMessages();
    const name = $("registerName").value.trim();
    const email = $("registerEmail").value.trim();
    const password = $("registerPassword").value;
    const confirm = $("registerConfirmPassword").value;
    if (!name || !email || !password || !confirm) { registerMessage.textContent = "Please fill all fields."; return; }
    if (password.length < 8) { registerMessage.textContent = "Password must be at least 8 characters."; return; }
    if (password !== confirm) { registerMessage.textContent = "Passwords do not match."; return; }
    try {
      // Single registration call: backend stashes a pending entry,
      // returns QR code. Nothing committed to the DB yet.
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { registerMessage.textContent = data.detail || "Registration failed."; return; }

      pendingRegistrationEmail = email;
      pendingRegistrationPassword = password;
      mfaQrImage.src = `data:image/png;base64,${data.qr_code_base64}`;
      mfaVerifyForm.reset();
      showOnlyAuthSection(mfaSetupSection);
    } catch (err) { registerMessage.textContent = "Network error during registration."; console.error(err); }
  });

  mfaVerifyForm.addEventListener("submit", async (e) => {
    e.preventDefault(); clearAuthMessages();
    const otpCode = $("mfaCode").value.trim();
    if (!pendingRegistrationEmail) {
      mfaMessage.textContent = "Session expired. Register again.";
      showOnlyAuthSection(registerSection); return;
    }
    if (!otpCode) { mfaMessage.textContent = "Enter the code."; return; }
    try {
      // This call now CREATES the user in the database. Before this
      // succeeds, no user record exists.
      const res = await fetch(`${API_BASE}/auth/verify-mfa`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: pendingRegistrationEmail, otp_code: otpCode }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { mfaMessage.textContent = data.detail || "MFA activation failed."; return; }

      // User is now in the DB. Log them in immediately.
      const loginRes = await fetch(`${API_BASE}/auth/login-mfa`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: pendingRegistrationEmail,
          password: pendingRegistrationPassword,
          otp_code: otpCode,
        }),
      });
      const loginData = await loginRes.json().catch(() => ({}));
      const savedEmail = pendingRegistrationEmail;
      pendingRegistrationEmail = ""; pendingRegistrationPassword = "";
      mfaQrImage.src = "";
      if (loginRes.ok) {
        setSession(loginData.access_token, loginData.user);
        showDashboard();
      } else {
        $("usernameInput").value = savedEmail;
        showOnlyAuthSection(loginSection);
        loginError.style.color = "var(--good)";
        loginError.textContent = "Registration complete. Please log in.";
      }
    } catch (err) { mfaMessage.textContent = "Network error activating MFA."; console.error(err); }
  });

  // ---------- Sidebar ----------
  hamburgerBtn.addEventListener("click", () => { sidebar.classList.add("open"); sidebarOverlay.classList.add("show"); });
  sidebarOverlay.addEventListener("click", () => { sidebar.classList.remove("open"); sidebarOverlay.classList.remove("show"); });
  logoutBtn.addEventListener("click", logout);
  document.querySelectorAll(".menu-item[data-section]").forEach(button => {
    button.addEventListener("click", () => {
      showSection(button.getAttribute("data-section"));
      sidebar.classList.remove("open"); sidebarOverlay.classList.remove("show");
    });
  });
  function showSection(sectionId) {
    document.querySelectorAll(".content-section").forEach(s => s.classList.add("hidden-section"));
    const section = $(sectionId);
    if (section) section.classList.remove("hidden-section");
  }

  // ---------- Top-level refresh ----------
  async function refreshAll() {
    await fetchTargets();
    await fetchFleetSummary();
  }

  // ---------- Targets ----------
  async function fetchTargets() {
    try {
      const res = await apiFetch("/targets");
      if (!res.ok) throw new Error("Failed to fetch targets.");
      allTargets = await res.json();
      updateTargetDropdown();
      updateTargetsTable();

      if (allTargets.length === 0) {
        emptyState.classList.remove("hidden-section");
        updateMachineInfo(null);
        renderMachineKeys([]);
        renderPolicyFindings([]);
        renderMachineSummary([], []);
        return;
      }
      emptyState.classList.add("hidden-section");

      const current = getSelectedTarget() || allTargets[0];
      targetSelect.value = current.id;
      updateMachineInfo(current);
      await Promise.all([fetchKeys(current.id), fetchPolicyFindings(current.id)]);
      renderMachineSummary(allKeys, policyFindings);
    } catch (err) { console.error(err); }
  }

  function getSelectedTarget() {
    const id = Number(targetSelect.value);
    return allTargets.find(t => t.id === id) || null;
  }

  function updateTargetDropdown() {
    targetSelect.innerHTML = "";
    if (allTargets.length === 0) {
      const opt = document.createElement("option");
      opt.textContent = "No machines registered"; opt.value = "";
      targetSelect.appendChild(opt);
      return;
    }
    allTargets.forEach(t => {
      const opt = document.createElement("option");
      opt.value = t.id;
      opt.textContent = `${t.hostname} (ID: ${t.id})`;
      targetSelect.appendChild(opt);
    });
  }

  function updateMachineInfo(target) {
    if (!target) {
      ["hostname","ipAddress","operatingSystem","targetStatus"].forEach(id => $(id).textContent = "-");
      $("lastScanAt").textContent = "never";
      return;
    }
    $("hostname").textContent = target.hostname || "-";
    $("ipAddress").textContent = target.ip_address || "-";
    $("operatingSystem").textContent = target.operating_system || "-";
    $("targetStatus").textContent = target.status || "-";
    $("lastScanAt").textContent = formatDate(target.last_scan_at);
  }

  function updateTargetsTable() {
    const tbody = $("targetsTableBody");
    tbody.innerHTML = "";
    if (allTargets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="muted">No machines registered yet.</td></tr>`;
      return;
    }
    allTargets.forEach(t => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${escapeHtml(t.id)}</td>
        <td>${escapeHtml(t.hostname)}</td>
        <td>${escapeHtml(t.ip_address || "")}</td>
        <td>${escapeHtml(t.operating_system || "")}</td>
        <td>${escapeHtml(t.status || "")}</td>
        <td>${escapeHtml(formatDate(t.last_scan_at))}</td>
        <td>
          <button class="row-actions-btn" data-action="reissue" data-id="${t.id}">Re-download agent</button>
          <button class="row-actions-btn danger" data-action="delete" data-id="${t.id}">Delete</button>
        </td>`;
      tbody.appendChild(row);
    });
    tbody.querySelectorAll(".row-actions-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = Number(btn.getAttribute("data-id"));
        const action = btn.getAttribute("data-action");
        if (action === "delete") deleteTarget(id);
        else if (action === "reissue") reissueAgent(id);
      });
    });
  }

  async function deleteTarget(targetId) {
    if (!confirm("Delete this machine and all its scan data?")) return;
    try {
      const res = await apiFetch(`/targets/${targetId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Delete failed");
      await refreshAll();
    } catch (err) { alert("Could not delete target."); console.error(err); }
  }

  // ---------- Agent download ----------
  async function downloadAgentTarball(targetId) {
    const res = await apiFetch(`/installers/agent/${targetId}`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to build agent");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `aunix-agent-${targetId}.tar.gz`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  async function reissueAgent(targetId) {
    try {
      await downloadAgentTarball(targetId);
      const cmd = `tar -xzf aunix-agent-${targetId}.tar.gz && cd aunix-agent-${targetId} && sudo ./run.sh`;
      activeAgentTargetId = targetId;
      activeAgentInstallCmd = cmd;
      installCommand.textContent = cmd;
      installerHeadline.textContent = "Run this on the machine you registered.";
      installerMessage.textContent = "Note: any previously downloaded agent for this machine has been revoked.";
      installerModal.classList.remove("hidden");
    } catch (err) { alert("Could not download agent."); console.error(err); }
  }

  // ---------- Per-machine: keys + policy ----------
  targetSelect.addEventListener("change", async () => {
    const t = getSelectedTarget();
    if (t) {
      updateMachineInfo(t);
      await Promise.all([fetchKeys(t.id), fetchPolicyFindings(t.id)]);
      renderMachineSummary(allKeys, policyFindings);
    }
  });
  refreshDataBtn.addEventListener("click", refreshAll);

  async function fetchKeys(targetId) {
    try {
      const res = await apiFetch(`/keys?target_id=${targetId}`);
      if (!res.ok) throw new Error("Failed to fetch keys.");
      allKeys = await res.json();
      renderMachineKeys(allKeys);
    } catch (err) { console.error(err); }
  }

  async function fetchPolicyFindings(targetId) {
    try {
      const res = await apiFetch(`/policy/findings/${targetId}`);
      if (!res.ok) throw new Error("Failed to fetch policy findings");
      policyFindings = await res.json();
      renderPolicyFindings(policyFindings);
    } catch (err) { console.error(err); policyFindings = []; renderPolicyFindings([]); }
  }

  function renderMachineKeys(keys) {
    const sevCount = combinedSeverityCounts(keys, policyFindings);

    $("totalKeys").textContent = keys.length;
    $("privateKeys").textContent = keys.filter(k => k.key_kind === "private").length;
    $("publicKeys").textContent = keys.filter(k => k.key_kind === "public").length;
    $("machineCritical").textContent = sevCount.critical;
    $("machineHigh").textContent = sevCount.high;
    $("machineMedium").textContent = sevCount.medium;

    renderKeyFindings(keys);
    renderKeysTable(keys);
  }

  function combinedSeverityCounts(keys, findings) {
    const out = { critical: 0, high: 0, medium: 0, info: 0 };
    keys.forEach(k => { if (out[k.severity] !== undefined) out[k.severity]++; });
    findings.forEach(f => { if (out[f.severity] !== undefined) out[f.severity]++; });
    return out;
  }

  // ---------- Per-machine summary panel ----------
  function postureBand(score) {
    if (score >= 90) return "good";
    if (score >= 70) return "fair";
    if (score >= 50) return "poor";
    return "critical";
  }

  function renderMachineSummary(keys, findings) {
    const panel = $("machineSummaryPanel");
    const sev = combinedSeverityCounts(keys, findings);
    const score = Math.max(0, 100 - 8 * sev.critical - 3 * sev.high - sev.medium);
    const band = postureBand(score);

    $("machinePostureScore").textContent = (keys.length === 0 && findings.length === 0) ? "—" : score;
    $("machinePostureBand").textContent = (keys.length === 0 && findings.length === 0) ? "no data" : band;
    panel.classList.remove("band-good", "band-fair", "band-poor", "band-critical");
    if (keys.length > 0 || findings.length > 0) panel.classList.add(`band-${band}`);

    $("machineSummaryNarrative").innerHTML = composeNarrative(keys, findings, sev, score);
  }

  function composeNarrative(keys, findings, sev, score) {
    if (keys.length === 0 && findings.length === 0) {
      return "Run the scanner agent on this machine to see findings here.";
    }

    const parts = [];

    // Lead with overall posture.
    if (sev.critical === 0 && sev.high === 0 && sev.medium === 0) {
      parts.push(`This machine is in good shape. ${keys.length} SSH key${keys.length === 1 ? "" : "s"} discovered, no policy issues, no risky configurations detected.`);
      return parts.join(" ");
    }

    // What's wrong, in order of urgency.
    const inventoryBit = `${keys.length} SSH key${keys.length === 1 ? "" : "s"} discovered.`;
    parts.push(inventoryBit);

    const phrases = [];
    if (sev.critical > 0) phrases.push(`<span class="sev-text-critical">${sev.critical} critical</span>`);
    if (sev.high > 0)     phrases.push(`<span class="sev-text-high">${sev.high} high</span>`);
    if (sev.medium > 0)   phrases.push(`<span class="sev-text-medium">${sev.medium} medium</span>`);
    parts.push(`Active findings: ${phrases.join(", ")}.`);

    // Action verdict.
    if (sev.critical > 0) {
      parts.push(`<strong>Address critical issues immediately</strong> — these typically allow unauthorized access or escalation if exploited.`);
    } else if (sev.high > 0) {
      parts.push(`Address high-severity issues this week — they materially weaken the machine's defenses.`);
    } else {
      parts.push(`Plan to address medium issues at the next maintenance window.`);
    }

    // Posture footer.
    parts.push(`Posture score: <strong>${score}/100</strong> (${postureBand(score)}).`);

    return parts.join(" ");
  }

  function renderFindingItem(severity, title, description, evidence, recommendation) {
    const safeDesc = description ? `<div class="finding-desc">${escapeHtml(description)}</div>` : "";
    const safeEvidence = evidence ? `<div class="finding-meta">${escapeHtml(evidence)}</div>` : "";
    const safeFix = recommendation
      ? `<div class="finding-fix"><span class="finding-fix-label">Recommendation:</span> ${escapeHtml(recommendation)}</div>`
      : "";
    return `
      <div class="finding severity-${severity || "info"}">
        <span class="severity-pill ${severity || "info"}">${escapeHtml(severity || "info")}</span>
        <div>
          <div class="finding-title">${escapeHtml(title)}</div>
          ${safeDesc}
          ${safeEvidence}
          ${safeFix}
        </div>
      </div>`;
  }

  function severityRank(s) { return { critical: 0, high: 1, medium: 2, info: 3 }[s] ?? 9; }

  function renderListWithCollapse(container, items, htmlFn, expandedCount = 5) {
    container.innerHTML = "";
    if (items.length === 0) {
      container.innerHTML = `<div class="no-findings">No issues detected.</div>`;
      return;
    }
    const wrap = document.createElement("div");
    wrap.className = "findings-list";
    const initial = items.slice(0, expandedCount);
    const rest = items.slice(expandedCount);

    wrap.innerHTML = initial.map(htmlFn).join("");
    container.appendChild(wrap);

    if (rest.length > 0) {
      const btn = document.createElement("button");
      btn.className = "show-more-btn";
      btn.textContent = `Show ${rest.length} more`;
      btn.addEventListener("click", () => {
        wrap.insertAdjacentHTML("beforeend", rest.map(htmlFn).join(""));
        btn.remove();
      });
      container.appendChild(btn);
    }
  }

  function renderKeyFindings(keys) {
    const entries = [];
    keys.forEach(k => {
      const fList = k.findings || [];
      const rList = k.recommendations || [];
      fList.forEach((msg, i) => {
        if (k.severity === "info") return;  // skip info-level
        entries.push({
          severity: k.severity,
          title: msg,
          description: "",
          evidence: k.file_path,
          recommendation: rList[i] || "",
        });
      });
    });
    entries.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

    const sev = { critical: 0, high: 0, medium: 0 };
    entries.forEach(e => { if (sev[e.severity] !== undefined) sev[e.severity]++; });
    $("keyFindingCounts").innerHTML = entries.length === 0
      ? `<span class="muted">no issues</span>`
      : `<span class="sev-text-critical">${sev.critical} critical</span> · `
        + `<span class="sev-text-high">${sev.high} high</span> · `
        + `<span class="sev-text-medium">${sev.medium} medium</span>`;

    renderListWithCollapse(
      $("keyFindingsList"),
      entries,
      e => renderFindingItem(e.severity, e.title, e.description, e.evidence, e.recommendation)
    );
  }

  function renderPolicyFindings(findings) {
    // Hide info-level from the highlighted list (they appear in details only)
    const visible = findings.filter(f => f.severity !== "info");
    visible.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

    const sev = { critical: 0, high: 0, medium: 0 };
    visible.forEach(f => { if (sev[f.severity] !== undefined) sev[f.severity]++; });
    $("policyCounts").innerHTML = visible.length === 0
      ? `<span class="muted">no issues</span>`
      : `<span class="sev-text-critical">${sev.critical} critical</span> · `
        + `<span class="sev-text-high">${sev.high} high</span> · `
        + `<span class="sev-text-medium">${sev.medium} medium</span>`;

    renderListWithCollapse(
      $("policyFindings"),
      visible,
      f => renderFindingItem(f.severity, f.title, f.description, f.evidence, f.recommendation)
    );
  }

  function renderKeysTable(keys) {
    const tbody = $("keysTableBody");
    tbody.innerHTML = "";
    if (keys.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="muted">No SSH keys for this machine yet.</td></tr>`;
      $("keyTableCount").textContent = "0 keys";
      return;
    }
    $("keyTableCount").textContent = `${keys.length} key${keys.length === 1 ? "" : "s"}`;
    const sorted = keys.slice().sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    sorted.forEach(k => {
      const algoLabel = k.key_algorithm
        ? (k.key_bits ? `${k.key_algorithm}-${k.key_bits}` : k.key_algorithm)
        : "";
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><span class="severity-pill ${k.severity || "info"}">${escapeHtml(k.severity || "info")}</span></td>
        <td>${escapeHtml(k.username || "")}</td>
        <td style="max-width:300px; word-break:break-word; font-family:ui-monospace,monospace; font-size:12px;">${escapeHtml(k.file_path || "")}</td>
        <td>${escapeHtml(algoLabel)}</td>
        <td>${escapeHtml(k.permissions || "")}</td>
        <td>${escapeHtml(k.owner || "")}</td>
        <td>${escapeHtml(k.key_kind || "")}</td>
        <td>${escapeHtml(k.paired_key_status || "")}</td>`;
      tbody.appendChild(row);
    });
  }

  // ---------- Fleet summary ----------
  async function fetchFleetSummary() {
    try {
      const res = await apiFetch("/dashboard/summary");
      if (!res.ok) throw new Error("Failed to fetch summary");
      fleetSummary = await res.json();
      renderFleetSummary(fleetSummary);
    } catch (err) { console.error(err); }
  }

  function renderFleetSummary(s) {
    if (!s) return;

    const score = s.posture_score;
    $("postureScore").textContent = score;
    const band = postureBand(score);
    const postureCard = $("postureCard");
    postureCard.classList.remove("band-good", "band-fair", "band-poor", "band-critical");
    postureCard.classList.add(`band-${band}`);
    $("postureBand").textContent = band;

    $("kpiMachines").textContent = s.total_machines;
    $("kpiMachinesReporting").textContent = s.machines_reporting;
    $("kpiMachinesSilent").textContent = s.machines_silent;
    $("kpiMachinesNever").textContent = s.machines_never_scanned;
    $("kpiTotalKeys").textContent = s.total_keys;
    $("kpiUniqueKeys").textContent = s.unique_fingerprints;

    if (s.total_keys > 0 && s.unique_fingerprints < s.total_keys) {
      const reused = s.total_keys - s.unique_fingerprints;
      $("kpiReuseSub").textContent = ` · ${reused} duplicate${reused === 1 ? "" : "s"}`;
    } else {
      $("kpiReuseSub").textContent = "";
    }

    $("kpiCritical").textContent = s.findings_by_severity.critical || 0;
    $("kpiHigh").textContent = s.findings_by_severity.high || 0;
    $("kpiMedium").textContent = s.findings_by_severity.medium || 0;

    const trBody = $("topRiskTable");
    trBody.innerHTML = "";
    if (!s.top_risk_machines.length) {
      trBody.innerHTML = `<tr><td colspan="4" class="muted">No findings yet.</td></tr>`;
    } else {
      s.top_risk_machines.forEach(m => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${escapeHtml(m.hostname)}</td>
          <td class="num"><span class="${m.critical > 0 ? "sev-text-critical" : "muted"}">${m.critical}</span></td>
          <td class="num"><span class="${m.high > 0 ? "sev-text-high" : "muted"}">${m.high}</span></td>
          <td class="num"><span class="${m.medium > 0 ? "sev-text-medium" : "muted"}">${m.medium}</span></td>`;
        trBody.appendChild(row);
      });
    }

    renderAlgorithmChart(s.algorithm_distribution);

    const skBody = $("sharedKeysTable");
    skBody.innerHTML = "";
    if (!s.shared_keys.length) {
      skBody.innerHTML = `<tr><td colspan="4" class="muted">No shared keys detected.</td></tr>`;
    } else {
      s.shared_keys.forEach(k => {
        const algo = k.algorithm
          ? (k.bits ? `${k.algorithm}-${k.bits}` : k.algorithm)
          : "";
        const row = document.createElement("tr");
        row.innerHTML = `
          <td style="font-family:ui-monospace,monospace; font-size:11px; word-break:break-all;">${escapeHtml(k.fingerprint)}</td>
          <td>${escapeHtml(algo)}</td>
          <td class="num">${escapeHtml(k.machine_count)}</td>
          <td>${k.hostnames.map(h => escapeHtml(h)).join(", ")}</td>`;
        skBody.appendChild(row);
      });
    }
  }

  function renderAlgorithmChart(dist) {
    const labels = Object.keys(dist);
    const values = labels.map(l => dist[l]);

    const colorFor = (l) => {
      if (l.startsWith("DSA")) return "#a01e25";
      if (l === "RSA-1024" || l === "RSA-768") return "#a01e25";
      if (l === "ED25519" || l.startsWith("RSA-4096") || l.startsWith("ECDSA")) return "#1f3a64";
      if (l === "RSA-2048") return "#5a7ba8";
      return "#aab5c5";
    };

    if (algorithmChart) algorithmChart.destroy();
    algorithmChart = new Chart($("algorithmChart"), {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: labels.map(colorFor),
          borderWidth: 0,
          barThickness: 16,
        }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { precision: 0, color: "#7a8aa3", font: { size: 11 } },
            grid: { color: "#eef2f8" },
          },
          y: {
            ticks: { color: "#4a5b75", font: { size: 12 } },
            grid: { display: false },
          },
        },
      },
    });
  }

  // ---------- PDF report downloads ----------
  async function downloadPdf(path, filename) {
    try {
      const res = await apiFetch(path);
      if (!res.ok) throw new Error(`Download failed: ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (err) {
      alert("Could not download report. Make sure you have at least one scan.");
      console.error(err);
    }
  }

  downloadReportBtn.addEventListener("click", () => {
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    downloadPdf("/reports/fleet", `aunix_fleet_${date}.pdf`);
    sidebar.classList.remove("open");
    sidebarOverlay.classList.remove("show");
  });

  const downloadMachinePdfBtn = $("downloadMachinePdfBtn");
  if (downloadMachinePdfBtn) {
    downloadMachinePdfBtn.addEventListener("click", () => {
      const t = getSelectedTarget();
      if (!t) { alert("Pick a machine first."); return; }
      const safeHost = (t.hostname || `target${t.id}`).replace(/[^a-zA-Z0-9_-]/g, "_");
      const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      downloadPdf(`/reports/audit/${t.id}`, `aunix_audit_${safeHost}_${date}.pdf`);
    });
  }

  // ---------- Register target ----------
  scanTargetBtn.addEventListener("click", () => {
    scanModal.classList.remove("hidden");
    sidebar.classList.remove("open"); sidebarOverlay.classList.remove("show");
  });
  closeModalBtn.addEventListener("click", () => {
    scanModal.classList.add("hidden");
    scanMessage.textContent = ""; scanTargetForm.reset();
  });
  closeInstallerModalBtn.addEventListener("click", () => {
    installerModal.classList.add("hidden"); installerMessage.textContent = "";
  });

  scanTargetForm.addEventListener("submit", async (e) => {
    e.preventDefault(); scanMessage.textContent = "";
    const payload = {
      hostname: $("scanHostname").value.trim(),
      ip_address: $("scanIp").value.trim() || null,
      operating_system: $("scanOs").value.trim() || null,
    };
    try {
      const res = await apiFetch("/targets", { method: "POST", body: JSON.stringify(payload) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { scanMessage.textContent = data.detail || "Failed to register machine."; return; }
      await refreshAll();
      targetSelect.value = data.id;
      updateMachineInfo(data);
      await Promise.all([fetchKeys(data.id), fetchPolicyFindings(data.id)]);
      renderMachineSummary(allKeys, policyFindings);

      activeAgentTargetId = data.id;
      activeAgentInstallCmd = data.install_command;
      installCommand.textContent = data.install_command;
      installerHeadline.textContent = `Machine "${data.hostname}" registered. Download the agent and run it.`;
      installerMessage.textContent = "";

      await downloadAgentTarball(data.id);
      scanTargetForm.reset();
      scanModal.classList.add("hidden");
      installerModal.classList.remove("hidden");
    } catch (err) { scanMessage.textContent = "Network error registering machine."; console.error(err); }
  });

  downloadInstallerBtn.addEventListener("click", async () => {
    if (!activeAgentTargetId) return;
    try { await downloadAgentTarball(activeAgentTargetId); }
    catch (err) { alert("Failed to download agent."); console.error(err); }
  });

  copyInstallCmdBtn.addEventListener("click", async () => {
    if (!activeAgentInstallCmd) return;
    try {
      await navigator.clipboard.writeText(activeAgentInstallCmd);
      copyInstallCmdBtn.textContent = "Copied!";
      setTimeout(() => { copyInstallCmdBtn.textContent = "Copy command"; }, 1500);
    } catch { alert("Could not copy. Select the command manually."); }
  });

  // ---------- Polling ----------
  setInterval(() => {
    if (appContainer.style.display === "block" && getToken()) {
      refreshAll();
    }
  }, 30000);
});
