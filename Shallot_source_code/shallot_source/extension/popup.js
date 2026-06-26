const CONTROL_BASE = "http://127.0.0.1:7070";

function authHeaders(extra = {}) {
  const token = window.ONION_CONTROL_TOKEN || window.CONTROL_API_TOKEN || "";
  return token ? { ...extra, Authorization: `Bearer ${token}` } : { ...extra };
}

const $ = (id) => document.getElementById(id);
const els = {
  statusBadge: $("statusBadge"), routingState: $("routingState"), apiState: $("apiState"), proxyValue: $("proxyValue"), controlValue: $("controlValue"),
  routeBox: $("routeBox"), circuitId: $("circuitId"), rotationCountdown: $("rotationCountdown"), rotationMode: $("rotationMode"), routeModeLabel: $("routeModeLabel"), previousCircuit: $("previousCircuit"), policyLabel: $("policyLabel"),
  activeSessions: $("activeSessions"), totalSessions: $("totalSessions"), bytesUp: $("bytesUp"), bytesDown: $("bytesDown"), uptime: $("uptime"), sessionsContainer: $("sessionsContainer"), visitedSitesContainer: $("visitedSitesContainer"), messageBox: $("messageBox"),
  enableBtn: $("enableBtn"), disableBtn: $("disableBtn"), newCircuitBtn: $("newCircuitBtn"), refreshBtn: $("refreshBtn"), resetSessionsBtn: $("resetSessionsBtn"), entrySelect: $("entrySelect"), applyEntryBtn: $("applyEntryBtn"), autoRotateMode: $("autoRotateMode"), rotateIntervalSelect: $("rotateIntervalSelect"), applyRotateBtn: $("applyRotateBtn"),
  entryRelayPool: $("entryRelayPool"), middleRelayPool: $("middleRelayPool"), exitRelayPool: $("exitRelayPool"),
  keyExchangeLabel: $("keyExchangeLabel"), paddingLabel: $("paddingLabel"), paddingToggle: $("paddingToggle"),
  contributorToggle: $("contributorToggle"), contributorHost: $("contributorHost"), contributorPort: $("contributorPort"), contributorStatus: $("contributorStatus"), directoryServerStatusLine: $("directoryServerStatusLine"), contributorSettings: $("contributorSettings"),
  contributorPathToggle: $("contributorPathToggle"), contributorPathOptions: $("contributorPathOptions"), contributorHopSelect: $("contributorHopSelect"), onlineContributorCount: $("onlineContributorCount"), contributorPathStatus: $("contributorPathStatus"),
  directoryCacheBanner: $("directoryCacheBanner"), directoryCacheBannerDetail: $("directoryCacheBannerDetail"),
  httpWarningBanner: $("httpWarningBanner"), httpWarningDetail: $("httpWarningDetail"),
  systemProxyNotice: $("systemProxyNotice"),
  systemProxyNoticeTitle: $("systemProxyNoticeTitle"),
  systemProxyNoticeText: $("systemProxyNoticeText"),
  systemProxyConfirmed: $("systemProxyConfirmed"),
};

let latestDashboard = null;
let countdownTimer = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[c]));
}

function formatBytes(n) {
  const u = ["B", "KB", "MB", "GB"];
  let v = Math.max(0, Number(n || 0));
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(2)} ${u[i]}`;
}

function formatDuration(s) {
  s = Math.max(0, Number(s || 0) | 0);
  const m = Math.floor(s / 60), r = s % 60, h = Math.floor(m / 60), mm = m % 60;
  if (h) return `${h}h ${mm}m ${r}s`;
  if (m) return `${m}m ${r}s`;
  return `${r}s`;
}

function formatTimestamp(epoch) {
  if (!epoch) return "-";
  return new Date(epoch * 1000).toLocaleTimeString();
}

function updateBadge(apiOnline, enabled) {
  els.statusBadge.className = "badge " + (!apiOnline ? "badge-offline" : enabled ? "badge-online" : "badge-disabled");
  els.statusBadge.textContent = !apiOnline ? "Offline" : enabled ? "Enabled" : "Disabled";
}

function showMessage(msg, isError = false) {
  els.messageBox.classList.remove("hidden");
  els.messageBox.textContent = msg;
  els.messageBox.style.borderColor = isError ? "#ef4444" : "#2563eb";
}

function clearMessage() {
  els.messageBox.classList.add("hidden");
  els.messageBox.textContent = "";
}

async function apiGet(path) {
  const res = await fetch(CONTROL_BASE + path, { cache: "no-store", headers: authHeaders() });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiPost(path, body = {}) {
  const res = await fetch(CONTROL_BASE + path, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function proxyMessage(type) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type }, (response) => {
        if (chrome.runtime.lastError) return resolve({ ok: false, error: chrome.runtime.lastError.message });
        resolve(response || { ok: false, error: "No response from background script" });
      });
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
}

function populateEntrySelect(dir, selected) {
  const entries = dir.entries || [];
  const options = [
    '<option value="">Random entry relay (no lock)</option>',
    ...entries.map(e => `<option value="${escapeHtml(e.id)}">${escapeHtml(e.label || `${e.id} (${e.host}:${e.port})`)}</option>`)
  ];
  els.entrySelect.innerHTML = options.join("");
  els.entrySelect.value = selected || "";
}

function routeHopClass(hop) {
  const text = String(hop || "").toLowerCase();
  if (text === "client" || text.includes("client")) return "client";
  if (text.includes("entry")) return "entry";
  if (text.includes("exit")) return "exit";
  if (text.includes("contrib") || text.includes("contributor") || text.includes("user")) return "contributor";
  return "middle";
}

function compactHopLabel(hop) {
  const text = String(hop || "");
  const parts = text.split(":");
  if (parts.length >= 4) return `${parts[0]}:${parts[1]}:${parts[3]}`;
  return text;
}

function renderRoute(routeList) {
  if (!routeList?.length) return '<span class="empty">No route yet.</span>';
  return routeList.map((hop, index) => {
    const hopHtml = `<span class="route-hop ${routeHopClass(hop)}" title="${escapeHtml(hop)}">${escapeHtml(compactHopLabel(hop))}</span>`;
    return index === 0 ? hopHtml : `<span class="route-arrow">→</span>${hopHtml}`;
  }).join("");
}

function renderRelayPool(container, relays) {
  if (!relays.length) {
    container.innerHTML = '<div class="empty">None</div>';
    return;
  }
  container.innerHTML = relays.map(r => {
    const tags = [r.contributor ? "Contributor" : "Official", r.status && r.status !== "online" ? r.status : ""].filter(Boolean).join(" • ");
    return `<div class="relay-chip ${r.active ? "active" : ""}">
      <div>
        <div class="relay-name">${escapeHtml(r.id)}</div>
        <div class="mono small wrap">${escapeHtml(r.host)}:${escapeHtml(r.port)}</div>
        <div class="muted small wrap">${escapeHtml(tags)}</div>
      </div>
      <span class="relay-state ${r.enabled ? "on" : ""}">${r.active ? "Active" : r.enabled ? "Ready" : "Off"}</span>
    </div>`;
  }).join("");
}

function cleanDestinationHost(destination) {
  let value = String(destination || "").trim();
  if (!value) return "";
  value = value.replace(/^https?:\/\//i, "");
  value = value.split("/")[0].split("?")[0].split("#")[0];
  value = value.replace(/^\[/, "").replace(/\]$/, "");
  const lastColon = value.lastIndexOf(":");
  if (lastColon > -1 && /^\d+$/.test(value.slice(lastColon + 1))) {
    value = value.slice(0, lastColon);
  }
  return value.toLowerCase();
}

function isUserFacingDestination(destination) {
  const host = cleanDestinationHost(destination);
  if (!host) return false;

  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$/.test(host)) return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return false;

  const blockedExact = new Set([
    "edge.microsoft.com",
    "browser.events.data.msn.com",
    "assets.msn.com",
    "ntp.msn.com",
    "c.msn.com",
    "r.bing.com",
    "c.bing.com",
    "th.bing.com",
    "r.msftstatic.com",
    "sb.scorecardresearch.com",
    "img-s-msn-com.akamaized.net",
    "fonts.gstatic.com",
    "fonts.googleapis.com",
    "i.ytimg.com",
    "yt3.ggpht.com",
    "storage.live.com",
    "login.live.com",
  ]);

  if (blockedExact.has(host)) return false;

  const blockedContains = [
    "cloudmessaging.edge.microsoft.com",
    "msftconnecttest.com",
    "akamaized.net",
    "scorecardresearch.com",
    "doubleclick.net",
    "google-analytics.com",
    "googlesyndication.com",
    "gstatic.com",
    "msftstatic.com",
    "windows.com",
  ];
  if (blockedContains.some(part => host.includes(part))) return false;

  const allowedExact = new Set([
    "google.com",
    "www.google.com",
    "youtube.com",
    "www.youtube.com",
    "wikipedia.org",
    "www.wikipedia.org",
    "example.com",
    "www.example.com",
    "chatgpt.com",
    "www.chatgpt.com",
    "claude.ai",
    "www.bing.com",
    "bing.com",
  ]);
  if (allowedExact.has(host)) return true;

  if (host.startsWith("www.")) return true;

  const labels = host.split(".");
  if (labels.length <= 2) return true;

  return false;
}

function renderVisitedSites(sessionList) {
  const visibleSessions = (sessionList || []).filter(s => isUserFacingDestination(s.destination));

  if (!visibleSessions.length) {
    els.visitedSitesContainer.innerHTML = '<div class="empty">No user-facing websites detected yet. Background browser services are hidden here.</div>';
    return;
  }

  const byDestination = new Map();
  for (const s of visibleSessions) {
    const host = cleanDestinationHost(s.destination);
    const destination = host || String(s.destination || "unknown");
    const item = byDestination.get(destination) || {
      destination,
      count: 0,
      up: 0,
      down: 0,
      lastStarted: 0,
      statuses: new Set(),
    };
    item.count += 1;
    item.up += Number(s.bytes_from_browser || 0);
    item.down += Number(s.bytes_to_browser || 0);
    item.lastStarted = Math.max(item.lastStarted, Number(s.started_at || 0));
    item.statuses.add(String(s.status || "unknown"));
    byDestination.set(destination, item);
  }

  const sites = [...byDestination.values()].sort((a, b) => b.lastStarted - a.lastStarted).slice(0, 20);
  els.visitedSitesContainer.innerHTML = sites.map(site => `<div class="site-card">
    <div class="site-card-title">${escapeHtml(site.destination)}</div>
    <div class="site-meta">
      <div><strong>Sessions:</strong> ${site.count}</div>
      <div><strong>Last seen:</strong> ${formatTimestamp(site.lastStarted)}</div>
      <div><strong>Traffic:</strong> ↑ ${formatBytes(site.up)} / ↓ ${formatBytes(site.down)}</div>
      <div><strong>Status:</strong> ${escapeHtml([...site.statuses].join(", "))}</div>
    </div>
  </div>`).join("");
}

function renderSessions(sessionList) {
  if (!sessionList?.length) {
    els.sessionsContainer.innerHTML = '<div class="empty">No sessions yet.</div>';
    return;
  }
  els.sessionsContainer.innerHTML = sessionList.slice(0, 20).map(s => {
    const cl = { open: "status-open", opening: "status-opening", closed: "status-closed", error: "status-error" }[s.status] || "status-closed";
    return `<div class="session-card">
      <div class="session-top">
        <div class="session-destination">${escapeHtml(s.destination)}</div>
        <div class="session-status ${cl}">${escapeHtml(s.status)}</div>
      </div>
      <div class="session-meta">
        <div><strong>ID:</strong> <span class="mono wrap">${escapeHtml(s.session_id)}</span></div>
        <div><strong>Type:</strong> ${escapeHtml(s.type)}</div>
        <div><strong>Started:</strong> ${formatTimestamp(s.started_at)}</div>
        <div><strong>Route:</strong> <span class="wrap">${escapeHtml((s.route || []).join(' → '))}</span></div>
        <div><strong>Up:</strong> ${formatBytes(s.bytes_from_browser || 0)}</div>
        <div><strong>Down:</strong> ${formatBytes(s.bytes_to_browser || 0)}</div>
        ${s.last_error ? `<div><strong>Error:</strong> <span class="wrap">${escapeHtml(s.last_error)}</span></div>` : ""}
      </div>
    </div>`;
  }).join("");
}

function startCountdown() {
  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = setInterval(() => {
    if (!latestDashboard?.auto_rotate) {
      els.rotationCountdown.textContent = "-";
      return;
    }
    const auto = latestDashboard.auto_rotate;
    if (!auto.enabled) {
      els.rotationCountdown.textContent = "Manual";
      return;
    }
    auto.seconds_until_rotation = Math.max(0, (auto.seconds_until_rotation || 0) - 1);
    els.rotationCountdown.textContent = formatDuration(auto.seconds_until_rotation);
  }, 1000);
}

function isHttpSession(s) {
  if (!s) return false;
  if (String(s.type || "").toLowerCase() === "http") return true;
  const dest = String(s.destination || "");
  return /:80(\b|$)/.test(dest) && !dest.startsWith("https");
}

function updateHttpWarning(sessions) {
  if (!els.httpWarningBanner) return;
  const httpSessions = (sessions || []).filter(isHttpSession);
  if (httpSessions.length === 0) {
    els.httpWarningBanner.classList.add("hidden");
    return;
  }
  const examples = [...new Set(httpSessions.map(s => s.destination).filter(Boolean))].slice(0, 4);
  const exampleText = examples.length ? ` Observed: ${examples.map(escapeHtml).join(", ")}.` : "";
  if (els.httpWarningDetail) {
    els.httpWarningDetail.innerHTML = `${httpSessions.length} plain HTTP session${httpSessions.length === 1 ? "" : "s"} observed. HTTPS sessions are still protected end-to-end by TLS, but plain HTTP can be read by the exit relay. Some of these may be automatic browser or Windows connectivity checks.${exampleText}`;
  }
  els.httpWarningBanner.classList.remove("hidden");
}

function updateDirectoryCacheBanner(cache) {
  if (!els.directoryCacheBanner) return;
  if (!cache) {
    els.directoryCacheBanner.classList.add("hidden");
    return;
  }
  // Healthy state: serving directly from the live signed directory server.
  if (cache.source === "directory_server") {
    els.directoryCacheBanner.classList.add("hidden");
    return;
  }
  // Otherwise the cache is on local file or uninitialized; surface a
  // specific reason so the user knows what is wrong. There is no in-popup
  // fix anymore: the directory server URL is baked at install time, so
  // the recovery path is on the server/admin side, not the user side.
  let detail = "";
  const err = cache.last_error || "";
  if (err === "no_directory_server_url_configured") {
    detail = "This client was not configured at install time. Run tools/install_client.py http://&lt;directory-server&gt;:7071 and restart proxy_client.";
  } else if (err === "signature_mismatch_check_pinned_key") {
    detail = "Signature mismatch — the pinned directory signing key on this machine does not match the directory server's current key. Re-run tools/install_client.py http://&lt;directory-server&gt;:7071 and restart proxy_client.";
  } else if (err === "response_stale") {
    detail = "The directory response was older than the maximum acceptable age. Check that the directory-server clock is in sync with this machine.";
  } else if (err === "response_missing_signature") {
    detail = "The directory server returned a response without a signature. The directory server may be running an older build.";
  } else if (err === "remote_payload_malformed") {
    detail = "The directory server returned a malformed payload.";
  } else if (err && err.startsWith("fetch_failed")) {
    detail = "The directory server is unreachable: " + escapeHtml(err) + ". Check that the directory server process is running and that the network/firewall allows this machine to connect to it.";
  } else {
    detail = "The directory cache source is currently '" + escapeHtml(String(cache.source || "uninitialized")) + "', so contributors registered live will not appear here yet. The next refresh cycle should restore live data; if not, check the directory server logs.";
  }
  if (els.directoryCacheBannerDetail) {
    els.directoryCacheBannerDetail.innerHTML = detail;
  }
  els.directoryCacheBanner.classList.remove("hidden");
}

function updateContributorSettingsVisibility() {
  const contributeOn = !!els.contributorToggle?.checked;
  const contributorPathOn = !!els.contributorPathToggle?.checked;
  if (els.contributorSettings) {
    els.contributorSettings.classList.toggle("hidden", !(contributeOn || contributorPathOn));
  }
  if (els.contributorPathOptions) {
    els.contributorPathOptions.classList.toggle("hidden", !contributorPathOn);
  }
}

function renderDashboard(d) {
  latestDashboard = d;
  const status = d.status || {};
  const route = d.route || {};
  const stats = d.stats || {};
  const auto = d.auto_rotate || {};
  const dir = d.directory || {};
  const ui = d.ui || {};
  const relay = d.relay_health || {};
  const sec = d.security || {};

  updateBadge(true, !!status.enabled);
  els.routingState.textContent = status.enabled ? "Enabled" : "Disabled";
  els.apiState.textContent = "Online";
  els.proxyValue.textContent = `${status.proxy_host}:${status.proxy_port}`;
  els.controlValue.textContent = `${status.control_host}:${status.control_port}`;
  els.routeBox.innerHTML = renderRoute(route.route || []);
  els.circuitId.textContent = route.circuit_id || "-";
  els.rotationCountdown.textContent = formatDuration(auto.seconds_until_rotation);
  els.rotationMode.textContent = ui.rotation_mode || "-";
  els.routeModeLabel.textContent = ui.route_mode || "Official Path";
  els.previousCircuit.textContent = ui.previous_circuit_id || "None";
  els.policyLabel.textContent = ui.routing_policy || "-";
  els.activeSessions.textContent = String(stats.active_sessions || 0);
  els.totalSessions.textContent = String(stats.total_sessions_opened || 0);
  els.bytesUp.textContent = formatBytes(stats.total_bytes_from_browser || 0);
  els.bytesDown.textContent = formatBytes(stats.total_bytes_to_browser || 0);
  els.uptime.textContent = formatDuration(stats.uptime_seconds || 0);
  els.keyExchangeLabel.textContent = sec.key_exchange || "X25519-HKDF-SHA256";
  els.paddingLabel.textContent = sec.onion_padding || "Off";
  els.paddingToggle.checked = !!sec.padding_enabled;
  els.contributorToggle.checked = !!sec.contributor_mode_enabled;
  if (els.contributorStatus) {
    els.contributorStatus.textContent = sec.contributor_mode_enabled
      ? `Contributing as ${sec.local_contributor_id || "contributor middle"}`
      : "Not contributing";
  }
  if (els.contributorPathToggle) els.contributorPathToggle.checked = !!sec.contributor_path_enabled;
  if (els.contributorHopSelect) els.contributorHopSelect.value = String(sec.contributor_path_hops || 1);
  if (els.onlineContributorCount) els.onlineContributorCount.textContent = String(sec.online_contributor_count || 0);
  // Render the read-only directory server status line. The URL is baked
  // at install time via tools/install_client.py — there is nothing for
  // the user to edit here.
  if (els.directoryServerStatusLine) {
    const url = sec.directory_server_url || "";
    if (url) {
      const cache = d.directory_cache || {};
      const live = cache.source === "directory_server";
      const dot = live ? "🟢" : "🔴";
      els.directoryServerStatusLine.textContent = `${dot} ${url} ${live ? "(live)" : "(unreachable)"}`;
    } else {
      els.directoryServerStatusLine.textContent = "⚠ Not configured. Run tools/install_client.py http://<directory-server>:7071";
    }
  }
  if (els.contributorPathStatus) {
    const current = sec.current_contributor_count || 0;
    els.contributorPathStatus.textContent = sec.contributor_path_enabled
      ? `Contributor Path on. Requested ${sec.contributor_path_hops || 1} hop(s); current route uses ${current}.`
      : "Contributor Path is off. Official Entry → Middle → Exit route is used.";
  }

  updateContributorSettingsVisibility();
  populateEntrySelect(dir, route.selected_entry_id || status.selected_entry_id || dir.selected_entry_id);
  renderRelayPool(els.entryRelayPool, relay.entries || []);
  renderRelayPool(els.middleRelayPool, relay.middles || []);
  renderRelayPool(els.exitRelayPool, relay.exits || []);
  renderVisitedSites(d.sessions || []);
  renderSessions(d.sessions || []);
  updateHttpWarning(d.sessions || []);
  updateDirectoryCacheBanner(d.directory_cache);
  els.autoRotateMode.value = auto.enabled ? "on" : "off";
  els.rotateIntervalSelect.value = String(auto.interval_seconds || 300);
  startCountdown();
}

async function refreshAll() {
  try {
    const dashboard = await apiGet("/dashboard");
    renderDashboard(dashboard);
  } catch (err) {
    updateBadge(false, false);
    els.routingState.textContent = "Unknown";
    els.apiState.textContent = "Offline";
    showMessage(`Control API error: ${err.message}`, true);
  }
}

async function handleEnable() {
  clearMessage();
  const apiResponse = await apiPost("/enable");
  showMessage(`${apiResponse.message || "Enabled"} — make sure the Windows system proxy is set to 127.0.0.1:8080.`);
  await refreshAll();
}

async function handleDisable() {
  clearMessage();
  const apiResponse = await apiPost("/disable");
  showMessage(`${apiResponse.message || "Disabled"} — if the system proxy is still on, browsing will fail closed until routing is enabled again or the proxy is turned off.`);
  await refreshAll();
}

async function handleApplyEntry() {
  clearMessage();
  const id = els.entrySelect.value;
  const res = await apiPost("/set-entry", { entry_id: id });
  showMessage(res.message || (id ? "Entry applied" : "Entry preference cleared"));
  await refreshAll();
}

async function handleNewCircuit() {
  clearMessage();
  const res = await apiPost("/new-circuit");
  showMessage(`New route built: ${res.circuit_id}`);
  await refreshAll();
}

async function handleResetSessions() {
  clearMessage();
  const res = await apiPost("/reset-sessions");
  showMessage(res.message || "Active sessions closed and session history cleared");
  await refreshAll();
}

async function handleApplyRotate() {
  clearMessage();
  const enabled = els.autoRotateMode.value === "on";
  const interval_seconds = parseInt(els.rotateIntervalSelect.value, 10);
  const res = await apiPost("/set-auto-rotate", { enabled, interval_seconds });
  showMessage(res.message || "Rotation updated");
  await refreshAll();
}

async function handlePaddingToggle() {
  clearMessage();
  const enabled = !!els.paddingToggle.checked;
  await apiPost("/set-padding", { enabled, cell_size: 16384 });
  showMessage(enabled ? "Fixed-size cell padding enabled" : "Fixed-size cell padding disabled");
  await refreshAll();
}

async function handleContributorToggle() {
  clearMessage();
  const enabled = !!els.contributorToggle.checked;
  const body = { enabled };
  if (enabled) {
    if (els.contributorHost?.value.trim()) body.public_host = els.contributorHost.value.trim();
    if (els.contributorPort?.value.trim()) body.port = parseInt(els.contributorPort.value.trim(), 10) || 9022;
  }
  const res = await apiPost("/set-contributor-mode", body);
  showMessage(res.message || (enabled ? "Contributor middle relay enabled" : "Contributor middle relay disabled"));
  await refreshAll();
}

async function handleContributorPathChange() {
  clearMessage();
  const enabled = !!els.contributorPathToggle.checked;
  const hops = parseInt(els.contributorHopSelect.value, 10) || 1;
  const body = { enabled, hops };
  const res = await apiPost("/set-contributor-path", body);
  showMessage(res.message || (enabled ? `Contributor Path enabled with ${hops} hop(s)` : "Contributor Path disabled"));
  await refreshAll();
}

function on(el, event, fn) {
  if (el) el.addEventListener(event, () => fn().catch(e => showMessage(e.message, true)));
}

on(els.enableBtn, "click", handleEnable);
on(els.disableBtn, "click", handleDisable);
on(els.newCircuitBtn, "click", handleNewCircuit);
on(els.refreshBtn, "click", refreshAll);
on(els.resetSessionsBtn, "click", handleResetSessions);
on(els.applyEntryBtn, "click", handleApplyEntry);
on(els.applyRotateBtn, "click", handleApplyRotate);
on(els.paddingToggle, "change", handlePaddingToggle);
on(els.contributorToggle, "change", handleContributorToggle);
on(els.contributorPathToggle, "change", handleContributorPathChange);
on(els.contributorHopSelect, "change", handleContributorPathChange);

if (els.contributorToggle) els.contributorToggle.addEventListener("change", updateContributorSettingsVisibility);
if (els.contributorPathToggle) els.contributorPathToggle.addEventListener("change", updateContributorSettingsVisibility);

function updateSystemProxyNotice() {
  if (!els.systemProxyConfirmed || !els.systemProxyNotice) return;

  const confirmed = !!els.systemProxyConfirmed.checked;

  localStorage.setItem("onionSystemProxyConfirmed", confirmed ? "1" : "0");

  els.systemProxyNotice.classList.toggle("confirmed", confirmed);

  if (els.systemProxyNoticeTitle) {
    els.systemProxyNoticeTitle.textContent = confirmed
      ? "System proxy confirmed"
      : "System proxy required";
  }

  if (els.systemProxyNoticeText) {
    els.systemProxyNoticeText.innerHTML = confirmed
      ? 'Traffic should enter the onion network through <span class="mono">127.0.0.1:8080</span>. If sessions stay at 0, re-check Windows proxy settings.'
      : 'To send browser traffic into the onion network, turn on the system proxy manually: <span class="mono">127.0.0.1:8080</span>. The Enable button starts the onion-routing engine; it does not change Windows proxy settings.';
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  if (els.systemProxyConfirmed) {
    els.systemProxyConfirmed.checked = localStorage.getItem("onionSystemProxyConfirmed") === "1";
    els.systemProxyConfirmed.addEventListener("change", updateSystemProxyNotice);
    updateSystemProxyNotice();
  }

  // Note: the directory server URL is now baked into the client at install
  // time via tools/install_client.py. The popup no longer offers a URL
  // input field; users do not need to know or type the URL.

  updateContributorSettingsVisibility();
  await refreshAll();
  setInterval(refreshAll, 4000);
});
