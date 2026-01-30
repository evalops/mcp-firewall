const statusPill = document.getElementById("status-pill");
const sandboxPill = document.getElementById("sandbox-pill");
const upstreamEl = document.getElementById("upstream");
const dryRunEl = document.getElementById("dry-run");
const inspectEl = document.getElementById("inspection");
const policyTotalsEl = document.getElementById("policy-totals");
const modeEl = document.getElementById("mode");
const sandboxStatusEl = document.getElementById("sandbox-status");
const toggleBtn = document.getElementById("toggle-firewall");
const toggleHint = document.getElementById("toggle-hint");
const policyEditor = document.getElementById("policy-editor");
const policyHint = document.getElementById("policy-hint");
const policyMessage = document.getElementById("policy-message");
const policyWarnings = document.getElementById("policy-warnings");
const setTokenBtn = document.getElementById("set-token");
const templateList = document.getElementById("template-list");
const schemaEl = document.getElementById("policy-schema");
const notesEl = document.getElementById("policy-notes");
const historyList = document.getElementById("history-list");
const chartGroup = document.getElementById("chart-group");
const chartContainer = document.getElementById("blocked-chart");
const chartHint = document.getElementById("chart-hint");
const logTableBody = document.getElementById("log-table-body");
const filterDecision = document.getElementById("log-filter-decision");
const filterMethod = document.getElementById("log-filter-method");
const filterTarget = document.getElementById("log-filter-target");
const openLibraryBtn = document.getElementById("open-library");
const closeLibraryBtn = document.getElementById("close-library");
const libraryModal = document.getElementById("library-modal");
const openDiffBtn = document.getElementById("open-diff");
const closeDiffBtn = document.getElementById("close-diff");
const diffModal = document.getElementById("diff-modal");
const diffCurrent = document.getElementById("diff-current");
const diffSelected = document.getElementById("diff-selected");
const savePresetBtn = document.getElementById("save-preset");
const openPresetsBtn = document.getElementById("load-presets");
const closePresetsBtn = document.getElementById("close-presets");
const presetModal = document.getElementById("preset-modal");
const presetList = document.getElementById("preset-list");
const exportLogsBtn = document.getElementById("export-logs");
const exportChartBtn = document.getElementById("export-chart");
const savePolicyBtn = document.getElementById("save-policy");
const reloadPolicyBtn = document.getElementById("reload-policy");
const clearLogsBtn = document.getElementById("clear-logs");

const MAX_LOGS = 500;
const PRESET_KEY = "mcpFirewallLogPresets";
const STREAM_RETRY_MAX = 30000;
const MAX_DIFF_CELLS = 200000;

let policyWritable = false;
let logs = [];
let baselinePolicy = "";
let authToken = localStorage.getItem("mcpFirewallToken") || "";
let logSource = null;
let warningTimer = null;
let presets = loadPresets();
let streamRetryMs = 1000;
let streamRetryTimer = null;
let enforcementEnabled = true;

function setStatusPill(text) {
  if (statusPill.textContent === "Auth required") {
    return;
  }
  statusPill.textContent = text;
}

function apiHeaders(extra = {}) {
  const headers = { ...extra };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }
  return headers;
}

async function apiFetch(url, options = {}) {
  const opts = { ...options };
  opts.headers = apiHeaders(opts.headers || {});
  const res = await fetch(url, opts);
  if (res.status === 401) {
    statusPill.textContent = "Auth required";
  }
  return res;
}

function promptToken() {
  const token = window.prompt("Enter API token");
  if (token === null) {
    return;
  }
  authToken = token.trim();
  if (authToken) {
    localStorage.setItem("mcpFirewallToken", authToken);
  } else {
    localStorage.removeItem("mcpFirewallToken");
  }
  reconnectStreams();
}

async function loadStatus() {
  const res = await apiFetch("/api/status");
  if (!res.ok) {
    setStatusPill("Offline");
    return;
  }
  const data = await res.json();
  setStatusPill(data.ready ? "Online" : "Starting");
  upstreamEl.textContent = data.upstream || "-";
  dryRunEl.textContent = data.dryRun ? "Enabled" : "Disabled";
  inspectEl.textContent = data.inspectEnabled ? `On (>= ${data.inspectThreshold})` : "Off";
  policyTotalsEl.textContent = `${data.tools} tools - ${data.resources} resources - ${data.prompts} prompts`;
  modeEl.textContent = data.mode || "stdio";
  const noNetwork = !!data.noNetwork;
  const allowedBins = Array.isArray(data.allowedBins) ? data.allowedBins : [];
  const bestEffort = !!data.sandboxBestEffort;
  const sandboxParts = [];
  if (noNetwork) {
    sandboxParts.push("no network");
  }
  if (allowedBins.length > 0) {
    sandboxParts.push(`allowlist ${allowedBins.length}`);
  }
  if (sandboxParts.length === 0) {
    sandboxStatusEl.textContent = "Off";
  } else {
    sandboxStatusEl.textContent = `${sandboxParts.join(" + ")}${bestEffort ? " (best-effort)" : ""}`;
  }
  if (noNetwork) {
    sandboxPill.textContent = bestEffort ? "No network (best-effort)" : "No network";
    sandboxPill.style.display = "inline-flex";
  } else {
    sandboxPill.style.display = "none";
  }
  enforcementEnabled = data.enforcementEnabled !== false;
  const toggleFile = data.toggleFile || "";
  if (!toggleFile) {
    toggleBtn.disabled = true;
    toggleBtn.textContent = "Always on";
    toggleHint.textContent = "No toggle file configured.";
  } else {
    toggleBtn.disabled = false;
    toggleBtn.textContent = enforcementEnabled ? "Disable firewall" : "Enable firewall";
    toggleHint.textContent = enforcementEnabled
      ? `Enforcing policy (toggle: ${toggleFile})`
      : `Bypassing policy (toggle: ${toggleFile})`;
  }
  policyWritable = data.policyWritable;
  policyEditor.readOnly = !policyWritable;
  savePolicyBtn.disabled = !policyWritable;
  updatePolicyHint();
}

async function loadPolicy() {
  const res = await apiFetch("/api/policy");
  if (!res.ok) {
    policyEditor.value = "# Unable to load policy";
    return;
  }
  baselinePolicy = await res.text();
  policyEditor.value = baselinePolicy;
  policyMessage.textContent = "";
  scheduleWarnings();
  updatePolicyHint();
  renderDiffIfOpen();
}

function renderLogTable() {
  logTableBody.innerHTML = "";
  const filtered = filterLogs(logs);
  if (filtered.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No matching events.";
    row.appendChild(cell);
    logTableBody.appendChild(row);
    return;
  }
  filtered.slice().reverse().forEach((log) => {
    const row = document.createElement("tr");
    const decision = document.createElement("td");
    decision.textContent = log.decision || "";
    const method = document.createElement("td");
    method.textContent = log.method || "";
    const target = document.createElement("td");
    target.textContent = log.name || log.uri || "";
    const reason = document.createElement("td");
    reason.textContent = log.reason || "";
    const ts = document.createElement("td");
    ts.textContent = log.ts || "";
    row.appendChild(decision);
    row.appendChild(method);
    row.appendChild(target);
    row.appendChild(reason);
    row.appendChild(ts);
    logTableBody.appendChild(row);
  });
}

function filterLogs(items) {
  const decisionFilter = filterDecision.value;
  const methodFilter = (filterMethod.value || "").toLowerCase();
  const targetFilter = (filterTarget.value || "").toLowerCase();

  return items.filter((log) => {
    if (decisionFilter !== "all" && log.decision !== decisionFilter) {
      return false;
    }
    const method = (log.method || "").toLowerCase();
    const target = (log.name || log.uri || "").toLowerCase();
    if (methodFilter && !method.includes(methodFilter)) {
      return false;
    }
    if (targetFilter && !target.includes(targetFilter)) {
      return false;
    }
    return true;
  });
}

function appendLog(event) {
  logs.push(event);
  if (logs.length > MAX_LOGS) {
    logs = logs.slice(logs.length - MAX_LOGS);
  }
  renderLogTable();
  renderChart();
}

function connectLogStream(reset = true) {
  if (logSource) {
    logSource.close();
  }
  if (streamRetryTimer) {
    clearTimeout(streamRetryTimer);
    streamRetryTimer = null;
  }
  if (reset) {
    logs = [];
    renderLogTable();
    renderChart();
  }
  streamRetryMs = 1000;
  openLogStream();
}

function openLogStream() {
  if (logSource) {
    logSource.close();
  }
  const tokenParam = authToken ? `&token=${encodeURIComponent(authToken)}` : "";
  const url = `/api/logs/stream?limit=${MAX_LOGS}${tokenParam}`;
  logSource = new EventSource(url);
  logSource.addEventListener("open", () => {
    streamRetryMs = 1000;
    setStatusPill("Online");
  });
  logSource.addEventListener("log", (event) => {
    try {
      const payload = JSON.parse(event.data);
      appendLog(payload);
    } catch (err) {
      // ignore parse errors
    }
  });
  logSource.onerror = () => {
    if (logSource) {
      logSource.close();
      logSource = null;
    }
    scheduleStreamReconnect();
  };
}

function scheduleStreamReconnect() {
  if (streamRetryTimer) {
    return;
  }
  const wait = streamRetryMs;
  setStatusPill(`Stream offline - retrying in ${Math.round(wait / 1000)}s`);
  streamRetryTimer = setTimeout(() => {
    streamRetryTimer = null;
    openLogStream();
  }, wait);
  streamRetryMs = Math.min(streamRetryMs * 2, STREAM_RETRY_MAX);
}

function reconnectStreams() {
  connectLogStream();
  loadStatus();
  loadPolicy();
  loadHistory();
}

async function savePolicy() {
  if (!policyWritable) {
    policyMessage.textContent = "Policy is read-only.";
    return;
  }
  policyMessage.textContent = "";
  const res = await apiFetch("/api/policy", {
    method: "POST",
    headers: { "Content-Type": "text/yaml" },
    body: policyEditor.value,
  });
  if (!res.ok) {
    const text = await res.text();
    policyMessage.textContent = text || "Save failed.";
    return;
  }
  policyMessage.textContent = "Saved.";
  baselinePolicy = policyEditor.value;
  updatePolicyHint();
  renderDiffIfOpen();
  await loadStatus();
  await loadHistory();
}

async function toggleFirewall() {
  if (toggleBtn.disabled) {
    return;
  }
  const desired = !enforcementEnabled;
  const res = await apiFetch("/api/toggle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: desired }),
  });
  if (!res.ok) {
    const text = await res.text();
    policyMessage.textContent = text || "Failed to toggle firewall.";
    return;
  }
  await loadStatus();
}

function updatePolicyHint() {
  const diff = countLineDiff(baselinePolicy, policyEditor.value);
  const diffLabel = diff === 0 ? "No changes" : `${diff} line${diff === 1 ? "" : "s"} changed`;
  policyHint.textContent = policyWritable
    ? `Editing is live. Save will update the running policy. - ${diffLabel}`
    : `Read-only unless policy writes are enabled. - ${diffLabel}`;
}

function countLineDiff(a, b) {
  if (a === b) {
    return 0;
  }
  const aLines = a.split(/\r?\n/);
  const bLines = b.split(/\r?\n/);
  const max = Math.max(aLines.length, bLines.length);
  let diff = 0;
  for (let i = 0; i < max; i += 1) {
    if (aLines[i] !== bLines[i]) {
      diff += 1;
    }
  }
  return diff;
}

function scheduleWarnings() {
  if (warningTimer) {
    clearTimeout(warningTimer);
  }
  warningTimer = setTimeout(runWarnings, 400);
}

function runWarnings() {
  const warnings = computeWarnings(policyEditor.value);
  if (warnings.length === 0) {
    policyWarnings.style.display = "none";
    policyWarnings.textContent = "";
    return;
  }
  policyWarnings.style.display = "block";
  policyWarnings.innerHTML = warnings.map((w) => `* ${w}`).join("<br/>");
}

function computeWarnings(text) {
  const lines = text.split(/\r?\n/);
  let section = "";
  let subsection = "";
  let hasAnyRule = false;
  let hasToolsRules = false;
  let hasResourceRules = false;
  const allowSchemes = [];
  const allowWildcards = [];

  lines.forEach((line) => {
    const stripped = line.split("#")[0];
    if (!stripped.trim()) {
      return;
    }
    const indent = stripped.match(/^\s*/)[0].length;
    const trimmed = stripped.trim();
    if (indent === 0 && trimmed.endsWith(":")) {
      section = trimmed.slice(0, -1);
      subsection = "";
      return;
    }
    if (indent > 0 && trimmed.endsWith(":")) {
      subsection = trimmed.slice(0, -1);
      return;
    }
    if (trimmed.startsWith("-")) {
      const value = trimmed.slice(1).trim().replace(/^"|"$/g, "");
      hasAnyRule = true;
      if (section === "tools" && (subsection === "allow" || subsection === "deny")) {
        hasToolsRules = true;
      }
      if (section === "resources") {
        hasResourceRules = true;
        if (subsection === "allow_schemes") {
          allowSchemes.push(value.toLowerCase());
        }
      }
      if (subsection === "allow" && (value.includes("*") || value.includes("?"))) {
        allowWildcards.push(section || "unknown");
      }
    }
  });

  const warnings = [];
  if (!hasAnyRule) {
    warnings.push("Policy has no allow/deny rules; everything is permitted.");
  }
  if (!hasToolsRules) {
    warnings.push("Tools rules are empty; all tools are allowed.");
  }
  if (!hasResourceRules) {
    warnings.push("Resources rules are empty; all resources are allowed.");
  }
  if (allowSchemes.includes("http") || allowSchemes.includes("https")) {
    warnings.push("Resource allow_schemes includes http/https (external content).");
  }
  if (allowSchemes.includes("smtp") || allowSchemes.includes("imap")) {
    warnings.push("Resource allow_schemes includes mail protocols.");
  }
  if (allowWildcards.length > 0) {
    warnings.push("Allow lists contain wildcard entries.");
  }
  return warnings;
}

async function loadTemplates() {
  const res = await apiFetch("/api/policy/templates");
  if (!res.ok) {
    return;
  }
  const data = await res.json();
  const templates = data.templates || [];
  templateList.innerHTML = "";
  if (templates.length === 0) {
    templateList.textContent = "No templates available.";
    return;
  }
  templates.forEach((tpl) => {
    const card = document.createElement("div");
    card.className = "template-card";
    const title = document.createElement("h4");
    title.textContent = tpl.name || tpl.id;
    const desc = document.createElement("p");
    desc.textContent = tpl.description || "";
    const actions = document.createElement("div");
    actions.className = "actions";
    const applyBtn = document.createElement("button");
    applyBtn.className = "ghost";
    applyBtn.textContent = "Apply";
    applyBtn.addEventListener("click", () => {
      policyEditor.value = tpl.yaml || "";
      policyMessage.textContent = `Template applied: ${tpl.name || tpl.id}`;
      scheduleWarnings();
      updatePolicyHint();
      renderDiffIfOpen();
    });
    actions.appendChild(applyBtn);
    card.appendChild(title);
    card.appendChild(desc);
    card.appendChild(actions);
    templateList.appendChild(card);
  });
}

async function loadHelp() {
  const res = await apiFetch("/api/policy/help");
  if (!res.ok) {
    return;
  }
  const data = await res.json();
  schemaEl.textContent = data.schema || "";
  notesEl.innerHTML = "";
  (data.notes || []).forEach((note) => {
    const li = document.createElement("li");
    li.textContent = note;
    notesEl.appendChild(li);
  });
}

async function loadHistory() {
  const res = await apiFetch("/api/policy/history?limit=25");
  if (!res.ok) {
    return;
  }
  const data = await res.json();
  const history = data.history || [];
  const current = data.current || "";
  historyList.innerHTML = "";
  if (history.length === 0) {
    historyList.textContent = "No history yet.";
    return;
  }
  history.forEach((snap) => {
    const card = document.createElement("div");
    card.className = "history-card";
    const title = document.createElement("h4");
    const currentLabel = snap.id === current ? " (current)" : "";
    title.textContent = `${snap.reason || "snapshot"} - ${snap.ts}${currentLabel}`;
    const meta = document.createElement("p");
    meta.textContent = `tools ${snap.tools}, resources ${snap.resources}, prompts ${snap.prompts}`;
    const actions = document.createElement("div");
    actions.className = "actions";
    const loadBtn = document.createElement("button");
    loadBtn.className = "ghost";
    loadBtn.textContent = "Load";
    loadBtn.addEventListener("click", () => loadHistoryVersion(snap.id));
    const rollbackBtn = document.createElement("button");
    rollbackBtn.className = "primary";
    rollbackBtn.textContent = "Rollback";
    if (!policyWritable) {
      rollbackBtn.disabled = true;
    } else {
      rollbackBtn.addEventListener("click", () => rollbackHistory(snap.id));
    }
    actions.appendChild(loadBtn);
    actions.appendChild(rollbackBtn);
    card.appendChild(title);
    card.appendChild(meta);
    card.appendChild(actions);
    historyList.appendChild(card);
  });
}

async function loadHistoryVersion(id) {
  const res = await apiFetch(`/api/policy/history/${id}`);
  if (!res.ok) {
    policyMessage.textContent = "Failed to load history entry.";
    return;
  }
  const text = await res.text();
  policyEditor.value = text;
  policyMessage.textContent = `Loaded history ${id}`;
  scheduleWarnings();
  updatePolicyHint();
  renderDiffIfOpen();
}

async function rollbackHistory(id) {
  if (!policyWritable) {
    policyMessage.textContent = "Policy is read-only.";
    return;
  }
  const ok = window.confirm(`Rollback to ${id}?`);
  if (!ok) {
    return;
  }
  const res = await apiFetch("/api/policy/rollback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id }),
  });
  if (!res.ok) {
    const text = await res.text();
    policyMessage.textContent = text || "Rollback failed.";
    return;
  }
  policyMessage.textContent = "Rollback complete.";
  await loadPolicy();
  await loadHistory();
  await loadStatus();
}

function chartData() {
  const group = chartGroup.value;
  const filtered = logs.filter((log) => log.decision === "blocked" || log.decision === "would_block");
  const counts = {};
  filtered.forEach((log) => {
    const key = group === "method" ? log.method || "(none)" : log.name || log.uri || "(none)";
    counts[key] = (counts[key] || 0) + 1;
  });
  const entries = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  return { group, entries, total: filtered.length };
}

function renderChart() {
  const data = chartData();
  chartContainer.innerHTML = "";
  if (data.entries.length === 0) {
    chartContainer.textContent = "No blocked events yet.";
    chartHint.textContent = "Waiting for blocked events.";
    return;
  }
  const max = data.entries[0][1] || 1;
  data.entries.forEach(([label, count]) => {
    const row = document.createElement("div");
    row.className = "chart-row";
    const labelEl = document.createElement("div");
    labelEl.className = "label";
    labelEl.textContent = label;
    const bar = document.createElement("div");
    bar.className = "chart-bar";
    const fill = document.createElement("span");
    fill.style.width = `${Math.round((count / max) * 100)}%`;
    bar.appendChild(fill);
    const value = document.createElement("div");
    value.textContent = count;
    row.appendChild(labelEl);
    row.appendChild(bar);
    row.appendChild(value);
    chartContainer.appendChild(row);
  });
  chartHint.textContent = `Top ${data.entries.length} of ${data.total} blocked events.`;
}

function openModal(modal) {
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
}

function closeModal(modal) {
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
}

function openLibrary() {
  openModal(libraryModal);
}

function closeLibrary() {
  closeModal(libraryModal);
}

function openDiff() {
  closeLibrary();
  renderDiff();
  openModal(diffModal);
}

function closeDiff() {
  closeModal(diffModal);
}

function openPresets() {
  renderPresets();
  openModal(presetModal);
}

function closePresets() {
  closeModal(presetModal);
}

function renderDiffIfOpen() {
  if (diffModal.classList.contains("open")) {
    renderDiff();
  }
}

function renderDiff() {
  const currentLines = baselinePolicy.split(/\r?\n/);
  const selectedLines = policyEditor.value.split(/\r?\n/);
  diffCurrent.innerHTML = "";
  diffSelected.innerHTML = "";
  const diff = diffLines(currentLines, selectedLines);
  diff.left.forEach((line) => appendDiffLine(diffCurrent, line));
  diff.right.forEach((line) => appendDiffLine(diffSelected, line));
}

function appendDiffLine(container, line) {
  const span = document.createElement("span");
  span.className = "line";
  if (line.type && line.type !== "same") {
    span.classList.add(line.type);
  }
  span.textContent = line.text || "";
  container.appendChild(span);
}

function diffLines(currentLines, selectedLines) {
  if (currentLines.length === 0 && selectedLines.length === 0) {
    return { left: [], right: [] };
  }
  if (currentLines.length * selectedLines.length > MAX_DIFF_CELLS) {
    return fallbackDiff(currentLines, selectedLines);
  }
  const rows = currentLines.length + 1;
  const cols = selectedLines.length + 1;
  const dp = Array.from({ length: rows }, () => new Array(cols).fill(0));
  for (let i = rows - 2; i >= 0; i -= 1) {
    for (let j = cols - 2; j >= 0; j -= 1) {
      if (currentLines[i] === selectedLines[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }
  let i = 0;
  let j = 0;
  const left = [];
  const right = [];
  while (i < currentLines.length && j < selectedLines.length) {
    if (currentLines[i] === selectedLines[j]) {
      left.push({ text: currentLines[i], type: "same" });
      right.push({ text: selectedLines[j], type: "same" });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      left.push({ text: currentLines[i], type: "removed" });
      right.push({ text: "", type: "empty" });
      i += 1;
    } else {
      left.push({ text: "", type: "empty" });
      right.push({ text: selectedLines[j], type: "added" });
      j += 1;
    }
  }
  while (i < currentLines.length) {
    left.push({ text: currentLines[i], type: "removed" });
    right.push({ text: "", type: "empty" });
    i += 1;
  }
  while (j < selectedLines.length) {
    left.push({ text: "", type: "empty" });
    right.push({ text: selectedLines[j], type: "added" });
    j += 1;
  }
  return { left, right };
}

function fallbackDiff(currentLines, selectedLines) {
  const max = Math.max(currentLines.length, selectedLines.length);
  const left = [];
  const right = [];
  for (let i = 0; i < max; i += 1) {
    const currentLine = currentLines[i] || "";
    const selectedLine = selectedLines[i] || "";
    if (currentLine === selectedLine) {
      left.push({ text: currentLine, type: "same" });
      right.push({ text: selectedLine, type: "same" });
      continue;
    }
    left.push({ text: currentLine, type: currentLine ? "removed" : "empty" });
    right.push({ text: selectedLine, type: selectedLine ? "added" : "empty" });
  }
  return { left, right };
}

function loadPresets() {
  try {
    const raw = localStorage.getItem(PRESET_KEY);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed;
    }
  } catch (err) {
    // ignore parsing errors
  }
  return [];
}

function savePresets() {
  localStorage.setItem(PRESET_KEY, JSON.stringify(presets));
}

function renderPresets() {
  presetList.innerHTML = "";
  if (presets.length === 0) {
    presetList.textContent = "No presets saved.";
    return;
  }
  presets.forEach((preset) => {
    const card = document.createElement("div");
    card.className = "preset-card";
    const title = document.createElement("h4");
    title.textContent = preset.name;
    const meta = document.createElement("p");
    meta.textContent = `decision ${preset.decision || "all"}, method ${preset.method || "*"}, target ${preset.target || "*"}`;
    const actions = document.createElement("div");
    actions.className = "actions";
    const applyBtn = document.createElement("button");
    applyBtn.className = "primary";
    applyBtn.textContent = "Apply";
    applyBtn.addEventListener("click", () => {
      filterDecision.value = preset.decision || "all";
      filterMethod.value = preset.method || "";
      filterTarget.value = preset.target || "";
      renderLogTable();
      renderChart();
      closePresets();
    });
    const deleteBtn = document.createElement("button");
    deleteBtn.className = "ghost";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => {
      presets = presets.filter((item) => item.name !== preset.name);
      savePresets();
      renderPresets();
    });
    actions.appendChild(applyBtn);
    actions.appendChild(deleteBtn);
    card.appendChild(title);
    card.appendChild(meta);
    card.appendChild(actions);
    presetList.appendChild(card);
  });
}

function savePreset() {
  const name = window.prompt("Preset name");
  if (!name) {
    return;
  }
  const trimmed = name.trim();
  if (!trimmed) {
    return;
  }
  const preset = {
    name: trimmed,
    decision: filterDecision.value,
    method: filterMethod.value,
    target: filterTarget.value,
  };
  const existing = presets.find((item) => item.name === trimmed);
  if (existing) {
    const ok = window.confirm(`Overwrite preset "${trimmed}"?`);
    if (!ok) {
      return;
    }
    existing.decision = preset.decision;
    existing.method = preset.method;
    existing.target = preset.target;
  } else {
    presets.unshift(preset);
  }
  savePresets();
}

function csvEscape(value) {
  if (value === null || value === undefined) {
    return "";
  }
  const str = String(value);
  if (str.includes("\n") || str.includes("\r") || str.includes(",") || str.includes('"')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function downloadCSV(filename, rows) {
  const csv = rows.map((row) => row.map(csvEscape).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function exportLogs() {
  const filtered = filterLogs(logs);
  const rows = [
    [
      "ts",
      "decision",
      "method",
      "name",
      "uri",
      "reason",
      "direction",
      "id",
      "suspicionScore",
      "suspicionFlags",
      "suspicionExcerpt",
    ],
  ];
  filtered.forEach((log) => {
    rows.push([
      log.ts || "",
      log.decision || "",
      log.method || "",
      log.name || "",
      log.uri || "",
      log.reason || "",
      log.direction || "",
      log.id || "",
      log.suspicionScore || "",
      Array.isArray(log.suspicionFlags) ? log.suspicionFlags.join("|") : "",
      log.suspicionExcerpt || "",
    ]);
  });
  const stamp = new Date().toISOString().slice(0, 10);
  downloadCSV(`mcp-firewall-logs-${stamp}.csv`, rows);
}

function exportChart() {
  const data = chartData();
  const rows = [["group", "label", "count"]];
  data.entries.forEach(([label, count]) => {
    rows.push([data.group, label, count]);
  });
  const stamp = new Date().toISOString().slice(0, 10);
  downloadCSV(`mcp-firewall-blocked-${data.group}-${stamp}.csv`, rows);
}

function bindControls() {
  savePolicyBtn.addEventListener("click", savePolicy);
  reloadPolicyBtn.addEventListener("click", loadPolicy);
  clearLogsBtn.addEventListener("click", () => {
    logs = [];
    renderLogTable();
    renderChart();
  });
  setTokenBtn.addEventListener("click", promptToken);
  toggleBtn.addEventListener("click", toggleFirewall);
  policyEditor.addEventListener("input", () => {
    updatePolicyHint();
    scheduleWarnings();
    renderDiffIfOpen();
  });
  [chartGroup, filterDecision, filterMethod, filterTarget].forEach((el) => {
    el.addEventListener("input", () => {
      renderLogTable();
      renderChart();
    });
    el.addEventListener("change", () => {
      renderLogTable();
      renderChart();
    });
  });
  openLibraryBtn.addEventListener("click", openLibrary);
  closeLibraryBtn.addEventListener("click", closeLibrary);
  libraryModal.addEventListener("click", (event) => {
    if (event.target === libraryModal) {
      closeLibrary();
    }
  });
  openDiffBtn.addEventListener("click", openDiff);
  closeDiffBtn.addEventListener("click", closeDiff);
  diffModal.addEventListener("click", (event) => {
    if (event.target === diffModal) {
      closeDiff();
    }
  });
  openPresetsBtn.addEventListener("click", openPresets);
  closePresetsBtn.addEventListener("click", closePresets);
  presetModal.addEventListener("click", (event) => {
    if (event.target === presetModal) {
      closePresets();
    }
  });
  savePresetBtn.addEventListener("click", savePreset);
  exportLogsBtn.addEventListener("click", exportLogs);
  exportChartBtn.addEventListener("click", exportChart);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeLibrary();
      closeDiff();
      closePresets();
    }
  });
}

async function init() {
  bindControls();
  await loadStatus();
  await loadPolicy();
  await loadTemplates();
  await loadHelp();
  await loadHistory();
  connectLogStream();
  setInterval(loadStatus, 10000);
}

init();
