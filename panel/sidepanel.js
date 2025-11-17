const TERMS_STORAGE_KEY = "sbde_terms_acceptance";
const TERMS_VERSION = "1.0";
const TERMS_EFFECTIVE_DATE = "2025-11-05";

const storageKeys = {
  connection: "sbde_connection",
  selectedTable: "sbde_currentTable",
  theme: "sbde_theme",
  connectionMeta: "sbde_connection_meta",
};

const ASSET_DETECTIONS_KEY = "sbde_asset_detections";
const LEAK_DETECTIONS_KEY = "sbde_generic_leaks";
const REPORT_STORAGE_KEY = "sbde_security_reports";

const RISK_LEVEL_ORDER = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const REPORT_ANALYSIS_CONCURRENCY = 4; // Limit simultaneous table checks to keep PostgREST responsive.

const state = {
  connection: {
    projectId: "",
    schema: "public",
    apiKey: "",
    bearer: "",
  },
  baseUrl: "",
  openApi: null,
  tables: [],
  tableCounts: {},
  tableCountErrors: {},
  currentTable: null,
  theme: "dark",
  connectionWriteSource: null,
  assetDetections: [],
  leakDetections: [],
  inspectedHost: null,
  isGeneratingReport: false,
  termsAccepted: false,
  hasBootstrappedAfterTerms: false,
  isShareReportOpen: false,
};

const dom = {
  connectionForm: document.getElementById("connection-form"),
  projectId: document.getElementById("project-id"),
  schema: document.getElementById("schema"),
  apiKey: document.getElementById("api-key"),
  bearer: document.getElementById("bearer"),
  connectBtn: document.getElementById("connect-btn"),
  clearStorageBtn: document.getElementById("clear-storage-btn"),
  reloadBtn: document.getElementById("reload-btn"),
  reportBtn: document.getElementById("report-btn"),
  tablesList: document.getElementById("tables-list"),
  connectionStatus: document.getElementById("connection-status"),
  themeToggle: document.getElementById("theme-toggle"),
  themeIcon: document.querySelector(".theme-icon"),
  shareReportModal: document.getElementById("share-report-modal"),
  shareReportBackdrop: document.getElementById("share-report-backdrop"),
  shareReportCloseBtn: document.getElementById("share-report-close-btn"),
  shareReportViewBtn: document.getElementById("share-report-view-btn"),
  shareReportShareBtn: document.getElementById("share-report-share-btn"),
  termsModal: document.getElementById("terms-modal"),
  termsBackdrop: document.getElementById("terms-backdrop"),
  termsBody: document.querySelector(".terms-body"),
  termsAcceptBtn: document.getElementById("terms-accept-btn"),
  termsDeclineBtn: document.getElementById("terms-decline-btn"),
  termsCloseBtn: document.getElementById("terms-close-btn"),
  termsOpenBtn: document.getElementById("terms-open-btn"),
  termsWithdrawBtn: document.getElementById("terms-withdraw-btn"),
  termsFootnote: document.getElementById("terms-footnote"),
};

const sensitiveColumnIndicators = [
  "password",
  "token",
  "secret",
  "email",
  "phone",
  "address",
  "ssn",
  "credit",
  "card",
  "api",
  "key",
  "auth",
  "metadata",
];

let pendingTermsResolve = null;
let pendingTermsPromise = null;

function sanitize(value) {
  return (value || "").trim();
}

function isValidTermsAcceptance(record) {
  return Boolean(record && typeof record.version === "string" && record.version === TERMS_VERSION);
}

async function readTermsAcceptance() {
  const stored = await storageGet(TERMS_STORAGE_KEY);
  return stored?.[TERMS_STORAGE_KEY] || null;
}

function lockTermsScroll(lock) {
  if (!document?.body) {
    return;
  }
  document.body.classList.toggle("terms-locked", lock);
}

function toggleTermsCloseVisibility(enforce) {
  if (!dom.termsCloseBtn) {
    return;
  }
  dom.termsCloseBtn.classList.toggle("hidden", Boolean(enforce));
}

function showTermsModal({ enforce = false, focusBody = true } = {}) {
  if (!dom.termsModal) {
    return;
  }
  dom.termsModal.classList.remove("hidden");
  dom.termsModal.dataset.mode = enforce ? "enforce" : "view";
  toggleTermsCloseVisibility(enforce);
  lockTermsScroll(true);
  if (focusBody && dom.termsBody) {
    dom.termsBody.focus();
  }
}

function hideTermsModal() {
  if (!dom.termsModal) {
    return;
  }
  dom.termsModal.classList.add("hidden");
  dom.termsModal.dataset.mode = "";
  lockTermsScroll(false);
}

function ensureTermsPromise() {
  if (!pendingTermsPromise) {
    pendingTermsPromise = new Promise((resolve) => {
      pendingTermsResolve = resolve;
    });
  }
  return pendingTermsPromise;
}

function updateTermsControls() {
  if (dom.termsWithdrawBtn) {
    dom.termsWithdrawBtn.disabled = !state.termsAccepted;
  }
  if (dom.connectBtn) {
    dom.connectBtn.disabled = !state.termsAccepted;
  }
  if (dom.reloadBtn) {
    dom.reloadBtn.disabled = !state.termsAccepted;
  }
  if (dom.clearStorageBtn) {
    dom.clearStorageBtn.disabled = !state.termsAccepted;
  }
  if (dom.reportBtn && !state.termsAccepted) {
    dom.reportBtn.disabled = true;
    dom.reportBtn.classList.remove("is-busy");
  }
}

function resolvePendingTerms(result) {
  if (pendingTermsResolve) {
    pendingTermsResolve(result);
    pendingTermsResolve = null;
    pendingTermsPromise = null;
  }
}

async function ensureTermsAccepted({ enforce = true } = {}) {
  const record = await readTermsAcceptance();
  const accepted = isValidTermsAcceptance(record);
  state.termsAccepted = accepted;
  updateTermsControls();
  if (accepted) {
    hideTermsModal();
    resolvePendingTerms(true);
    return true;
  }
  if (enforce) {
    showTermsModal({ enforce: true });
    setStatus("Accept the Terms & Conditions to continue.", "error");
    return ensureTermsPromise();
  }
  return false;
}

function enforceTermsAccess({ showModal = true, announce = true } = {}) {
  if (state.termsAccepted) {
    return true;
  }
  if (announce) {
    setStatus("Accept the Terms & Conditions to continue.", "error");
  }
  if (showModal) {
    showTermsModal({ enforce: true, focusBody: false });
  }
  return false;
}

async function handleTermsAccept() {
  if (dom.termsAcceptBtn) {
    dom.termsAcceptBtn.disabled = true;
  }
  try {
    const payload = {
      version: TERMS_VERSION,
      acceptedAt: new Date().toISOString(),
      effectiveDate: TERMS_EFFECTIVE_DATE,
    };
    await storageSet({ [TERMS_STORAGE_KEY]: payload });
    state.termsAccepted = true;
    hideTermsModal();
    resolvePendingTerms(true);
    setStatus("Terms accepted. Ready.", "success");
    updateTermsControls();
    updateReportButtonState();
  } catch (error) {
    console.error("Failed to store terms acceptance", error);
    setStatus("Failed to record acceptance. Try again.", "error");
    state.termsAccepted = false;
    ensureTermsPromise();
  } finally {
    if (dom.termsAcceptBtn) {
      dom.termsAcceptBtn.disabled = false;
    }
  }
}

function handleTermsDecline() {
  setStatus("Terms declined. Disable or remove the extension to stop usage.", "error");
  try {
    window.close();
  } catch (error) {
    // Ignore close failures.
  }
}

async function handleTermsWithdraw() {
  try {
    await storageRemove(TERMS_STORAGE_KEY);
    await storageRemove(storageKeys.connection);
    await storageRemove(storageKeys.selectedTable);
    await storageRemove(storageKeys.connectionMeta);
    await storageRemove(ASSET_DETECTIONS_KEY);
    await storageRemove(LEAK_DETECTIONS_KEY);
    await storageRemove(REPORT_STORAGE_KEY);
  } catch (error) {
    console.error("Failed to withdraw consent", error);
  }
  state.termsAccepted = false;
  state.hasBootstrappedAfterTerms = false;
  markConnectionWriteSource(null);
  applyConnectionToForm(null, { announce: false });
  state.tables = [];
  state.tableCounts = {};
  state.tableCountErrors = {};
  state.currentTable = null;
  state.assetDetections = [];
  state.leakDetections = [];
  state.inspectedHost = null;
  renderTablesList();
  updateReportButtonState();
  updateTermsControls();
  ensureTermsPromise();
  showTermsModal({ enforce: true });
  setStatus("Consent withdrawn. Accept the Terms to resume.", "error");
}

function initTermsUi() {
  if (dom.termsAcceptBtn) {
    dom.termsAcceptBtn.addEventListener("click", handleTermsAccept);
  }
  if (dom.termsDeclineBtn) {
    dom.termsDeclineBtn.addEventListener("click", handleTermsDecline);
  }
  if (dom.termsCloseBtn) {
    dom.termsCloseBtn.addEventListener("click", () => {
      if (state.termsAccepted) {
        hideTermsModal();
      }
    });
  }
  if (dom.termsOpenBtn) {
    dom.termsOpenBtn.addEventListener("click", () => {
      const enforce = !state.termsAccepted;
      showTermsModal({ enforce, focusBody: true });
      if (enforce) {
        setStatus("Accept the Terms & Conditions to continue.", "error");
        ensureTermsPromise();
      }
    });
  }
  if (dom.termsWithdrawBtn) {
    dom.termsWithdrawBtn.addEventListener("click", handleTermsWithdraw);
  }
  if (dom.termsBackdrop) {
    dom.termsBackdrop.addEventListener("click", () => {
      if (state.termsAccepted && dom.termsModal?.dataset.mode !== "enforce") {
        hideTermsModal();
      }
    });
  }
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && state.termsAccepted && !dom.termsModal?.classList.contains("hidden")) {
      hideTermsModal();
    }
  });
  updateTermsControls();
}
function deriveRootDomain(hostname) {
  if (!hostname || typeof hostname !== "string") {
    return null;
  }
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 1) {
    return hostname;
  }
  if (parts.length === 2) {
    return parts.join(".");
  }
  const last = parts[parts.length - 1];
  const secondLast = parts[parts.length - 2];
  const countryTld = last.length === 2;
  const commonSecondLevels = new Set(["com", "net", "org", "gov", "edu", "co", "mil", "gob", "govt"]);
  if (countryTld && commonSecondLevels.has(secondLast) && parts.length >= 3) {
    return parts.slice(parts.length - 3).join(".");
  }
  return parts.slice(parts.length - 2).join(".");
}

function setStatus(message, type = "idle") {
  const el = dom.connectionStatus;
  el.textContent = message;
  el.classList.remove("status-idle", "status-success", "status-error", "status-progress");
  if (type === "success") el.classList.add("status-success");
  else if (type === "error") el.classList.add("status-error");
  else if (type === "progress") el.classList.add("status-progress");
  else el.classList.add("status-idle");
}

function applyConnectionToForm(connection, { announce = false } = {}) {
  const normalized = connection
    ? {
        projectId: sanitize(connection.projectId),
        schema: sanitize(connection.schema) || "public",
        apiKey: sanitize(connection.apiKey),
        bearer: sanitize(connection.bearer) || sanitize(connection.apiKey),
      }
    : {
        projectId: "",
        schema: "public",
        apiKey: "",
        bearer: "",
      };

  state.connection = normalized;
  state.baseUrl = normalized.projectId ? buildBaseUrl(normalized.projectId) : "";

  if (dom.projectId) dom.projectId.value = normalized.projectId;
  if (dom.schema) dom.schema.value = normalized.schema || "public";
  if (dom.apiKey) dom.apiKey.value = normalized.apiKey;
  if (dom.bearer) dom.bearer.value = normalized.bearer;

  if (announce) {
    if (normalized.projectId || normalized.apiKey || normalized.bearer) {
      setStatus("Connection details received from DevTools.", "success");
    } else {
      setStatus("Connection details cleared.", "idle");
    }
  }
}

function markConnectionWriteSource(source) {
  state.connectionWriteSource = source;
  if (source) {
    setTimeout(() => {
      if (state.connectionWriteSource === source) {
        state.connectionWriteSource = null;
      }
    }, 500);
  }
}

function buildBaseUrl(projectId) {
  const cleanId = sanitize(projectId);
  if (!cleanId) return "";
  return `https://${cleanId}.supabase.co/rest/v1`;
}

function buildHeaders(connection, accept = "application/json") {
  const apiKey = sanitize(connection.apiKey);
  const bearer = sanitize(connection.bearer || connection.apiKey);
  const schema = sanitize(connection.schema || "public");

  return {
    apikey: apiKey,
    authorization: `Bearer ${bearer}`,
    "Accept-Profile": schema,
    accept,
    "cache-control": "no-cache",
  };
}

async function storageGet(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get(key, resolve);
  });
}

async function storageSet(values) {
  return new Promise((resolve) => {
    chrome.storage.local.set(values, resolve);
  });
}

async function storageRemove(key) {
  return new Promise((resolve) => {
    chrome.storage.local.remove(key, resolve);
  });
}

function elevateRiskLevel(current, next) {
  const currentRank = RISK_LEVEL_ORDER[current] ?? 0;
  const nextRank = RISK_LEVEL_ORDER[next] ?? 0;
  return nextRank > currentRank ? next : current;
}

async function loadAssetDetectionsForProject(projectId) {
  if (!projectId) {
    return [];
  }
  const stored = await storageGet(ASSET_DETECTIONS_KEY);
  const map = stored?.[ASSET_DETECTIONS_KEY];
  if (!map || typeof map !== "object") {
    return [];
  }
  const entries = Array.isArray(map[projectId]) ? map[projectId] : [];
  if (!entries.length) {
    return [];
  }

  return entries
    .map((entry) => ({
      supabaseUrl: typeof entry?.supabaseUrl === "string" ? entry.supabaseUrl : "",
      assetUrl: typeof entry?.assetUrl === "string" ? entry.assetUrl : "",
      keyType: typeof entry?.keyType === "string" ? entry.keyType : "",
      keyLabel: typeof entry?.keyLabel === "string" ? entry.keyLabel : "",
      apiKeySnippet: typeof entry?.apiKeySnippet === "string" ? entry.apiKeySnippet : "",
      detectedAt: typeof entry?.detectedAt === "string" ? entry.detectedAt : "",
    }))
    .sort((a, b) => {
      const aTime = new Date(a.detectedAt || 0).getTime();
      const bTime = new Date(b.detectedAt || 0).getTime();
      return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
    });
}

async function loadLeakDetectionsForHost(hostname) {
  if (!hostname) {
    return [];
  }
  const stored = await storageGet(LEAK_DETECTIONS_KEY);
  const map = stored?.[LEAK_DETECTIONS_KEY];
  if (!map || typeof map !== "object") {
    return [];
  }
  const rootDomain = deriveRootDomain(hostname);
  const exact = Array.isArray(map[hostname]) ? map[hostname] : [];
  const root = rootDomain && rootDomain !== hostname && Array.isArray(map[rootDomain]) ? map[rootDomain] : [];
  const combined = [...exact, ...root];
  if (!combined.length) {
    return [];
  }
  const normalized = combined.map((entry) => ({
    sourceUrl: typeof entry?.sourceUrl === "string" ? entry.sourceUrl : "",
    assetUrl: typeof entry?.assetUrl === "string" ? entry.assetUrl : "",
    pattern: typeof entry?.pattern === "string" ? entry.pattern : "",
    matchSnippet: typeof entry?.matchSnippet === "string" ? entry.matchSnippet : "",
    contextSnippet: typeof entry?.contextSnippet === "string" ? entry.contextSnippet : "",
    encodedSnippet: typeof entry?.encodedSnippet === "string" ? entry.encodedSnippet : "",
    detectedAt: typeof entry?.detectedAt === "string" ? entry.detectedAt : "",
  }));
  const seen = new Set();
  const deduped = normalized.filter((entry) => {
    const key = `${entry.pattern}|${entry.matchSnippet}|${entry.sourceUrl}|${entry.detectedAt}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
  return deduped.sort((a, b) => {
    const aTime = new Date(a.detectedAt || 0).getTime();
    const bTime = new Date(b.detectedAt || 0).getTime();
    return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
  });
}

async function resolveInspectedHost() {
  if (!chrome?.tabs?.query) {
    return state.inspectedHost || null;
  }
  return new Promise((resolve) => {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = Array.isArray(tabs) ? tabs[0] : null;
        if (tab?.url) {
          try {
            const { hostname } = new URL(tab.url);
            resolve(hostname || null);
            return;
          } catch (error) {
            // Fall through to resolve previous host.
          }
        }
        resolve(state.inspectedHost || null);
      });
    } catch (error) {
      resolve(state.inspectedHost || null);
    }
  });
}

async function refreshDetectionSnapshots() {
  if (!state.termsAccepted) {
    state.assetDetections = [];
    state.leakDetections = [];
    updateReportButtonState();
    return;
  }
  const host = await resolveInspectedHost();
  const projectId = state.connection?.projectId ? sanitize(state.connection.projectId) : "";
  const [assetDetections, leakDetections] = await Promise.all([
    projectId ? loadAssetDetectionsForProject(projectId) : [],
    host ? loadLeakDetectionsForHost(host) : [],
  ]);
  state.assetDetections = assetDetections;
  state.leakDetections = leakDetections;
  state.inspectedHost = host;
  updateReportButtonState();
}

function hasSupabaseContext() {
  return Boolean(state.connection?.projectId && state.connection?.apiKey && state.baseUrl);
}

function hasDetectionFindings() {
  const assetCount = Array.isArray(state.assetDetections) ? state.assetDetections.length : 0;
  const leakCount = Array.isArray(state.leakDetections) ? state.leakDetections.length : 0;
  return assetCount > 0 || leakCount > 0;
}

function deriveLeakRiskLevel(leakDetections) {
  if (!Array.isArray(leakDetections) || !leakDetections.length) {
    return null;
  }
  let risk = "medium";
  leakDetections.forEach((detection) => {
    const haystack = `${detection.pattern || ""} ${detection.matchSnippet || ""}`.toLowerCase();
    if (/service|secret|token|aws|github|slack|twilio|discord|private|bearer/.test(haystack)) {
      risk = "critical";
    } else if (/key|api|auth/.test(haystack) && risk !== "critical") {
      risk = "high";
    }
  });
  return risk;
}

async function fetchOpenApi() {
  const url = `${state.baseUrl.replace(/\/$/, "")}/`;
  const headers = buildHeaders(state.connection, "application/openapi+json;version=3.0");
  const response = await fetch(url, { headers });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`OpenAPI request failed (${response.status}): ${text}`);
  }
  return response.json();
}

function parseTablesFromOpenApi(openApi) {
  const paths = openApi?.paths || {};
  const names = new Set();

  Object.keys(paths).forEach((path) => {
    if (!path.startsWith("/") || path.startsWith("/rpc/")) return;
    const seg = path.split("?")[0].replace(/^\//, "");
    if (!seg || seg.includes("/")) return;
    names.add(seg);
  });

  return Array.from(names).sort();
}

function sendMessageAsync(message) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          reject(new Error(lastError.message));
          return;
        }
        resolve(response);
      });
    } catch (error) {
      reject(error);
    }
  });
}

function updateReportButtonState({ busy = false } = {}) {
  if (!dom.reportBtn) return;
  const isBusy = busy || state.isGeneratingReport;
  if (isBusy) {
    dom.reportBtn.disabled = true;
    dom.reportBtn.classList.add("is-busy");
  } else {
    dom.reportBtn.classList.remove("is-busy");
    if (!state.termsAccepted) {
      dom.reportBtn.disabled = true;
    } else {
      const hasTables = Array.isArray(state.tables) && state.tables.length > 0;
      const shouldDisable = !(hasTables || hasDetectionFindings());
      dom.reportBtn.disabled = shouldDisable;
    }
  }

  if (dom.shareReportViewBtn) {
    const shouldDisableView = dom.reportBtn.disabled || isBusy;
    dom.shareReportViewBtn.disabled = shouldDisableView;
    dom.shareReportViewBtn.classList.toggle("is-busy", isBusy);
  }
}

function toggleShareReportModal(visible) {
  if (!dom.shareReportModal) return;
  state.isShareReportOpen = Boolean(visible);
  dom.shareReportModal.classList.toggle("hidden", !visible);
  document.body?.classList.toggle("share-report-locked", Boolean(visible));
  if (visible) {
    dom.shareReportViewBtn?.focus();
  }
}

function openShareReportModal(event) {
  event?.preventDefault();
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  if (dom.reportBtn?.disabled) {
    return;
  }
  toggleShareReportModal(true);
}

function closeShareReportModal(event) {
  event?.preventDefault?.();
  if (!state.isShareReportOpen) {
    return;
  }
  toggleShareReportModal(false);
}

function handleShareReportKeydown(event) {
  if (event.key === "Escape" && state.isShareReportOpen) {
    event.preventDefault();
    toggleShareReportModal(false);
  }
}

async function handleShareReportView(event) {
  event?.preventDefault?.();
  if (dom.shareReportViewBtn?.disabled) {
    return;
  }
  closeShareReportModal();
  await handleGenerateReport();
}

function generateLocalId(prefix = "id") {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`;
}

function decodeJwtClaims(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    let payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = payload.length % 4;
    if (pad) {
      payload += "=".repeat(4 - pad);
    }
    const json = atob(payload);
    return JSON.parse(json);
  } catch (error) {
    return null;
  }
}

function inferRoleFromClaims(claims) {
  if (!claims || typeof claims !== "object") return null;
  if (typeof claims.role === "string" && claims.role.trim()) {
    return claims.role.trim();
  }
  const metadataRole = claims?.app_metadata?.role;
  if (typeof metadataRole === "string" && metadataRole.trim()) {
    return metadataRole.trim();
  }
  const aud = claims?.aud;
  if (Array.isArray(aud)) {
    if (aud.includes("service_role")) return "service_role";
    if (aud.includes("anon")) return "anon";
  } else if (typeof aud === "string") {
    if (aud === "authenticated" || aud === "anon") return "anon";
    if (aud === "service_role") return "service_role";
  }
  return null;
}

function isSensitiveColumn(name) {
  if (!name || typeof name !== "string") return false;
  const lower = name.toLowerCase();
  return sensitiveColumnIndicators.some((indicator) => lower.includes(indicator));
}

function findSensitiveColumns(columns) {
  if (!Array.isArray(columns)) return [];
  return columns.filter(isSensitiveColumn);
}

function parseRowCountFromRange(range) {
  if (!range || typeof range !== "string" || !range.includes("/")) return null;
  const total = range.split("/").pop();
  if (!total || total === "*") {
    return null;
  }
  const num = Number(total);
  return Number.isFinite(num) ? num : null;
}

function trimErrorMessage(text, limit = 200) {
  if (!text || typeof text !== "string") return "";
  const trimmed = text.trim();
  if (trimmed.length <= limit) return trimmed;
  return `${trimmed.slice(0, limit)}…`;
}

function formatList(items, limit = 5) {
  if (!Array.isArray(items) || !items.length) return "";
  const slice = items.slice(0, limit);
  const remainder = items.length - slice.length;
  if (remainder > 0) {
    return `${slice.join(", ")} and ${remainder} more`;
  }
  return slice.join(", ");
}

async function mapWithConcurrency(items, limit, mapper) {
  if (!Array.isArray(items) || !items.length) {
    return [];
  }
  const concurrency = Math.max(1, Math.floor(limit) || 1);
  const results = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const currentIndex = nextIndex;
      if (currentIndex >= items.length) {
        break;
      }
      nextIndex += 1;
      results[currentIndex] = await mapper(items[currentIndex], currentIndex);
    }
  }

  const poolSize = Math.min(concurrency, items.length);
  const workers = Array.from({ length: poolSize }, worker);
  await Promise.all(workers);
  return results;
}

function summarizeClaims(claims) {
  if (!claims || typeof claims !== "object") return null;
  const summary = {};
  if (typeof claims.role === "string") summary.role = claims.role;
  if (typeof claims.ref === "string") summary.ref = claims.ref;
  if (typeof claims.iss === "string") summary.iss = claims.iss;
  if (typeof claims.sub === "string") summary.sub = claims.sub;
  if (typeof claims.aud === "string" || Array.isArray(claims.aud)) summary.aud = claims.aud;
  if (typeof claims.exp === "number") summary.exp = claims.exp;
  if (typeof claims.iat === "number") summary.iat = claims.iat;
  return summary;
}

async function getTableRowCount(table) {
  const url = new URL(`${state.baseUrl.replace(/\/$/, "")}/${table}`);
  const headers = buildHeaders(state.connection);
  headers.Prefer = "count=exact";
  url.searchParams.set("select", "*");
  url.searchParams.set("limit", "1");

  const response = await fetch(url.toString(), { headers });
  if (!response.ok) {
    let detail = "";
    try {
      detail = await response.text();
    } catch (readError) {
      // Ignore read errors and fall back to basic message.
    }
    const trimmed = detail ? detail.trim().slice(0, 200) : "";
    const message = trimmed ? `Count failed (${response.status}): ${trimmed}` : `Count failed (${response.status})`;
    throw new Error(message);
  }
  const contentRange = response.headers.get("Content-Range");
  if (contentRange && contentRange.includes("/")) {
    const total = contentRange.split("/").pop();
    if (total && total !== "*") {
      return Number(total);
    }
  }
  return null;
}

function renderTablesList() {
  if (!dom.tablesList) return;

  updateReportButtonState();

  dom.tablesList.innerHTML = "";

  if (!state.tables.length) {
    const emptyRow = document.createElement("tr");
    emptyRow.className = "tables-empty";
    const cell = document.createElement("td");
    cell.colSpan = 2;
    cell.textContent = state.baseUrl ? "No tables found for this schema." : "Connect to populate tables.";
    emptyRow.appendChild(cell);
    dom.tablesList.appendChild(emptyRow);
    updateActiveRowHighlight();
    return;
  }

  state.tables.forEach((table) => {
    const row = document.createElement("tr");
    row.dataset.table = table;

    const nameCell = document.createElement("td");
    nameCell.textContent = table;

    const countCell = document.createElement("td");
    const count = state.tableCounts?.[table];
    const error = state.tableCountErrors?.[table];
    if (typeof count === "number") {
      countCell.textContent = count.toLocaleString();
    } else if (count === null) {
      countCell.textContent = "—";
    } else {
      countCell.textContent = "…";
    }
    if (error) {
      countCell.textContent = "⚠";
      countCell.title = error.message || "Unable to fetch row count.";
      row.classList.add("has-error");
    } else {
      countCell.title = "";
      row.classList.remove("has-error");
    }

    row.appendChild(nameCell);
    row.appendChild(countCell);
    if (state.currentTable === table) {
      row.classList.add("active");
    }
    dom.tablesList.appendChild(row);
  });

  updateActiveRowHighlight();
}

function handleTableClick(event) {
  if (!state.termsAccepted) {
    enforceTermsAccess({ showModal: true, announce: false });
    return;
  }
  const row = event.target.closest("tr[data-table]");
  if (!row) return;
  const table = row.dataset.table;
  if (!table) return;
  setActiveTable(table, { persist: true, announce: false });
}

function handleTableDoubleClick(event) {
  if (!state.termsAccepted) {
    enforceTermsAccess({ showModal: true, announce: false });
    return;
  }
  const row = event.target.closest("tr[data-table]");
  if (!row) return;
  const table = row.dataset.table;
  if (!table) return;
  setActiveTable(table, { persist: true, announce: false });
  openTableExplorer(table);
}

async function handleConnect(event) {
  event?.preventDefault();
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  const connection = {
    projectId: sanitize(dom.projectId.value),
    schema: sanitize(dom.schema.value) || "public",
    apiKey: sanitize(dom.apiKey.value),
    bearer: sanitize(dom.bearer.value),
  };
  await connectWithConnection(connection, { triggeredBy: "user" });
}

async function connectWithConnection(connection, { triggeredBy = "user" } = {}) {
  if (!state.termsAccepted) {
    enforceTermsAccess({ showModal: true });
    return;
  }
  const normalized = {
    projectId: sanitize(connection.projectId),
    schema: sanitize(connection.schema) || "public",
    apiKey: sanitize(connection.apiKey),
    bearer: sanitize(connection.bearer || connection.apiKey),
  };

  if (!normalized.projectId || !normalized.apiKey) {
    setStatus("Project ID and apiKey required.", "error");
    return;
  }

  applyConnectionToForm(normalized, { announce: false });

  const previousTable = state.currentTable;
  state.tables = [];
  state.tableCounts = {};
  state.tableCountErrors = {};
  state.currentTable = null;
  renderTablesList();

  const statusPrefix = triggeredBy === "devtools"
    ? "DevTools connection"
    : triggeredBy === "detector"
      ? "Detected Supabase request"
      : triggeredBy === "restore"
        ? "Restoring connection"
        : "Connecting";
  setStatus(`${statusPrefix}…`, "progress");
  dom.connectBtn.disabled = true;
  dom.reloadBtn.disabled = true;

  try {
    state.openApi = await fetchOpenApi();
    state.tables = parseTablesFromOpenApi(state.openApi);
    state.tableCounts = {};
    renderTablesList();

    if (state.tables.length) {
      const initialTable = previousTable && state.tables.includes(previousTable)
        ? previousTable
        : state.tables[0];
      if (initialTable) {
        setActiveTable(initialTable, { persist: true });
      }
    } else {
      setActiveTable(null);
    }

    markConnectionWriteSource("sidepanel");
    const metaSource = triggeredBy === "devtools" || triggeredBy === "restore"
      ? "sidepanel"
      : triggeredBy;
    await storageSet({
      [storageKeys.connection]: state.connection,
      [storageKeys.connectionMeta]: { source: metaSource, updatedAt: Date.now() },
    });

    if (state.tables.length) {
      await refreshTableCounts();
    }

    const suffix = state.tables.length
      ? `Connected (${state.tables.length} table${state.tables.length === 1 ? "" : "s"}).`
      : "Connected, but no tables were found.";
    setStatus(suffix, "success");
  } catch (error) {
    console.error(error);
    setStatus(error.message, "error");
  } finally {
    await refreshDetectionSnapshots();
    dom.connectBtn.disabled = false;
    dom.reloadBtn.disabled = false;
    updateReportButtonState();
  }
}

async function refreshTableCounts() {
  if (!state.tables.length) return;
  setStatus("Counting rows…", "progress");

  state.tableCounts = {};
  state.tableCountErrors = {};

  for (const table of state.tables) {
    try {
      const count = await getTableRowCount(table);
      state.tableCounts[table] = typeof count === "number" ? count : null;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error || "Row count failed.");
      const suppressLog = /401/.test(message) || /permission denied/i.test(message);
      /*if (!suppressLog) {
        console.warn(`Failed to count rows for ${table}`, error);
      }*/
      state.tableCounts[table] = null;
      state.tableCountErrors[table] = { message };
    }
    renderTablesList();
  }

  const erroredTables = Object.keys(state.tableCountErrors || {});
  if (erroredTables.length) {
    setStatus("Row counts loaded with permission warnings.", "error");
  } else {
    setStatus("Row counts updated.", "success");
  }
}

async function analyzeTableSecurity(table) {
  const url = new URL(`${state.baseUrl.replace(/\/$/, "")}/${table}`);
  const headers = buildHeaders(state.connection);
  const cachedRowCount = typeof state.tableCounts?.[table] === "number" ? state.tableCounts[table] : null;
  if (cachedRowCount === null) {
    headers.Prefer = "count=exact";
  }
  url.searchParams.set("select", "*");
  url.searchParams.set("limit", "1");

  let accessible = false;
  let status = null;
  let rowCount = cachedRowCount;
  let columns = [];
  let errorDetail = null;

  try {
    const response = await fetch(url.toString(), { headers });
    status = response.status;
    if (cachedRowCount === null) {
      const contentRange = response.headers.get("Content-Range");
      const parsedCount = parseRowCountFromRange(contentRange);
      if (parsedCount !== null) {
        rowCount = parsedCount;
        if (!state.tableCounts) state.tableCounts = {};
        state.tableCounts[table] = parsedCount;
      }
    }

    if (response.ok) {
      accessible = true;
      let body = null;
      try {
        body = await response.json();
      } catch (parseError) {
        body = null;
      }
      if (Array.isArray(body) && body.length && body[0] && typeof body[0] === "object") {
        columns = Object.keys(body[0]);
      }
    } else {
      const text = await response.text();
      errorDetail = trimErrorMessage(text);
    }
  } catch (error) {
    errorDetail = error instanceof Error ? error.message : String(error || "Fetch failed.");
  }

  const uniqueColumns = Array.from(new Set(columns || [])).slice(0, 12);
  const sensitiveColumns = findSensitiveColumns(uniqueColumns);
  const warnings = [];
  const notes = [];
  let policyState = "unknown";

  if (accessible) {
    policyState = "likely-unprotected";
    warnings.push("Table responds with data using the current credentials. Enable RLS and restrictive policies.");
    if (typeof rowCount === "number") {
      notes.push(`Approximate row count: ${rowCount.toLocaleString()}.`);
      if (rowCount > 1000) {
        warnings.push("Large row count is exposed; attackers can exfiltrate datasets with filter operators.");
      }
    }
    if (uniqueColumns.length) {
      notes.push(`Columns observed: ${uniqueColumns.join(", ")}`);
    }
    if (sensitiveColumns.length) {
      warnings.push(`Sensitive-looking columns exposed: ${sensitiveColumns.join(", ")}.`);
    }
  } else if (status === 401 || status === 403) {
    policyState = "protected";
    notes.push("API returned 401/403 for this table, indicating RLS or equivalent protection.");
    if (errorDetail) {
      notes.push(`Error detail: ${errorDetail}`);
    }
  } else {
    policyState = "unknown";
    if (errorDetail) {
      notes.push(`Access failed: ${errorDetail}`);
    }
  }

  return {
    name: table,
    accessible,
    status,
    rowCount: typeof rowCount === "number" ? rowCount : null,
    columns: uniqueColumns,
    sensitiveColumns,
    warnings,
    notes,
    error: errorDetail,
    policyState,
  };
}

function buildSecurityRecommendations({
  accessibleTables,
  sensitiveTables,
  assetDetections,
  leakDetections,
  keyRole,
  bearerRole,
  inspectedHost,
}) {
  const recommendations = [];
  const leaks = Array.isArray(leakDetections) ? leakDetections : [];
  const leakRisk = deriveLeakRiskLevel(leaks);
  const leakSeverity = leakRisk === "critical" ? "critical" : leakRisk === "high" ? "high" : "medium";
  const locationLabel = inspectedHost || "the inspected site";
  const exposedNames = formatList(accessibleTables.map((item) => item.name));
  const sensitiveNames = formatList(sensitiveTables.map((item) => item.name));
  const sensitiveColumnsCombined = Array.from(
    new Set(sensitiveTables.flatMap((item) => item.sensitiveColumns || []))
  );
  const sensitiveColumnsPreview = formatList(sensitiveColumnsCombined);
  const assetExposureCount = Array.isArray(assetDetections) ? assetDetections.length : 0;
  const hasServiceAsset = Array.isArray(assetDetections)
    ? assetDetections.some((item) => /service/i.test(item.keyType || "") || /service_role/i.test(item.keyLabel || ""))
    : false;

  if (leaks.length) {
    const summary = leaks.length === 1
      ? "1 potential API credential leak was detected."
      : `${leaks.length} potential API credential leaks were detected.`;
    recommendations.push({
      id: "api-leaks",
      title: "Rotate leaked API credentials",
      detail: `${summary} Review detections for ${locationLabel}, revoke the exposed secrets, and remove them from client-side bundles.`,
      severity: leakRisk ? leakSeverity : "high",
    });
  }

  if (accessibleTables.length) {
    recommendations.push({
      id: "rls",
      title: "Enforce Row Level Security on exposed tables",
      detail: `The following tables respond to anonymous/service requests: ${exposedNames}. Enable RLS and create explicit SELECT policies that scope rows to authorized users only.`,
      severity: keyRole === "anon" || bearerRole === "anon" ? "critical" : "high",
    });
  }

  if (sensitiveTables.length) {
    recommendations.push({
      id: "sensitive-columns",
      title: "Protect sensitive columns behind policies or RPCs",
      detail: `Sensitive-looking columns (${sensitiveColumnsPreview}) were exposed by ${sensitiveNames}. Restrict them to trusted roles or move them behind server-side functions.`,
      severity: "high",
    });
  }

  if (keyRole === "service_role" || bearerRole === "service_role") {
    recommendations.push({
      id: "service-role",
      title: "Remove service_role keys from client-side contexts",
      detail: "Service role keys bypass RLS entirely. Rotate this key and move privileged operations to secure backend services.",
      severity: "critical",
    });
  }

  if (assetExposureCount) {
    recommendations.push({
      id: "static-assets",
      title: "Purge Supabase credentials from static assets",
      detail: `${assetExposureCount} exposed credential${assetExposureCount === 1 ? " was" : "s were"} discovered in static files while DevTools was open. Rotate the affected key${assetExposureCount === 1 ? "" : "s"} immediately, remove them from bundles, and load configuration from server-side storage instead of shipping secrets to the client.`,
      severity: hasServiceAsset ? "critical" : "high",
    });
  }

  if (accessibleTables.length) {
    recommendations.push({
      id: "filters",
      title: "Test filter operators against exposed endpoints",
      detail: "Use Supabase filter operators (`eq`, `neq`, `ilike`, `in`) to ensure unauthorized users cannot pivot across tables, as highlighted in the DeepStrike misconfiguration research.",
      severity: "high",
    });
  } else {
    recommendations.push({
      id: "regression-tests",
      title: "Add automated RLS regression tests",
      detail: "Keep integration tests that exercise anon and authenticated roles so future schema changes do not re-open exposures.",
      severity: "medium",
    });
  }

  return recommendations;
}

async function buildSecurityReport() {
  const createdAt = new Date().toISOString();
  const reportId = generateLocalId("sbde_report");
  const assetDetections = Array.isArray(state.assetDetections) ? state.assetDetections : [];
  const leakDetections = Array.isArray(state.leakDetections) ? state.leakDetections : [];

  if (!hasSupabaseContext()) {
    return buildLeakOnlyReport({ reportId, createdAt, assetDetections, leakDetections });
  }

  const apiKeyClaims = decodeJwtClaims(state.connection.apiKey);
  const bearerClaims = state.connection.bearer && state.connection.bearer !== state.connection.apiKey
    ? decodeJwtClaims(state.connection.bearer)
    : null;
  const keyRole = inferRoleFromClaims(apiKeyClaims);
  const bearerRole = inferRoleFromClaims(bearerClaims);

  const tablesToAnalyze = Array.isArray(state.tables) ? state.tables : [];
  const findings = await mapWithConcurrency(
    tablesToAnalyze,
    REPORT_ANALYSIS_CONCURRENCY,
    (table) => analyzeTableSecurity(table)
  );

  const accessibleTables = findings.filter((item) => item.accessible);
  const protectedTables = findings.filter((item) => item.policyState === "protected");
  const sensitiveTables = accessibleTables.filter((item) => item.sensitiveColumns.length);
  const unknownTables = findings.filter((item) => !item.accessible && item.policyState === "unknown");

  let riskLevel = "low";
  const keyFindings = [];

  if (assetDetections.length) {
    const serviceExposure = assetDetections.some((item) => /service/i.test(item.keyType || "") || /service_role/i.test(item.keyLabel || ""));
    riskLevel = elevateRiskLevel(riskLevel, serviceExposure ? "critical" : "high");
    const summaryLabel = assetDetections.length === 1
      ? "1 exposed Supabase credential discovered in static assets."
      : `${assetDetections.length} exposed Supabase credentials discovered in static assets.`;
    keyFindings.push(summaryLabel);
  }

  const leakRisk = deriveLeakRiskLevel(leakDetections) || "high";
  if (leakDetections.length) {
    riskLevel = elevateRiskLevel(riskLevel, leakRisk);
    const leakSummary = leakDetections.length === 1
      ? "1 potential API credential leak detected in static assets."
      : `${leakDetections.length} potential API credential leaks detected in static assets.`;
    keyFindings.push(leakSummary);
  }

  if (accessibleTables.length) {
    const accessRisk = keyRole === "anon" || bearerRole === "anon" ? "critical" : "high";
    riskLevel = elevateRiskLevel(riskLevel, accessRisk);
    keyFindings.push(`${accessibleTables.length} table${accessibleTables.length === 1 ? "" : "s"} respond with data using the current credentials.`);
  }
  if (!accessibleTables.length && unknownTables.length) {
    riskLevel = elevateRiskLevel(riskLevel, "medium");
    keyFindings.push(`${unknownTables.length} table${unknownTables.length === 1 ? "" : "s"} returned non-auth errors that need manual review.`);
  }
  if (!keyFindings.length && protectedTables.length) {
    keyFindings.push(`All checked tables returned 401/403 responses (${protectedTables.length} protected).`);
  }

  const recommendations = buildSecurityRecommendations({
    accessibleTables,
    sensitiveTables,
    assetDetections,
    leakDetections,
    keyRole,
    bearerRole,
    inspectedHost: state.inspectedHost,
  });

  return {
    id: reportId,
    createdAt,
    projectId: state.connection.projectId,
    schema: state.connection.schema,
    baseUrl: state.baseUrl,
    connectionSummary: {
      apiKeyRole: keyRole || null,
      bearerRole: bearerRole || null,
      usesDistinctBearer: Boolean(state.connection.bearer && state.connection.bearer !== state.connection.apiKey),
      apiKeyClaims: summarizeClaims(apiKeyClaims),
      bearerClaims: summarizeClaims(bearerClaims),
    },
    summary: {
      riskLevel,
      tableCount: findings.length,
      accessibleCount: accessibleTables.length,
      protectedCount: protectedTables.length,
      unknownCount: unknownTables.length,
      keyFindings,
    },
    findings,
    assetDetections,
    leakDetections,
    recommendations,
  };
}

function buildLeakOnlyReport({ reportId, createdAt, assetDetections, leakDetections }) {
  let riskLevel = "low";
  const keyFindings = [];

  if (Array.isArray(assetDetections) && assetDetections.length) {
    const serviceExposure = assetDetections.some((item) => /service/i.test(item.keyType || "") || /service_role/i.test(item.keyLabel || ""));
    riskLevel = elevateRiskLevel(riskLevel, serviceExposure ? "critical" : "high");
    const summaryLabel = assetDetections.length === 1
      ? "1 exposed Supabase credential discovered in static assets."
      : `${assetDetections.length} exposed Supabase credentials discovered in static assets.`;
    keyFindings.push(summaryLabel);
  }

  const leakRisk = deriveLeakRiskLevel(leakDetections) || "high";
  if (Array.isArray(leakDetections) && leakDetections.length) {
    riskLevel = elevateRiskLevel(riskLevel, leakRisk);
    const leakSummary = leakDetections.length === 1
      ? "1 potential API credential leak detected in static assets."
      : `${leakDetections.length} potential API credential leaks detected in static assets.`;
    keyFindings.push(leakSummary);
  }

  if (!keyFindings.length) {
    keyFindings.push("No Supabase tables were analyzed; report generated from leak detections only.");
  }

  const projectLabel = state.connection.projectId || state.inspectedHost || "Unknown project";
  const schemaLabel = state.connection.schema || "n/a";
  const baseUrl = state.baseUrl || (state.inspectedHost ? `https://${state.inspectedHost}` : "");

  const recommendations = buildSecurityRecommendations({
    accessibleTables: [],
    sensitiveTables: [],
    assetDetections,
    leakDetections,
    keyRole: null,
    bearerRole: null,
    inspectedHost: state.inspectedHost,
  });

  return {
    id: reportId,
    createdAt,
    projectId: projectLabel,
    schema: schemaLabel,
    baseUrl,
    connectionSummary: null,
    summary: {
      riskLevel,
      tableCount: 0,
      accessibleCount: 0,
      protectedCount: 0,
      unknownCount: 0,
      keyFindings,
    },
    findings: [],
    assetDetections,
    leakDetections,
    recommendations,
  };
}

async function handleGenerateReport(event) {
  event?.preventDefault();
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  if (state.isGeneratingReport) {
    return;
  }

  await refreshDetectionSnapshots();

  const hasSupabase = hasSupabaseContext();
  const hasDetections = hasDetectionFindings();
  const hasTables = Array.isArray(state.tables) && state.tables.length > 0;

  if (!hasSupabase && !hasDetections) {
    setStatus("Connect to Supabase or capture leak detections before generating a report.", "error");
    return;
  }
  if (hasSupabase && !hasTables && !hasDetections) {
    setStatus("Load Supabase tables or capture leak detections before generating a report.", "error");
    return;
  }

  state.isGeneratingReport = true;
  updateReportButtonState({ busy: true });
  setStatus("Building security report…", "progress");

  try {
    const report = await buildSecurityReport();
    const response = await sendMessageAsync({ type: "SBDE_CREATE_SECURITY_REPORT", payload: report });
    if (!response?.ok) {
      throw new Error(response?.reason || "Failed to open security report.");
    }
    setStatus("Security report opened in a new tab.", "success");
  } catch (error) {
    console.error("Security report generation failed", error);
    const message = error instanceof Error ? error.message : String(error || "Security report failed.");
    setStatus(message, "error");
  } finally {
    state.isGeneratingReport = false;
    updateReportButtonState();
  }
}

async function openTableExplorer(table) {
  if (!state.termsAccepted) {
    enforceTermsAccess({ showModal: true });
    return;
  }
  const targetTable = table || state.currentTable;
  if (!targetTable) {
    setStatus("Select a table first.", "error");
    return;
  }

  setActiveTable(targetTable, { persist: true });
  setStatus(`Opening ${targetTable}…`, "progress");

  chrome.runtime.sendMessage({ type: "SBDE_OPEN_EXPLORER" }, (response) => {
    const lastErrorMessage = chrome.runtime.lastError?.message || "";
    const isPortClosed = lastErrorMessage.includes("The message port closed before a response was received");

    if (lastErrorMessage && !isPortClosed) {
      setStatus(lastErrorMessage || "Failed to open explorer.", "error");
      return;
    }

    if (!isPortClosed && response && !response.ok) {
      const reason = response.reason || "Unable to open explorer on this page.";
      setStatus(reason, "error");
      return;
    }

    setStatus(`Explorer opened for ${targetTable}.`, "success");
    setTimeout(() => {
      const message = state.tables.length
        ? `Connected (${state.tables.length} table${state.tables.length === 1 ? "" : "s"})`
        : "Ready";
      setStatus(message, "idle");
    }, 3000);
  });
}

async function restoreFromStorage() {
  if (!state.termsAccepted) {
    return;
  }
  try {
    chrome.storage.local.remove("sbde_capturedRequest");

    const stored = await storageGet(storageKeys.connection);
    const saved = stored?.[storageKeys.connection];
    applyConnectionToForm(saved || null, { announce: false });

    const tableStored = await storageGet(storageKeys.selectedTable);
    state.currentTable = tableStored?.[storageKeys.selectedTable] || null;
    state.tableCountErrors = {};
    renderTablesList();

    const themeStored = await storageGet(storageKeys.theme);
    const savedTheme = themeStored?.[storageKeys.theme];
    if (savedTheme) {
      setTheme(savedTheme, { persist: false });
    } else {
      setTheme("dark", { persist: false });
    }

    const metaStored = await storageGet(storageKeys.connectionMeta);
    const meta = metaStored?.[storageKeys.connectionMeta];
    const autoConnectSource = typeof meta?.source === "string" && ["devtools", "detector"].includes(meta.source)
      ? meta.source
      : null;
    const autoConnect = Boolean(
      saved?.projectId &&
      saved?.apiKey &&
      autoConnectSource &&
      typeof meta?.updatedAt === "number" &&
      Date.now() - meta.updatedAt < 30000
    );

    if (autoConnect && autoConnectSource) {
      await connectWithConnection(saved, { triggeredBy: autoConnectSource });
    } else if (saved?.projectId && saved?.apiKey) {
      setStatus("Restored credentials. Click Connect to refresh tables.", "idle");
    } else {
      setStatus("Idle", "idle");
    }
    await refreshDetectionSnapshots();
  } catch (error) {
    console.error("Storage restore failed", error);
  }
}

async function bootstrapAfterTerms() {
  if (!state.termsAccepted) {
    return;
  }
  if (state.hasBootstrappedAfterTerms) {
    await refreshDetectionSnapshots();
    return;
  }
  state.hasBootstrappedAfterTerms = true;
  await restoreFromStorage();
}

async function clearSavedConnection() {
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  markConnectionWriteSource("sidepanel");
  await storageRemove(storageKeys.connection);
  await storageRemove(storageKeys.selectedTable);
  await storageRemove(storageKeys.connectionMeta);

  applyConnectionToForm(null, { announce: false });
  state.tables = [];
  state.tableCounts = {};
  state.tableCountErrors = {};
  state.currentTable = null;

  renderTablesList();
  setActiveTable(null);
  await refreshDetectionSnapshots();
  setStatus("Cleared saved credentials.", "success");
}

function initEventListeners() {
  dom.connectionForm.addEventListener("submit", handleConnect);
  dom.reloadBtn.addEventListener("click", handleConnect);
  dom.tablesList.addEventListener("click", handleTableClick);
  dom.tablesList.addEventListener("dblclick", handleTableDoubleClick);
  dom.clearStorageBtn.addEventListener("click", clearSavedConnection);
  if (dom.themeToggle) {
    dom.themeToggle.addEventListener("click", () => {
      const next = state.theme === "dark" ? "light" : "dark";
      setTheme(next);
    });
  }
}

function initShareReportUi() {
  if (dom.reportBtn) {
    dom.reportBtn.addEventListener("click", openShareReportModal);
  }
  if (dom.shareReportCloseBtn) {
    dom.shareReportCloseBtn.addEventListener("click", closeShareReportModal);
  }
  if (dom.shareReportBackdrop) {
    dom.shareReportBackdrop.addEventListener("click", closeShareReportModal);
  }
  if (dom.shareReportViewBtn) {
    dom.shareReportViewBtn.addEventListener("click", handleShareReportView);
  }
  document.addEventListener("keydown", handleShareReportKeydown);
}

function registerGlobalListeners() {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") {
      return;
    }

    if (changes[TERMS_STORAGE_KEY]) {
      const record = changes[TERMS_STORAGE_KEY].newValue;
      const accepted = isValidTermsAcceptance(record);
      state.termsAccepted = accepted;
      if (accepted) {
        hideTermsModal();
        resolvePendingTerms(true);
        if (!state.hasBootstrappedAfterTerms) {
          bootstrapAfterTerms().catch((error) => {
            console.error("Post-terms bootstrap failed", error);
          });
        } else {
          refreshDetectionSnapshots().catch((error) => {
            console.error("Snapshot refresh failed", error);
          });
        }
        updateTermsControls();
      } else {
        state.hasBootstrappedAfterTerms = false;
        ensureTermsPromise();
        applyConnectionToForm(null, { announce: false });
        state.tables = [];
        state.tableCounts = {};
        state.tableCountErrors = {};
        state.currentTable = null;
        state.assetDetections = [];
        state.leakDetections = [];
        state.inspectedHost = null;
        renderTablesList();
        updateReportButtonState();
        showTermsModal({ enforce: true });
        setStatus("Accept the Terms & Conditions to continue.", "error");
        updateTermsControls();
      }
    }

    if (changes[storageKeys.theme]) {
      setTheme(changes[storageKeys.theme].newValue, { persist: false });
    }

    if (!state.termsAccepted) {
      return;
    }

    if (changes[storageKeys.connection]) {
      const change = changes[storageKeys.connection];
      const metaChange = changes[storageKeys.connectionMeta];
      const announce = state.connectionWriteSource !== "sidepanel";
      const newConnection = change.newValue || null;
      const source = metaChange?.newValue?.source;
      applyConnectionToForm(newConnection, { announce });
      if (announce) {
        state.tables = [];
        state.tableCounts = {};
        state.tableCountErrors = {};
        state.currentTable = null;
        renderTablesList();
        if (newConnection?.projectId && newConnection?.apiKey) {
          const triggeredBy = source === "detector"
            ? "detector"
            : source === "devtools"
              ? "devtools"
              : "storage";
          connectWithConnection(newConnection, { triggeredBy });
        }
      }
      state.connectionWriteSource = null;
    }

    if (changes[ASSET_DETECTIONS_KEY] || changes[LEAK_DETECTIONS_KEY]) {
      refreshDetectionSnapshots();
    }
  });

  if (chrome?.tabs?.onActivated) {
    chrome.tabs.onActivated.addListener(() => {
      if (!state.termsAccepted) {
        return;
      }
      refreshDetectionSnapshots();
    });
  }
  if (chrome?.tabs?.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (!state.termsAccepted) {
        return;
      }
      if (!tab?.active) {
        return;
      }
      if (changeInfo.status === "complete" || changeInfo.url) {
        refreshDetectionSnapshots();
      }
    });
  }
}

async function init() {
  setTheme(state.theme, { persist: false });
  renderTablesList();
  initTermsUi();
  initEventListeners();
  initShareReportUi();
  registerGlobalListeners();
  await ensureTermsAccepted({ enforce: true });
  await bootstrapAfterTerms();
}

init();
function setTheme(theme, { persist = true } = {}) {
  const nextTheme = theme === "light" ? "light" : "dark";
  state.theme = nextTheme;
  document.body.dataset.theme = nextTheme;
  if (dom.themeIcon) {
    dom.themeIcon.dataset.theme = nextTheme;
  }
  if (persist) {
    storageSet({ [storageKeys.theme]: nextTheme });
  }
}
function updateActiveRowHighlight() {
  if (!dom.tablesList) return;
  const rows = dom.tablesList.querySelectorAll("tr[data-table]");
  rows.forEach((row) => {
    row.classList.toggle("active", row.dataset.table === state.currentTable);
  });
}

function setActiveTable(table, { persist = true, announce = false } = {}) {
  if (!table || !state.tables.includes(table)) {
    state.currentTable = null;
    updateActiveRowHighlight();
    if (persist) {
      storageRemove(storageKeys.selectedTable);
    }
    return;
  }

  if (state.currentTable !== table) {
    state.currentTable = table;
    updateActiveRowHighlight();
    if (persist) {
      storageSet({ [storageKeys.selectedTable]: table });
    }
    if (announce) {
      setStatus(`Selected table: ${table}`, "idle");
    }
  }
}
