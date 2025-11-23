import { cloudConfig } from "../shared/cloud_config.js";

const TERMS_STORAGE_KEY = "sbde_terms_acceptance";
const TERMS_VERSION = "1.0";
const TERMS_EFFECTIVE_DATE = "2025-11-05";

const storageKeys = {
  connection: "sbde_connection",
  selectedTable: "sbde_currentTable",
  theme: "sbde_theme",
  connectionMeta: "sbde_connection_meta",
  cloudIdentity: "sbde_cloud_identity",
  cloudLink: "sbde_cloud_link_state",
  cloudOrigin: "sbde_cloud_origin",
  cloudTeams: "sbde_cloud_teams",
  cloudSelectedTeam: "sbde_cloud_selected_team",
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

const SENSITIVE_TABLE_KEYWORDS = [
  "profile",
  "profiles",
  "customer",
  "customers",
  "billing",
  "billings",
  "invoice",
  "invoices",
  "user",
  "users",
  "team",
  "teams",
  "member",
  "members",
  "project",
  "projects",
  "plan",
  "plans",
  "organization",
  "organizations",
  "message",
  "messages",
  "contact",
  "contacts",
  "submission",
  "submissions",
  "feedback",
  "feedbacks",
  "chat",
  "chats",
];

const CLOUD_SECRET_BYTES = 32;
const CLOUD_STATUS = {
  DISCONNECTED: "disconnected",
  PENDING: "pending",
  LINKED: "linked",
  ERROR: "error",
};
const CLOUD_SECRET_HEADER = "X-Extension-Secret";
const EXTENSION_VERSION = (chrome?.runtime?.getManifest && typeof chrome.runtime.getManifest === "function"
  ? chrome.runtime.getManifest()?.version
  : null) || "0.0.0";
const LINK_POLL_INTERVAL_MS = cloudConfig?.pollIntervalMs || 4000;
const LINK_PENDING_TIMEOUT_MS = cloudConfig?.pendingTimeoutMs || 5 * 60 * 1000;
const CLOUD_STATUS_REFRESH_MS = 60 * 1000;

const REPORT_ANALYSIS_CONCURRENCY = 4; // Limit simultaneous table checks to keep PostgREST responsive.

const state = {
  connection: {
    projectId: "",
    schema: "public",
    apiKey: "",
    bearer: "",
    inspectedHost: "",
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
  leakSourceHost: null,
  inspectedHost: null,
  isGeneratingReport: false,
  isSharingReport: false,
  termsAccepted: false,
  hasBootstrappedAfterTerms: false,
  isShareReportOpen: false,
  cloud: {
    identity: null,
    origin: null,
    link: null,
    pollTimer: null,
    isModalOpen: false,
    isBusy: false,
    isCheckingStatus: false,
    lastStatusCheck: 0,
    lastError: null,
    lastShareUrl: null,
    teams: [],
    selectedTeamId: null,
    isFetchingTeams: false,
    teamsFetchedAt: 0,
    supportsTeamEndpoint: true,
  },
};

const dom = {
  connectionForm: document.getElementById("connection-form"),
  projectId: document.getElementById("project-id"),
  schema: document.getElementById("schema"),
  apiKey: document.getElementById("api-key"),
  bearer: document.getElementById("bearer"),
  connectBtn: document.getElementById("connect-btn"),
  clearStorageBtn: document.getElementById("clear-storage-btn"),
  reportBtn: document.getElementById("report-btn"),
  tablesList: document.getElementById("tables-list"),
  connectionStatus: document.getElementById("connection-status"),
  themeToggle: document.getElementById("theme-toggle"),
  themeIcon: document.querySelector(".theme-icon"),
  statusCheckBtn: document.getElementById("status-check-btn"),
  linkModal: document.getElementById("link-modal"),
  linkModalBackdrop: document.getElementById("link-modal-backdrop"),
  linkModalCloseBtn: document.getElementById("link-modal-close-btn"),
  linkStatusPill: document.getElementById("link-status-pill"),
  linkStatusMessage: document.getElementById("link-status-message"),
  linkStatusMeta: document.getElementById("link-status-meta"),
  linkStatusAccount: document.getElementById("link-status-account"),
  linkStatusLinkedAt: document.getElementById("link-status-linked-at"),
  linkStatusInstance: document.getElementById("link-status-instance"),
  linkConnectBtn: document.getElementById("link-connect-btn"),
  linkManageBtn: document.getElementById("link-manage-btn"),
  linkDisconnectBtn: document.getElementById("link-disconnect-btn"),
  linkTeamSection: document.getElementById("link-team-section"),
  linkTeamSelect: document.getElementById("link-team-select"),
  linkTeamRefreshBtn: document.getElementById("link-team-refresh-btn"),
  linkTeamStatus: document.getElementById("link-team-status"),
  shareReportModal: document.getElementById("share-report-modal"),
  shareReportBackdrop: document.getElementById("share-report-backdrop"),
  shareReportCloseBtn: document.getElementById("share-report-close-btn"),
  shareReportViewBtn: document.getElementById("share-report-view-btn"),
  shareReportShareBtn: document.getElementById("share-report-share-btn"),
  shareReportConnectBtn: document.getElementById("share-report-connect-btn"),
  shareReportNote: document.getElementById("share-report-note"),
  shareReportLink: document.getElementById("share-report-link"),
  shareReportLinkText: document.getElementById("share-report-link-text"),
  shareReportCopyBtn: document.getElementById("share-report-copy-btn"),
  shareReportNote: document.getElementById("share-report-note"),
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
const SHARE_REPORT_NOTE_DEFAULT = dom.shareReportNote?.textContent || "Link this extension to SupaExplorer Cloud to sync reports with your team.";

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
    await storageRemove(storageKeys.cloudIdentity);
    await storageRemove(storageKeys.cloudLink);
    await storageRemove(storageKeys.cloudOrigin);
    await storageRemove(storageKeys.cloudTeams);
    await storageRemove(storageKeys.cloudSelectedTeam);
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
  state.leakSourceHost = null;
  state.inspectedHost = null;
  state.cloud.identity = null;
  state.cloud.link = null;
  state.cloud.origin = null;
  state.cloud.lastShareUrl = null;
  state.cloud.teams = [];
  state.cloud.selectedTeamId = null;
  state.cloud.teamsFetchedAt = 0;
  state.cloud.supportsTeamEndpoint = true;
  setShareReportLink(null);
  clearCloudPolling();
  renderTablesList();
  updateReportButtonState();
  updateTermsControls();
  ensureTermsPromise();
  showTermsModal({ enforce: true });
  setStatus("Consent withdrawn. Accept the Terms to resume.", "error");
  updateLinkModalUi();
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

function normalizeOrigin(origin) {
  if (!origin || typeof origin !== "string") {
    return null;
  }
  const trimmed = origin.trim();
  if (!trimmed) {
    return null;
  }
  return trimmed.replace(/\/+$/, "");
}

function buildOriginCandidates(primary = null) {
  const seen = new Set();
  const push = (value) => {
    const normalized = normalizeOrigin(value);
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
    }
  };
  push(primary);
  push(state.cloud.link?.origin);
  push(state.cloud.origin);
  const configured = Array.isArray(cloudConfig?.origins) ? cloudConfig.origins : [];
  configured.forEach(push);
  return Array.from(seen);
}

function normalizeTeam(entry) {
  if (!entry || typeof entry !== "object") {
    return null;
  }
  const idValue = entry.id ?? entry.uuid ?? null;
  const id = typeof idValue === "number"
    ? String(idValue)
    : (typeof idValue === "string" && idValue.trim() ? idValue.trim() : null);
  const slug = typeof entry.slug === "string" && entry.slug.trim() ? entry.slug.trim() : null;
  const name = typeof entry.name === "string" && entry.name.trim() ? entry.name.trim() : null;
  const role = typeof entry.role === "string" && entry.role.trim() ? entry.role.trim() : null;
  const safeId = id || slug;
  if (!safeId) {
    return null;
  }
  return {
    id: safeId,
    name: name || slug || id,
    slug: slug || null,
    role: role || entry.role || null,
  };
}

function generateRandomSecret(byteLength = CLOUD_SECRET_BYTES) {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
      const array = new Uint8Array(byteLength);
      crypto.getRandomValues(array);
      return Array.from(array)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    }
  } catch (error) {
    // Ignore and fall through.
  }
  return `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`;
}

async function ensureCloudIdentity() {
  if (state.cloud.identity?.instanceId && state.cloud.identity?.secret) {
    return state.cloud.identity;
  }
  const stored = await storageGet(storageKeys.cloudIdentity);
  let identity = stored?.[storageKeys.cloudIdentity];
  const hasStored = identity?.instanceId && identity?.secret;
  if (!hasStored) {
    identity = {
      instanceId: typeof crypto?.randomUUID === "function" ? crypto.randomUUID() : `sbde_${generateRandomSecret(12)}`,
      secret: generateRandomSecret(),
      createdAt: new Date().toISOString(),
    };
    await storageSet({ [storageKeys.cloudIdentity]: identity });
  }
  state.cloud.identity = identity;
  return identity;
}

async function persistCloudOrigin(origin) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) {
    return;
  }
  state.cloud.origin = normalized;
  await storageSet({ [storageKeys.cloudOrigin]: normalized });
}

async function loadStoredCloudOrigin() {
  const stored = await storageGet(storageKeys.cloudOrigin);
  const origin = normalizeOrigin(stored?.[storageKeys.cloudOrigin]);
  if (origin) {
    state.cloud.origin = origin;
  }
}

async function setCloudTeams(teams, { persist = true, fetchedAt = Date.now() } = {}) {
  const normalized = Array.isArray(teams) ? teams.map(normalizeTeam).filter(Boolean) : [];
  state.cloud.teams = normalized;
  state.cloud.teamsFetchedAt = normalized.length ? fetchedAt || Date.now() : 0;
  if (persist) {
    await storageSet({
      [storageKeys.cloudTeams]: {
        teams: normalized,
        fetchedAt: state.cloud.teamsFetchedAt,
      },
    });
  }
  if (normalized.length && state.cloud.selectedTeamId && !normalized.some((team) => team.id === state.cloud.selectedTeamId)) {
    await setSelectedTeam(normalized[0].id, { allowFallback: true });
  } else if (!normalized.length) {
    await setSelectedTeam(null, { allowFallback: false, persist });
  }
  updateTeamPickerUi();
  return normalized;
}

async function loadStoredCloudTeams() {
  const stored = await storageGet(storageKeys.cloudTeams);
  const record = stored?.[storageKeys.cloudTeams];
  const teams = Array.isArray(record?.teams) ? record.teams : [];
  const fetchedAt = typeof record?.fetchedAt === "number" ? record.fetchedAt : 0;
  return setCloudTeams(teams, { persist: false, fetchedAt });
}

function getSelectedTeam() {
  if (!state.cloud.selectedTeamId) {
    return null;
  }
  const targetId = String(state.cloud.selectedTeamId);
  return state.cloud.teams.find((team) => String(team.id) === targetId) || null;
}

async function setSelectedTeam(teamId, { persist = true, allowFallback = true } = {}) {
  const normalized = typeof teamId === "number"
    ? String(teamId)
    : (typeof teamId === "string" && teamId.trim() ? teamId.trim() : null);
  const hasTeam = normalized && state.cloud.teams.some((team) => team.id === normalized);
  let nextId = hasTeam ? normalized : null;
  if (!nextId && allowFallback && state.cloud.teams.length) {
    nextId = state.cloud.teams[0].id;
  }
  state.cloud.selectedTeamId = nextId;
  if (state.cloud.link) {
    state.cloud.link.selectedTeamId = nextId || null;
  }
  if (persist) {
    await storageSet({ [storageKeys.cloudSelectedTeam]: nextId || null });
    if (state.cloud.link) {
      await storageSet({ [storageKeys.cloudLink]: { ...state.cloud.link, selectedTeamId: nextId || null } });
    }
  }
  updateTeamPickerUi();
  updateLinkModalUi();
  return nextId;
}

async function loadStoredSelectedTeam() {
  const stored = await storageGet(storageKeys.cloudSelectedTeam);
  const raw = stored?.[storageKeys.cloudSelectedTeam];
  const nextId = typeof raw === "number"
    ? String(raw)
    : (typeof raw === "string" ? raw : null);
  await setSelectedTeam(nextId, { persist: false });
}

async function refreshSelectedTeamFromStorage() {
  const stored = await storageGet(storageKeys.cloudSelectedTeam);
  const raw = stored?.[storageKeys.cloudSelectedTeam];
  const nextId = typeof raw === "number" ? String(raw) : (typeof raw === "string" ? raw : null);
  if (nextId) {
    await setSelectedTeam(nextId, { persist: false, allowFallback: false });
  }
}

function setTeamStatus(message, tone = "muted") {
  if (!dom.linkTeamStatus) {
    return;
  }
  dom.linkTeamStatus.textContent = message || "";
  dom.linkTeamStatus.classList.remove("success", "error");
  if (tone === "success") {
    dom.linkTeamStatus.classList.add("success");
  } else if (tone === "error") {
    dom.linkTeamStatus.classList.add("error");
  }
}

function updateTeamPickerUi() {
  if (!dom.linkTeamSection || !dom.linkTeamSelect) {
    return;
  }
  const linked = isCloudLinked();
  dom.linkTeamSection.classList.toggle("disabled", !linked);
  if (dom.linkTeamRefreshBtn) {
    dom.linkTeamRefreshBtn.disabled = !linked || state.cloud.isBusy || state.isSharingReport || state.cloud.isFetchingTeams;
    dom.linkTeamRefreshBtn.classList.toggle("is-busy", state.cloud.isFetchingTeams);
  }

  const select = dom.linkTeamSelect;
  select.innerHTML = "";
  if (!linked) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Link to SupaExplorer Cloud to load teams";
    select.appendChild(option);
    select.disabled = true;
    setTeamStatus("Link to SupaExplorer Cloud to load teams.");
    return;
  }

  if (state.cloud.isFetchingTeams) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Refreshing teams…";
    select.appendChild(option);
    select.disabled = true;
    setTeamStatus("Refreshing teams…");
    return;
  }

  if (!state.cloud.teams.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No teams available";
    select.appendChild(option);
    select.disabled = true;
    setTeamStatus("No teams available for this account.", "error");
    return;
  }

  state.cloud.teams.forEach((team) => {
    const option = document.createElement("option");
    option.value = team.id;
    option.textContent = team.name || team.slug || team.id;
    if (team.slug) {
      option.dataset.slug = team.slug;
    }
    option.selected = team.id === state.cloud.selectedTeamId;
    select.appendChild(option);
  });
  select.disabled = false;
  const selected = getSelectedTeam();
  const label = selected?.name || selected?.slug || "a team";
  setTeamStatus(`Reports will sync to ${label}.`, "success");
}

async function persistCloudLink(link) {
  if (!link) {
    state.cloud.link = null;
    state.cloud.lastStatusCheck = 0;
    state.cloud.lastShareUrl = null;
    state.cloud.teams = [];
    state.cloud.selectedTeamId = null;
    state.cloud.teamsFetchedAt = 0;
    state.cloud.supportsTeamEndpoint = true;
    setShareReportLink(null);
    await storageRemove(storageKeys.cloudLink);
    await storageRemove(storageKeys.cloudTeams);
    await storageRemove(storageKeys.cloudSelectedTeam);
    return;
  }
  state.cloud.link = link;
  state.cloud.lastStatusCheck = Date.now();
  await storageSet({ [storageKeys.cloudLink]: link });
  const preferredSelectedId = state.cloud.selectedTeamId || link.selectedTeamId || null;
  if (Array.isArray(link.teams)) {
    await setCloudTeams(link.teams, { fetchedAt: Date.parse(link.lastStatusAt) || Date.now() });
  }
  if (preferredSelectedId) {
    await setSelectedTeam(preferredSelectedId, { allowFallback: true });
  } else if (!state.cloud.selectedTeamId && state.cloud.teams.length) {
    await setSelectedTeam(state.cloud.teams[0].id, { allowFallback: true });
  }
}

function normalizeCloudLinkPayload(payload, originOverride) {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  const data = payload.data && typeof payload.data === "object" ? payload.data : payload;
  const linkCode = typeof data.linkCode === "string" ? data.linkCode : typeof data.code === "string" ? data.code : null;
  if (!linkCode) {
    return null;
  }
  const statusRaw = typeof data.status === "string" ? data.status.toLowerCase() : "";
  const status = statusRaw === "linked" ? CLOUD_STATUS.LINKED : statusRaw === "pending"
    ? CLOUD_STATUS.PENDING
    : statusRaw === "revoked"
      ? CLOUD_STATUS.DISCONNECTED
      : CLOUD_STATUS.ERROR;
  const linkedUser = typeof data.linkedUser === "object" && data.linkedUser ? data.linkedUser : null;
  const linkUrl = typeof data.linkUrl === "string" ? data.linkUrl : null;
  const pollUrl = typeof data.pollUrl === "string" ? data.pollUrl : null;
  const manageUrl = typeof data.manageUrl === "string" ? data.manageUrl : null;
  const teamsPayload = Array.isArray(data.teams)
    ? data.teams
    : Array.isArray(data.availableTeams)
      ? data.availableTeams
      : [];
  const teams = teamsPayload.map(normalizeTeam).filter(Boolean);
  const rawTeamId = data.teamId ?? data.selectedTeamId ?? null;
  const selectedTeamId = typeof rawTeamId === "number"
    ? String(rawTeamId)
    : (typeof rawTeamId === "string" && rawTeamId.trim() ? rawTeamId.trim() : null);
  return {
    code: linkCode,
    status,
    linkUrl,
    pollUrl,
    manageUrl: manageUrl || (originOverride ? `${originOverride}${cloudConfig.managePath}` : null),
    origin: normalizeOrigin(data.origin || originOverride),
    expiresAt: typeof data.expiresAt === "string" ? data.expiresAt : null,
    linkedAt: typeof data.linkedAt === "string" ? data.linkedAt : null,
    linkedUser,
    teams,
    selectedTeamId: selectedTeamId || (teams.length ? teams[0].id : null),
    lastStatusAt: new Date().toISOString(),
  };
}

function describeLinkStatus(status, link) {
  if (!state.termsAccepted) {
    return "Accept the Terms & Conditions before linking to SupaExplorer Cloud.";
  }
  if (state.cloud.lastError) {
    return state.cloud.lastError;
  }
  if (!link) {
    return "Link this browser extension to SupaExplorer Cloud to enable user seats and collaboration.";
  }
  if (status === CLOUD_STATUS.LINKED) {
    const account = link?.linkedUser?.name || link?.linkedUser?.email;
    const team = getSelectedTeam();
    const teamNote = team ? ` Reports will sync to ${team.name || team.slug || "this team"}.` : "";
    return account
      ? `Linked to ${account}. Teams and billing now use this browser seat.${teamNote}`
      : `Linked to SupaExplorer Cloud. Manage seats from the dashboard.${teamNote}`;
  }
  if (status === CLOUD_STATUS.PENDING) {
    return "We opened the cloud console in a new tab. Approve the link request there to finish.";
  }
  if (status === CLOUD_STATUS.ERROR) {
    return "Link status unavailable. Try again or relaunch the extension.";
  }
  return "No SupaExplorer Cloud account is connected to this extension.";
}

function formatTimestamp(value) {
  if (!value) {
    return "—";
  }
  try {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  } catch (error) {
    return value;
  }
}

function updateLinkModalUi() {
  if (!dom.linkStatusPill) {
    return;
  }
  const link = state.cloud.link;
  const status = link?.status || CLOUD_STATUS.DISCONNECTED;
  updateStatusCheckButton(status);
  dom.linkStatusPill.classList.remove("link-status-success", "link-status-error", "link-status-progress");
  if (status === CLOUD_STATUS.LINKED) {
    dom.linkStatusPill.classList.add("link-status-success");
    dom.linkStatusPill.textContent = "Connected";
  } else if (status === CLOUD_STATUS.PENDING) {
    dom.linkStatusPill.classList.add("link-status-progress");
    dom.linkStatusPill.textContent = "Pending approval";
  } else if (status === CLOUD_STATUS.ERROR) {
    dom.linkStatusPill.classList.add("link-status-error");
    dom.linkStatusPill.textContent = "Error";
  } else {
    dom.linkStatusPill.textContent = "Not connected";
  }
  if (dom.linkStatusMessage) {
    dom.linkStatusMessage.textContent = describeLinkStatus(status, link);
  }
  const showMeta = status === CLOUD_STATUS.LINKED;
  if (dom.linkStatusMeta) {
    dom.linkStatusMeta.classList.toggle("hidden", !showMeta);
  }
  if (dom.linkStatusAccount) {
    dom.linkStatusAccount.textContent = link?.linkedUser?.name || link?.linkedUser?.email || "—";
  }
  if (dom.linkStatusLinkedAt) {
    dom.linkStatusLinkedAt.textContent = formatTimestamp(link?.linkedAt);
  }
  if (dom.linkStatusInstance) {
    dom.linkStatusInstance.textContent = state.cloud.identity?.instanceId || "—";
  }
  if (dom.linkConnectBtn) {
    dom.linkConnectBtn.classList.toggle("hidden", status === CLOUD_STATUS.LINKED);
    dom.linkConnectBtn.disabled = Boolean(state.cloud.isBusy);
  }
  if (dom.linkManageBtn) {
    dom.linkManageBtn.classList.toggle("hidden", status !== CLOUD_STATUS.LINKED);
  }
  if (dom.linkDisconnectBtn) {
    dom.linkDisconnectBtn.classList.toggle("hidden", status !== CLOUD_STATUS.LINKED);
    dom.linkDisconnectBtn.disabled = Boolean(state.cloud.isBusy);
  }
  updateTeamPickerUi();
  updateShareReportAvailability();
}

function updateStatusCheckButton(status) {
  const btn = dom.statusCheckBtn;
  if (!btn) {
    return;
  }
  const icon = btn.querySelector(".status-check-icon");
  const normalized = status === CLOUD_STATUS.LINKED ? "linked" : status === CLOUD_STATUS.PENDING ? "pending" : "disconnected";
  btn.dataset.cloudStatus = normalized;
  if (icon) {
    icon.dataset.status = normalized;
  }
}

function openLinkModal() {
  if (!dom.linkModal) {
    return;
  }
  state.cloud.isModalOpen = true;
  updateLinkModalUi();
  dom.linkModal.classList.remove("hidden");
  if (isCloudLinked()) {
    ensureTeamsLoaded({ force: false, silent: true }).catch((error) => {
      console.warn("Team preload failed", error);
    });
  }
}

function closeLinkModal() {
  if (!dom.linkModal) {
    return;
  }
  state.cloud.isModalOpen = false;
  dom.linkModal.classList.add("hidden");
}

function handleLinkModalKeydown(event) {
  if (event.key === "Escape" && state.cloud.isModalOpen) {
    closeLinkModal();
  }
}

function setCloudBusy(isBusy) {
  state.cloud.isBusy = Boolean(isBusy);
  if (dom.linkConnectBtn) {
    dom.linkConnectBtn.classList.toggle("is-busy", state.cloud.isBusy);
    dom.linkConnectBtn.disabled = state.cloud.isBusy;
  }
  if (dom.linkDisconnectBtn) {
    dom.linkDisconnectBtn.classList.toggle("is-busy", state.cloud.isBusy);
    dom.linkDisconnectBtn.disabled = state.cloud.isBusy;
  }
  updateShareReportAvailability();
  updateTeamPickerUi();
}

function getExtensionLinksPath(code) {
  const base = typeof cloudConfig?.api?.extensionLinks === "string"
    ? cloudConfig.api.extensionLinks
    : "/api/extension-links";
  const normalized = base.startsWith("/") ? base : `/${base}`;
  if (!code) {
    return normalized;
  }
  return `${normalized}/${encodeURIComponent(code)}`;
}

async function requestCloudLinkApi({ method = "GET", code = null, body = null, includeSecret = true, preferOrigin = null, pathSuffix = "" } = {}) {
  const identity = await ensureCloudIdentity();
  const headers = {
    accept: "application/json",
  };
  if (body) {
    headers["content-type"] = "application/json";
  }
  if (includeSecret && identity?.secret) {
    headers[CLOUD_SECRET_HEADER] = identity.secret;
  }
  const basePath = getExtensionLinksPath(code);
  const suffix = pathSuffix ? (pathSuffix.startsWith("/") ? pathSuffix : `/${pathSuffix}`) : "";
  const path = `${basePath}${suffix}`;
  const candidates = buildOriginCandidates(preferOrigin);
  if (!candidates.length) {
    throw new Error("No SupaExplorer Cloud origin available.");
  }
  let lastNetworkError = null;
  for (const origin of candidates) {
    const url = `${origin}${path}`;
    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        credentials: "omit",
      });
      if (response.status === 204) {
        await persistCloudOrigin(origin);
        return { ok: true, data: null, origin };
      }
      let payload = null;
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
      if (!response.ok) {
        const message = (payload && (payload.message || payload.error)) || `Cloud request failed (${response.status})`;
        const error = new Error(message);
        error.status = response.status;
        error.response = payload;
        error.origin = origin;
        error.code = payload?.error || payload?.code || null;
        throw error;
      }
      await persistCloudOrigin(origin);
      return { ok: true, data: payload, origin };
    } catch (error) {
      if (error instanceof TypeError || error.name === "TypeError") {
        lastNetworkError = error;
        continue;
      }
      throw error;
    }
  }
  if (lastNetworkError) {
    throw lastNetworkError;
  }
  throw new Error("Unable to reach SupaExplorer Cloud.");
}

async function fetchCloudTeams({ silent = false } = {}) {
  if (!state.cloud.link?.code) {
    if (!silent) {
      setTeamStatus("Link to SupaExplorer Cloud to load teams.");
    }
    return [];
  }
  if (!state.cloud.supportsTeamEndpoint) {
    if (!silent) {
      setTeamStatus("Teams endpoint not available yet. Using default team.", "error");
    }
    return state.cloud.teams;
  }
  state.cloud.isFetchingTeams = true;
  updateTeamPickerUi();
  try {
    const previousSelection = state.cloud.selectedTeamId || null;
    const response = await requestCloudLinkApi({
      method: "GET",
      code: state.cloud.link.code,
      includeSecret: true,
      preferOrigin: state.cloud.link.origin,
      pathSuffix: "/teams",
    });
    const payload = response?.data;
    const teams = Array.isArray(payload?.teams)
      ? payload.teams
      : Array.isArray(payload)
        ? payload
        : [];
    const selectedTeamId = payload?.teamId ?? payload?.selectedTeamId ?? null;
    await setCloudTeams(teams, { fetchedAt: Date.now() });
    if (previousSelection && state.cloud.teams.some((t) => String(t.id) === String(previousSelection))) {
      await setSelectedTeam(previousSelection, { allowFallback: false });
    } else if (selectedTeamId !== undefined && selectedTeamId !== null) {
      await setSelectedTeam(selectedTeamId, { allowFallback: true });
    } else if (state.cloud.teams.length) {
      await setSelectedTeam(state.cloud.teams[0].id, { allowFallback: true });
    }
    if (state.cloud.teams.length) {
      if (!silent) {
        const label = getSelectedTeam()?.name || getSelectedTeam()?.slug || "your team";
        setTeamStatus(`Reports will sync to ${label}.`, "success");
      }
    } else if (!silent) {
      setTeamStatus("No teams available for this account.", "error");
    }
    return state.cloud.teams;
  } catch (error) {
    const status = error?.status || error?.response?.status;
    if (status === 404) {
      state.cloud.supportsTeamEndpoint = false;
      if (!silent) {
        setTeamStatus("Teams endpoint not enabled on this cloud instance.", "error");
      }
      return state.cloud.teams;
    }
    console.error("Failed to fetch teams", error);
    if (!silent) {
      setTeamStatus("Could not refresh teams. Try again.", "error");
    }
    return state.cloud.teams;
  } finally {
    state.cloud.isFetchingTeams = false;
    updateTeamPickerUi();
  }
}

async function ensureTeamsLoaded({ force = false, silent = false } = {}) {
  if (!isCloudLinked()) {
    return [];
  }
  if (!force && state.cloud.teams.length) {
    return state.cloud.teams;
  }
  return fetchCloudTeams({ silent });
}

async function createCloudLinkSession() {
  const identity = await ensureCloudIdentity();
  const payload = {
    installation_id: identity.instanceId,
    secret: identity.secret,
    extension_version: EXTENSION_VERSION,
    platform: navigator?.userAgentData?.platform || navigator?.platform || "unknown",
    user_agent: navigator?.userAgent?.slice(0, 400) || "unknown",
    channel: "chrome_extension",
  };
  const response = await requestCloudLinkApi({ method: "POST", body: payload, includeSecret: false });
  const normalized = normalizeCloudLinkPayload(response.data, response.origin);
  if (!normalized) {
    throw new Error("Unexpected response from SupaExplorer Cloud.");
  }
  await persistCloudLink(normalized);
  state.cloud.lastError = null;
  return normalized;
}

async function fetchCloudLinkStatus(preferOrigin) {
  const link = state.cloud.link;
  if (!link?.code) {
    return null;
  }
  const response = await requestCloudLinkApi({
    method: "GET",
    code: link.code,
    includeSecret: true,
    preferOrigin: preferOrigin || link.origin,
  });
  const normalized = normalizeCloudLinkPayload(response.data, response.origin || link.origin);
  if (!normalized) {
    throw new Error("Link status missing.");
  }
  await persistCloudLink(normalized);
  state.cloud.lastError = null;
  return normalized;
}

async function pollCloudLinkStatus({ silent = false } = {}) {
  if (!state.cloud.link?.code) {
    return null;
  }
  try {
    const next = await fetchCloudLinkStatus();
    if (next?.status === CLOUD_STATUS.LINKED) {
      clearCloudPolling();
      setStatus("Extension linked to SupaExplorer Cloud.", "success");
      await ensureTeamsLoaded({ force: true, silent: true });
    } else if (next?.status === CLOUD_STATUS.DISCONNECTED) {
      clearCloudPolling();
    }
    updateLinkModalUi();
    return next;
  } catch (error) {
    if (!silent) {
      state.cloud.lastError = error instanceof Error ? error.message : String(error || "Link status failed.");
      setStatus(state.cloud.lastError, "error");
      updateLinkModalUi();
    }
    throw error;
  }
}

function clearCloudPolling() {
  if (state.cloud.pollTimer) {
    clearInterval(state.cloud.pollTimer);
    state.cloud.pollTimer = null;
  }
}

function scheduleCloudPolling({ immediate = true } = {}) {
  clearCloudPolling();
  if (!state.cloud.link?.code || state.cloud.link.status !== CLOUD_STATUS.PENDING) {
    return;
  }
  state.cloud.pollTimer = setInterval(() => {
    pollCloudLinkStatus({ silent: true }).catch((error) => {
      console.warn("Cloud polling failed", error);
    });
  }, LINK_POLL_INTERVAL_MS);
  if (immediate) {
    pollCloudLinkStatus({ silent: true }).catch((error) => {
      console.warn("Initial cloud poll failed", error);
    });
  }
}

async function handleTeamRefreshClick(event) {
  event?.preventDefault?.();
  if (!isCloudLinked()) {
    setTeamStatus("Link to SupaExplorer Cloud to load teams.", "error");
    return;
  }
  const stillLinked = await ensureCloudStatusFresh({ force: true });
  if (!stillLinked) {
    setTeamStatus("Cloud link revoked. Reconnect to refresh teams.", "error");
    return;
  }
  await fetchCloudTeams({ silent: false }).catch(() => {
    // Error already surfaced in fetchCloudTeams
  });
}

function handleTeamSelectChange(event) {
  const value = event?.target?.value || "";
  setSelectedTeam(value || null, { allowFallback: true });
}

async function handleCloudLinkConnect() {
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  await ensureCloudIdentity();
  setCloudBusy(true);
  try {
    const link = await createCloudLinkSession();
    updateLinkModalUi();
    if (link.status === CLOUD_STATUS.PENDING && link.linkUrl) {
      try {
        chrome.tabs.create({ url: link.linkUrl, active: true }, () => {
          if (chrome.runtime.lastError) {
            console.error("Failed to open SupaExplorer Cloud tab", chrome.runtime.lastError);
          }
        });
      } catch (error) {
        console.error("Failed to open SupaExplorer Cloud tab", error);
      }
      scheduleCloudPolling({ immediate: true });
    } else if (link.status === CLOUD_STATUS.LINKED) {
      clearCloudPolling();
      setStatus("Extension already linked to SupaExplorer Cloud.", "success");
      await ensureTeamsLoaded({ force: true, silent: false }).catch(() => {
        // Errors handled in fetchCloudTeams
      });
    }
  } catch (error) {
    state.cloud.lastError = error instanceof Error ? error.message : String(error || "Failed to start linking.");
    setStatus(state.cloud.lastError, "error");
    updateLinkModalUi();
  } finally {
    setCloudBusy(false);
  }
}

async function handleCloudLinkDisconnect() {
  if (!state.cloud.link?.code) {
    return;
  }
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  setCloudBusy(true);
  try {
    await requestCloudLinkApi({
      method: "DELETE",
      code: state.cloud.link.code,
      includeSecret: true,
      preferOrigin: state.cloud.link.origin,
    });
    clearCloudPolling();
    await persistCloudLink(null);
    state.cloud.lastError = null;
    updateLinkModalUi();
    setStatus("Disconnected from SupaExplorer Cloud.", "success");
  } catch (error) {
    state.cloud.lastError = error instanceof Error ? error.message : String(error || "Failed to disconnect.");
    setStatus(state.cloud.lastError, "error");
    updateLinkModalUi();
  } finally {
    setCloudBusy(false);
  }
}

function handleCloudLinkManage() {
  const manageUrl = state.cloud.link?.manageUrl || (state.cloud.origin ? `${state.cloud.origin}${cloudConfig.managePath}` : null);
  if (!manageUrl) {
    setStatus("Manage URL unavailable. Link the extension first.", "error");
    return;
  }
  try {
    chrome.tabs.create({ url: manageUrl, active: true }, () => {
      if (chrome.runtime.lastError) {
        console.error("Failed to open manage link", chrome.runtime.lastError);
      }
    });
  } catch (error) {
    console.error("Failed to open manage link", error);
  }
}

function initLinkingUi() {
  if (dom.statusCheckBtn) {
    dom.statusCheckBtn.addEventListener("click", async () => {
      if (!enforceTermsAccess({ showModal: true })) {
        return;
      }
      await ensureCloudIdentity();
      updateLinkModalUi();
      openLinkModal();
    });
  }
  if (dom.linkModalBackdrop) {
    dom.linkModalBackdrop.addEventListener("click", closeLinkModal);
  }
  if (dom.linkModalCloseBtn) {
    dom.linkModalCloseBtn.addEventListener("click", closeLinkModal);
  }
  if (dom.linkConnectBtn) {
    dom.linkConnectBtn.addEventListener("click", handleCloudLinkConnect);
  }
  if (dom.linkManageBtn) {
    dom.linkManageBtn.addEventListener("click", handleCloudLinkManage);
  }
  if (dom.linkDisconnectBtn) {
    dom.linkDisconnectBtn.addEventListener("click", handleCloudLinkDisconnect);
  }
  if (dom.linkTeamRefreshBtn) {
    dom.linkTeamRefreshBtn.addEventListener("click", handleTeamRefreshClick);
  }
  if (dom.linkTeamSelect) {
    dom.linkTeamSelect.addEventListener("change", handleTeamSelectChange);
  }
  document.addEventListener("keydown", handleLinkModalKeydown);
}

async function bootstrapCloudLinking() {
  if (!state.termsAccepted) {
    return;
  }
  try {
    await ensureCloudIdentity();
    await loadStoredCloudOrigin();
    await loadStoredCloudTeams();
    await loadStoredSelectedTeam();
    const stored = await storageGet(storageKeys.cloudLink);
    const link = stored?.[storageKeys.cloudLink];
    if (link) {
      const normalized = link.code ? link : normalizeCloudLinkPayload(link, link.origin);
      state.cloud.link = normalized;
      state.cloud.lastStatusCheck = normalized?.lastStatusAt ? Date.parse(normalized.lastStatusAt) || 0 : 0;
      if (normalized?.status === CLOUD_STATUS.PENDING) {
        scheduleCloudPolling({ immediate: false });
      }
    } else {
      state.cloud.link = null;
      state.cloud.lastStatusCheck = 0;
    }
    updateLinkModalUi();
    if (isCloudLinked() && !state.cloud.teams.length) {
      await ensureTeamsLoaded({ force: true, silent: true });
    }
  } catch (error) {
    console.error("Failed to bootstrap cloud linking", error);
  }
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
        inspectedHost: typeof connection.inspectedHost === "string" ? sanitize(connection.inspectedHost) : "",
      }
    : {
        projectId: "",
        schema: "public",
        apiKey: "",
        bearer: "",
        inspectedHost: "",
      };

  state.connection = normalized;
  state.baseUrl = normalized.projectId ? buildBaseUrl(normalized.projectId) : "";
  if (normalized.inspectedHost) {
    state.connection.inspectedHost = normalized.inspectedHost;
    state.inspectedHost = normalized.inspectedHost;
  } else if (!connection) {
    state.connection.inspectedHost = "";
    state.inspectedHost = null;
  }

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

function deriveHostnameFromUrl(url) {
  if (!url || typeof url !== "string") {
    return null;
  }
  try {
    const { hostname } = new URL(url);
    if (hostname) {
      return sanitize(hostname);
    }
  } catch (error) {
    // Ignore invalid URLs.
  }
  return null;
}

function normalizeLeakDetectionEntry(entry, fallbackHost) {
  const sourceUrl = typeof entry?.sourceUrl === "string" ? entry.sourceUrl : "";
  const assetUrl = typeof entry?.assetUrl === "string" ? entry.assetUrl : "";
  const pattern = typeof entry?.pattern === "string" ? entry.pattern : "";
  const matchSnippet = typeof entry?.matchSnippet === "string" ? entry.matchSnippet : "";
  const contextSnippet = typeof entry?.contextSnippet === "string" ? entry.contextSnippet : "";
  const encodedSnippet = typeof entry?.encodedSnippet === "string" ? entry.encodedSnippet : "";
  const detectedAt = typeof entry?.detectedAt === "string" ? entry.detectedAt : "";
  const hostCandidate =
    (typeof entry?.host === "string" && entry.host) ||
    deriveHostnameFromUrl(sourceUrl || assetUrl) ||
    fallbackHost ||
    "";
  const detectedHost = hostCandidate ? sanitize(hostCandidate) : "";

  return {
    detectedHost,
    sourceUrl,
    assetUrl,
    pattern,
    matchSnippet,
    contextSnippet,
    encodedSnippet,
    detectedAt,
  };
}

function dedupeAndSortLeakDetections(entries) {
  if (!Array.isArray(entries) || !entries.length) {
    return [];
  }
  const seen = new Set();
  const filtered = entries.filter((entry) => {
    const key = `${entry.pattern}|${entry.matchSnippet}|${entry.sourceUrl}|${entry.detectedAt}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
  return filtered.sort((a, b) => {
    const aTime = new Date(a.detectedAt || 0).getTime();
    const bTime = new Date(b.detectedAt || 0).getTime();
    return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
  });
}

function buildLeakSnapshotFromBuckets(buckets) {
  if (!Array.isArray(buckets) || !buckets.length) {
    return { host: null, leakDetections: [] };
  }
  const normalized = buckets.flatMap(({ host, entries }) => {
    if (!Array.isArray(entries) || !entries.length) {
      return [];
    }
    return entries.map((entry) => normalizeLeakDetectionEntry(entry, host));
  });
  const leakDetections = dedupeAndSortLeakDetections(normalized);
  const snapshotHost = leakDetections.length ? leakDetections[0].detectedHost : buckets[0]?.host || null;
  return {
    host: snapshotHost || null,
    leakDetections,
  };
}

function buildLeakSnapshotForHost(map, hostname) {
  if (!hostname || !map || typeof map !== "object") {
    return { host: null, leakDetections: [] };
  }
  const rootDomain = deriveRootDomain(hostname);
  const buckets = [];
  if (Array.isArray(map[hostname])) {
    buckets.push({ host: hostname, entries: map[hostname] });
  }
  if (rootDomain && rootDomain !== hostname && Array.isArray(map[rootDomain])) {
    buckets.push({ host: rootDomain, entries: map[rootDomain] });
  }
  if (!buckets.length) {
    return { host: null, leakDetections: [] };
  }
  const snapshot = buildLeakSnapshotFromBuckets(buckets);
  if (!snapshot.host) {
    snapshot.host = hostname;
  }
  return snapshot;
}

function findMostRecentLeakSnapshot(map, excludedHosts = new Set()) {
  if (!map || typeof map !== "object") {
    return { host: null, leakDetections: [] };
  }
  const exclude = excludedHosts instanceof Set ? excludedHosts : new Set(excludedHosts);
  let bestHost = null;
  let bestDetections = [];
  let freshestTimestamp = 0;

  Object.entries(map).forEach(([hostKey, entries]) => {
    if (exclude.has(hostKey) || !Array.isArray(entries) || !entries.length) {
      return;
    }
    const snapshot = buildLeakSnapshotFromBuckets([{ host: hostKey, entries }]);
    if (!snapshot.leakDetections.length) {
      return;
    }
    const newestTime = new Date(snapshot.leakDetections[0].detectedAt || 0).getTime();
    if (!Number.isFinite(newestTime)) {
      return;
    }
    if (newestTime > freshestTimestamp) {
      freshestTimestamp = newestTime;
      bestHost = snapshot.host || hostKey;
      bestDetections = snapshot.leakDetections;
    }
  });

  return { host: bestHost, leakDetections: bestDetections };
}

async function fetchLeakDetectionMap() {
  const stored = await storageGet(LEAK_DETECTIONS_KEY);
  const map = stored?.[LEAK_DETECTIONS_KEY];
  if (!map || typeof map !== "object") {
    return null;
  }
  return map;
}

async function loadLeakDetectionSnapshot(preferredHosts = []) {
  const map = await fetchLeakDetectionMap();
  if (!map) {
    return { host: null, leakDetections: [] };
  }
  const candidates = Array.isArray(preferredHosts)
    ? preferredHosts.filter(
        (host, index, array) => typeof host === "string" && host && array.indexOf(host) === index
      )
    : [];
  for (const candidate of candidates) {
    const snapshot = buildLeakSnapshotForHost(map, candidate);
    if (snapshot.leakDetections.length) {
      return snapshot;
    }
  }
  const fallback = findMostRecentLeakSnapshot(map, new Set(candidates));
  if (fallback.leakDetections.length) {
    return fallback;
  }
  return { host: null, leakDetections: [] };
}

async function loadLeakDetectionsForHost(hostname) {
  if (!hostname) {
    return [];
  }
  const map = await fetchLeakDetectionMap();
  if (!map) {
    return [];
  }
  const snapshot = buildLeakSnapshotForHost(map, hostname);
  return snapshot.leakDetections;
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
    state.leakSourceHost = null;
    updateReportButtonState();
    return;
  }
  const resolvedHost = await resolveInspectedHost();
  const host = resolvedHost ? sanitize(resolvedHost) : "";
  const projectId = state.connection?.projectId ? sanitize(state.connection.projectId) : "";
  const [assetDetections, leakDetections] = await Promise.all([
    projectId ? loadAssetDetectionsForProject(projectId) : [],
    host ? loadLeakDetectionsForHost(host) : [],
  ]);
  state.assetDetections = assetDetections;
  state.leakDetections = leakDetections;
  state.leakSourceHost = leakDetections.length ? host : null;
  state.inspectedHost = host || null;
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

function getStoredConnectionHost() {
  return typeof state.connection?.inspectedHost === "string" ? sanitize(state.connection.inspectedHost) : "";
}

function getConnectionHost() {
  const storedHost = getStoredConnectionHost();
  if (storedHost) {
    return storedHost;
  }
  return state.inspectedHost || null;
}

async function ensureReportPrerequisites() {
  await refreshDetectionSnapshots();

  const hasSupabase = hasSupabaseContext();
  const hasDetections = hasDetectionFindings();
  const hasTables = Array.isArray(state.tables) && state.tables.length > 0;

  if (!hasSupabase && !hasDetections) {
    setStatus("Connect to Supabase or capture leak detections before generating a report.", "error");
    return false;
  }
  if (hasSupabase && !hasTables && !hasDetections) {
    setStatus("Load Supabase tables or capture leak detections before generating a report.", "error");
    return false;
  }
  return true;
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

function deriveTableRiskLevel({ name, rowCount }) {
  const normalizedCount = typeof rowCount === "number" && Number.isFinite(rowCount) ? rowCount : null;
  const normalizedName = typeof name === "string" ? name.toLowerCase() : "";
  const hasSensitiveName = SENSITIVE_TABLE_KEYWORDS.some((keyword) => normalizedName.includes(keyword));

  let risk = "high";

  if (normalizedCount !== null) {
    if (normalizedCount <= 0) {
      risk = "low";
    } else if (normalizedCount === 1) {
      risk = "medium";
    } else if (normalizedCount > 1) {
      risk = "high";
    }

    if (normalizedCount > 10) {
      risk = "critical";
    }
    if (hasSensitiveName && normalizedCount > 1) {
      risk = "critical";
    }
  } else if (hasSensitiveName) {
    risk = "high";
  }

  return risk;
}

function summarizeTableRisks(tables) {
  return (Array.isArray(tables) ? tables : []).reduce(
    (acc, table) => {
      const risk = table.riskLevel || deriveTableRiskLevel({ name: table.name, rowCount: table.rowCount });
      acc.max = elevateRiskLevel(acc.max, risk);
      acc.counts[risk] = (acc.counts[risk] || 0) + 1;
      return acc;
    },
    { max: "low", counts: { low: 0, medium: 0, high: 0, critical: 0 } }
  );
}

function aggregateTableRisk(tableRiskStats, totalTables) {
  const total = totalTables || Object.values(tableRiskStats.counts || {}).reduce((sum, val) => sum + val, 0);
  if (!total) return "low";
  const { counts } = tableRiskStats;
  const criticalShare = (counts.critical || 0) / total;
  const highPlusShare = ((counts.high || 0) + (counts.critical || 0)) / total;

  if ((counts.critical || 0) >= 4 || criticalShare >= 0.5) {
    return "critical";
  }
  if (((counts.high || 0) + (counts.critical || 0)) >= 3 || highPlusShare >= 0.3) {
    return "high";
  }
  if ((counts.medium || 0) > 0 || (counts.high || 0) > 0 || (counts.critical || 0) > 0) {
    return "medium";
  }
  return "low";
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

  updateShareReportAvailability();
}

function updateShareReportAvailability() {
  if (!dom.shareReportShareBtn) {
    return;
  }
  const isLinked = isCloudLinked();
  const prerequisitesMet = !(dom.reportBtn?.disabled);
  const needsTeamSelection = isLinked && state.cloud.teams.length > 0 && !state.cloud.selectedTeamId;
  const busy = state.isSharingReport || state.isGeneratingReport || state.cloud.isBusy || state.cloud.isCheckingStatus || state.cloud.isFetchingTeams;
  const shouldDisable = !isLinked || !prerequisitesMet || busy || needsTeamSelection;
  if (dom.shareReportShareBtn) {
    dom.shareReportShareBtn.disabled = shouldDisable;
    dom.shareReportShareBtn.classList.toggle("is-busy", state.isSharingReport);
    dom.shareReportShareBtn.classList.toggle("hidden", !isLinked);
    if (!isLinked) {
      dom.shareReportShareBtn.title = "Link this extension to SupaExplorer Cloud to enable sharing.";
    } else if (!prerequisitesMet) {
      dom.shareReportShareBtn.title = "Connect to Supabase or capture detections before sharing.";
    } else if (needsTeamSelection) {
      dom.shareReportShareBtn.title = "Select a team before sharing.";
    } else if (busy) {
      dom.shareReportShareBtn.title = "Sharing in progress…";
    } else {
      dom.shareReportShareBtn.title = "";
    }
  }
  if (dom.shareReportConnectBtn) {
    dom.shareReportConnectBtn.classList.toggle("hidden", isLinked);
    dom.shareReportConnectBtn.disabled = busy;
  }
  if (!isLinked) {
    setShareReportLink(null);
  }
}

function isCloudLinked() {
  return state.cloud.link?.status === CLOUD_STATUS.LINKED;
}

function toggleShareReportModal(visible) {
  if (!dom.shareReportModal) return;
  state.isShareReportOpen = Boolean(visible);
  dom.shareReportModal.classList.toggle("hidden", !visible);
  document.body?.classList.toggle("share-report-locked", Boolean(visible));
  if (visible) {
    dom.shareReportViewBtn?.focus();
  }
  if (!visible) {
    setShareReportNote(null);
    setShareReportLink(null);
    state.cloud.lastShareUrl = null;
  }
}

async function openShareReportModal(event) {
  event?.preventDefault();
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  if (dom.reportBtn?.disabled) {
    return;
  }
  await ensureCloudStatusFresh({ force: false });
  setShareReportLink(null);
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

async function copyTextToClipboard(text) {
  if (!text) {
    return false;
  }
  if (navigator?.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      // Fallback below.
    }
  }
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    const success = document.execCommand("copy");
    document.body.removeChild(textarea);
    return success;
  } catch (error) {
    return false;
  }
}

function setShareReportNote(message, type = null) {
  if (!dom.shareReportNote) {
    return;
  }
  const text = message || SHARE_REPORT_NOTE_DEFAULT;
  dom.shareReportNote.textContent = text;
  const isHighlight = Boolean(message && message !== SHARE_REPORT_NOTE_DEFAULT);
  
  // Remove all status classes
  dom.shareReportNote.classList.remove("share-report-note-highlight", "share-report-note-success");
  
  // Apply appropriate class based on type
  if (isHighlight && type === "success") {
    dom.shareReportNote.classList.add("share-report-note-success");
  } else if (isHighlight && type === "error") {
    dom.shareReportNote.classList.add("share-report-note-highlight");
  } else if (isHighlight) {
    // Default to error/warning style if no type specified (backwards compatibility)
    dom.shareReportNote.classList.add("share-report-note-highlight");
  }
}

function mapCloudQuotaError(error) {
  const code = error?.code || error?.response?.error || null;
  const messageFromApi = error?.response?.message || null;
  const status = error?.status || error?.response?.status || null;

  const upgradeNote = "Upgrade your SupaExplorer Cloud plan to continue sharing.";

  switch (code) {
    case "domain_limit_reached":
      return {
        message: messageFromApi || "Domain limit reached for your plan (per team).",
        note: upgradeNote,
      };
    case "report_limit_reached":
      return {
        message: messageFromApi || "Report limit reached for this domain on your plan.",
        note: upgradeNote,
      };
    case "share_links_disabled":
      return {
        message: messageFromApi || "Sharing is not available on your current plan.",
        note: upgradeNote,
      };
    default:
      if (status === 402) {
        return {
          message: messageFromApi || "This feature requires a higher plan.",
          note: upgradeNote,
        };
      }
      return {
        message: messageFromApi || (error instanceof Error ? error.message : "Cloud request failed."),
        note: null,
      };
  }
}

function setShareReportLink(link) {
  if (!dom.shareReportLink || !dom.shareReportLinkText) {
    return;
  }
  if (link) {
    dom.shareReportLink.classList.remove("hidden");
    dom.shareReportLinkText.textContent = link;
    if (dom.shareReportCopyBtn) {
      dom.shareReportCopyBtn.dataset.link = link;
    }
  } else {
    dom.shareReportLink.classList.add("hidden");
    dom.shareReportLinkText.textContent = "";
    if (dom.shareReportCopyBtn) {
      dom.shareReportCopyBtn.dataset.link = "";
    }
  }
}

async function ensureCloudStatusFresh({ force = false } = {}) {
  if (!state.cloud.link?.code) {
    updateShareReportAvailability();
    return false;
  }
  const now = Date.now();
  const lastCheck = state.cloud.lastStatusCheck || 0;
  if (!force && now - lastCheck < CLOUD_STATUS_REFRESH_MS) {
    return state.cloud.link?.status === CLOUD_STATUS.LINKED;
  }
  state.cloud.isCheckingStatus = true;
  updateShareReportAvailability();
  try {
    const updated = await fetchCloudLinkStatus();
    state.cloud.lastStatusCheck = Date.now();
    updateLinkModalUi();
    if (updated?.status === CLOUD_STATUS.DISCONNECTED) {
      setShareReportLink(null);
      setStatus("Cloud link revoked. Reconnect to SupaExplorer Cloud to share.", "error");
      return false;
    }
    return updated?.status === CLOUD_STATUS.LINKED;
  } catch (error) {
    if (error?.status === 404) {
      await persistCloudLink(null);
      setShareReportLink(null);
      updateLinkModalUi();
      setStatus("Cloud link revoked. Reconnect to SupaExplorer Cloud.", "error");
    } else {
      console.warn("Cloud status refresh failed", error);
    }
    return false;
  } finally {
    state.cloud.isCheckingStatus = false;
    updateShareReportAvailability();
  }
}

async function handleShareReportConnect(event) {
  event?.preventDefault?.();
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  closeShareReportModal();
  await ensureCloudStatusFresh({ force: true });
  openLinkModal();
}

async function handleShareReportView(event) {
  event?.preventDefault?.();
  if (dom.shareReportViewBtn?.disabled) {
    return;
  }
  closeShareReportModal();
  await handleGenerateReport();
}

async function handleShareReportShare(event) {
  event?.preventDefault?.();
  if (!dom.shareReportShareBtn || dom.shareReportShareBtn.disabled) {
    return;
  }
  await refreshSelectedTeamFromStorage();
  // Re-read current UI selection to avoid any stale state before sharing.
  if (dom.linkTeamSelect && dom.linkTeamSelect.value) {
    await setSelectedTeam(dom.linkTeamSelect.value, { allowFallback: false });
  }
  if (!isCloudLinked()) {
    setStatus("Link this extension to SupaExplorer Cloud before sharing.", "error");
    return;
  }
  const stillLinked = await ensureCloudStatusFresh({ force: true });
  if (!stillLinked) {
    setStatus("Cloud link revoked. Reconnect before sharing.", "error");
    return;
  }
  if (state.cloud.teams.length && !state.cloud.selectedTeamId) {
    setStatus("Select a team before sharing.", "error");
    updateTeamPickerUi();
    return;
  }
  const ready = await ensureReportPrerequisites();
  if (!ready) {
    return;
  }
  state.isSharingReport = true;
  updateShareReportAvailability();
  setStatus("Uploading security report to SupaExplorer Cloud…", "progress");
  try {
    const report = await buildSecurityReport();
    const result = await uploadReportToCloud(report);
    const shareUrl = result?.share_url || result?.shareUrl || null;
    state.cloud.lastShareUrl = shareUrl || null;
    if (shareUrl) {
      const copied = await copyTextToClipboard(shareUrl);
      if (copied) {
        setShareReportNote("Share link copied. You can paste it anywhere or copy again below.", "success");
        setStatus("Report shared with SupaExplorer Cloud and link copied to clipboard.", "success");
      } else {
        setShareReportNote("Share link ready. Click below to copy.", "success");
        setStatus("Report shared. Copy the link from the share modal.", "success");
      }
      setShareReportLink(shareUrl);
    } else {
      setShareReportNote(null);
      setShareReportLink(null);
      setStatus("Report shared with SupaExplorer Cloud.", "success");
    }
  } catch (error) {
    //console.error("Cloud report share failed", error);
    const friendly = mapCloudQuotaError(error);
    setStatus(friendly.message, "error");
    setShareReportNote(friendly.note, "error");
    setShareReportLink(state.cloud.lastShareUrl);
  } finally {
    state.isSharingReport = false;
    updateShareReportAvailability();
  }
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
    inspectedHost: state.connection?.inspectedHost || state.inspectedHost || "",
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
    inspectedHost: typeof connection.inspectedHost === "string" ? sanitize(connection.inspectedHost) : "",
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

  const tableRiskLevel = accessible ? deriveTableRiskLevel({ name: table, rowCount }) : "low";

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
    riskLevel: tableRiskLevel,
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
  const tableRiskStats = summarizeTableRisks(accessibleTables);
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
      severity: tableRiskStats.max,
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
  const tableRiskStats = summarizeTableRisks(accessibleTables);
  const tableAggregateRisk = aggregateTableRisk(tableRiskStats, accessibleTables.length);
  const capNonTableToHigh = tableAggregateRisk === "high" || tableAggregateRisk === "critical" ? null : "high";

  let riskLevel = "low";
  const keyFindings = [];

  if (assetDetections.length) {
    const serviceExposure = assetDetections.some((item) => /service/i.test(item.keyType || "") || /service_role/i.test(item.keyLabel || ""));
    const assetRisk = serviceExposure ? "critical" : "high";
    const cappedAssetRisk =
      capNonTableToHigh && RISK_LEVEL_ORDER[assetRisk] > RISK_LEVEL_ORDER[capNonTableToHigh] ? capNonTableToHigh : assetRisk;
    riskLevel = elevateRiskLevel(riskLevel, cappedAssetRisk);
    const summaryLabel = assetDetections.length === 1
      ? "1 exposed Supabase credential discovered in static assets."
      : `${assetDetections.length} exposed Supabase credentials discovered in static assets.`;
    keyFindings.push(summaryLabel);
  }

  const leakRisk = deriveLeakRiskLevel(leakDetections) || "high";
  if (leakDetections.length) {
    const cappedLeakRisk =
      capNonTableToHigh && RISK_LEVEL_ORDER[leakRisk] > RISK_LEVEL_ORDER[capNonTableToHigh] ? capNonTableToHigh : leakRisk;
    riskLevel = elevateRiskLevel(riskLevel, cappedLeakRisk);
    const leakSummary = leakDetections.length === 1
      ? "1 potential API credential leak detected in static assets."
      : `${leakDetections.length} potential API credential leaks detected in static assets.`;
    keyFindings.push(leakSummary);
  }

  if (accessibleTables.length) {
    riskLevel = elevateRiskLevel(riskLevel, tableAggregateRisk);
    const severityBreakdown = ["critical", "high", "medium"]
      .map((level) => {
        const count = tableRiskStats.counts[level] || 0;
        return count ? `${count} ${level}` : null;
      })
      .filter(Boolean);
    const breakdownText = severityBreakdown.length ? ` Severity: ${severityBreakdown.join(", ")}.` : "";

    const hasAnonRole = keyRole === "anon" || bearerRole === "anon";
    const accessRisk = tableAggregateRisk === "critical"
      ? hasAnonRole ? "critical" : "high"
      : tableAggregateRisk === "high"
        ? hasAnonRole ? "high" : "medium"
        : hasAnonRole ? "medium" : "low";
    riskLevel = elevateRiskLevel(riskLevel, accessRisk);
    keyFindings.push(
      `${accessibleTables.length} table${accessibleTables.length === 1 ? "" : "s"} respond with data using the current credentials (aggregate severity: ${tableAggregateRisk}).${breakdownText}`
    );
  }
  if (!accessibleTables.length && unknownTables.length) {
    riskLevel = elevateRiskLevel(riskLevel, "medium");
    keyFindings.push(`${unknownTables.length} table${unknownTables.length === 1 ? "" : "s"} returned non-auth errors that need manual review.`);
  }
  if (!keyFindings.length && protectedTables.length) {
    keyFindings.push(`All checked tables returned 401/403 responses (${protectedTables.length} protected).`);
  }

  const domain = deriveReportDomain({ leakDetections, assetDetections });
  const inspectedHost = domain || null;

  const recommendations = buildSecurityRecommendations({
    accessibleTables,
    sensitiveTables,
    assetDetections,
    leakDetections,
    keyRole,
    bearerRole,
    inspectedHost,
  });

  return {
    id: reportId,
    createdAt,
    projectId: state.connection.projectId,
    schema: state.connection.schema,
    baseUrl: state.baseUrl,
    inspectedHost,
    domain: inspectedHost,
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
      highestTableRisk: tableRiskStats.max,
      tableRiskBreakdown: tableRiskStats.counts,
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

  const connectionHost = getStoredConnectionHost();
  const domain = deriveReportDomain({ leakDetections, assetDetections }) || connectionHost || null;
  const inspectedHost = domain || null;
  const projectLabel = state.connection.projectId || inspectedHost || connectionHost || "Unknown project";
  const schemaLabel = state.connection.schema || "n/a";
  const baseUrl = state.baseUrl || (connectionHost ? `https://${connectionHost}` : "");

  const recommendations = buildSecurityRecommendations({
    accessibleTables: [],
    sensitiveTables: [],
    assetDetections,
    leakDetections,
    keyRole: null,
    bearerRole: null,
    inspectedHost,
  });

  return {
    id: reportId,
    createdAt,
    projectId: projectLabel,
    schema: schemaLabel,
    baseUrl,
    inspectedHost,
    domain: inspectedHost,
    connectionSummary: null,
    summary: {
      riskLevel,
      tableCount: 0,
      accessibleCount: 0,
      protectedCount: 0,
      unknownCount: 0,
      highestTableRisk: "low",
      tableRiskBreakdown: { low: 0, medium: 0, high: 0, critical: 0 },
      keyFindings,
    },
    findings: [],
    assetDetections,
    leakDetections,
    recommendations,
  };
}

function deriveReportDomain({ leakDetections: leakDetectionsOverride = null, assetDetections: assetDetectionsOverride = null } = {}) {
  const leakHost = deriveLeakDetectionDomain(leakDetectionsOverride);
  if (leakHost) {
    return leakHost;
  }
  const assetHost = deriveAssetDetectionDomain(assetDetectionsOverride);
  if (assetHost) {
    return assetHost;
  }
  const connectionHost = getStoredConnectionHost();
  if (connectionHost) {
    return connectionHost;
  }
  const activeHost = typeof state.inspectedHost === "string" ? sanitize(state.inspectedHost) : "";
  if (activeHost) {
    return activeHost;
  }
  const projectId = state.connection?.projectId ? sanitize(state.connection.projectId) : "";
  if (projectId) {
    return `${projectId}.supabase.co`;
  }
  if (state.baseUrl) {
    try {
      const { hostname } = new URL(state.baseUrl);
      if (hostname) {
        return hostname;
      }
    } catch (error) {
      // Ignore
    }
  }
  return null;
}

function deriveLeakDetectionDomain(leakDetectionsOverride = null) {
  const leaks = Array.isArray(leakDetectionsOverride)
    ? leakDetectionsOverride
    : Array.isArray(state.leakDetections)
      ? state.leakDetections
      : [];
  const hostStats = new Map();
  leaks.forEach((leak) => {
    if (!leak || typeof leak !== "object") {
      return;
    }
    const detectedHost =
      (typeof leak.detectedHost === "string" && sanitize(leak.detectedHost)) ||
      deriveHostnameFromUrl(leak.sourceUrl || leak.assetUrl || "");
    if (!detectedHost) {
      return;
    }
    const detectedAt = new Date(leak.detectedAt || 0).getTime();
    const stat = hostStats.get(detectedHost) || { count: 0, newest: 0 };
    stat.count += 1;
    if (Number.isFinite(detectedAt) && detectedAt > stat.newest) {
      stat.newest = detectedAt;
    }
    hostStats.set(detectedHost, stat);
  });
  if (hostStats.size) {
    let bestHost = null;
    let bestCount = 0;
    let bestNewest = 0;
    hostStats.forEach((stat, host) => {
      if (stat.count > bestCount || (stat.count === bestCount && stat.newest > bestNewest)) {
        bestHost = host;
        bestCount = stat.count;
        bestNewest = stat.newest;
      }
    });
    if (bestHost) {
      return bestHost;
    }
  }
  const storedHost = typeof state.leakSourceHost === "string" ? sanitize(state.leakSourceHost) : "";
  if (storedHost) {
    return storedHost;
  }
  return null;
}

function deriveAssetDetectionDomain(assetDetectionsOverride = null) {
  const assets = Array.isArray(assetDetectionsOverride)
    ? assetDetectionsOverride
    : Array.isArray(state.assetDetections)
      ? state.assetDetections
      : [];
  const hostStats = new Map();
  assets.forEach((asset) => {
    if (!asset || typeof asset !== "object") {
      return;
    }
    const host =
      deriveHostnameFromUrl(asset.assetUrl || asset.sourceUrl || asset.supabaseUrl || "") ||
      "";
    if (!host) {
      return;
    }
    const detectedAt = new Date(asset.detectedAt || 0).getTime();
    const stat = hostStats.get(host) || { count: 0, newest: 0 };
    stat.count += 1;
    if (Number.isFinite(detectedAt) && detectedAt > stat.newest) {
      stat.newest = detectedAt;
    }
    hostStats.set(host, stat);
  });
  if (!hostStats.size) {
    return null;
  }
  let bestHost = null;
  let bestCount = 0;
  let bestNewest = 0;
  hostStats.forEach((stat, host) => {
    if (stat.count > bestCount || (stat.count === bestCount && stat.newest > bestNewest)) {
      bestHost = host;
      bestCount = stat.count;
      bestNewest = stat.newest;
    }
  });
  return bestHost ? sanitize(bestHost) : null;
}

function sanitizeMeta(meta) {
  if (!meta || typeof meta !== "object") {
    return null;
  }
  const entries = Object.entries(meta).filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (!entries.length) {
    return null;
  }
  return Object.fromEntries(entries);
}

function buildCloudReportPayload(report) {
  const explicitDomain =
    typeof report?.domain === "string" && report.domain ? sanitize(report.domain) : null;
  const derivedDomain =
    explicitDomain ||
    deriveReportDomain({
      leakDetections: report?.leakDetections || null,
      assetDetections: report?.assetDetections || null,
    });
  const connectionHost = getStoredConnectionHost();
  const inspectedHost = derivedDomain || (typeof report?.inspectedHost === "string" ? sanitize(report.inspectedHost) : "") || connectionHost || null;
  const targetLabel = state.connection.projectId || inspectedHost || report?.projectId || "Supabase target";
  const schemaLabel = state.connection.schema || report?.schema || "public";
  const selectedTeam = getSelectedTeam();
  const selectedTeamId = selectedTeam?.id || (state.cloud.selectedTeamId ? String(state.cloud.selectedTeamId) : null);
  const selectedTeamIdNum = selectedTeamId && Number(selectedTeamId);
  const meta = sanitizeMeta({
    source: "extension",
    extensionVersion: EXTENSION_VERSION,
    installationId: state.cloud.identity?.instanceId || null,
    inspectedHost,
    browser: navigator?.userAgent || null,
    team: selectedTeam
      ? {
        id: selectedTeam.id,
        name: selectedTeam.name || selectedTeam.slug || selectedTeam.id,
        slug: selectedTeam.slug || null,
      }
      : (selectedTeamId ? { id: selectedTeamIdNum || selectedTeamId } : null),
  });

  const payload = {
    title: `SupaExplorer Report – ${targetLabel}`,
    target: targetLabel,
    environment: schemaLabel,
    domain: derivedDomain || inspectedHost,
    payload: report,
  };
  if (selectedTeamId) {
    payload.team_id = Number.isFinite(selectedTeamIdNum) ? selectedTeamIdNum : selectedTeamId;
  }
  if (selectedTeam?.slug) {
    payload.team_slug = selectedTeam.slug;
  }
  if (meta) {
    payload.meta = meta;
  }
  return payload;
}

async function uploadReportToCloud(report) {
  const link = state.cloud.link;
  if (!link?.code) {
    throw new Error("Link this extension to SupaExplorer Cloud before sharing.");
  }
  await ensureCloudIdentity();
  const body = buildCloudReportPayload(report);
  try {
    console.debug("SBDE upload team selection", {
      team_id: body.team_id,
      team_slug: body.team_slug,
      meta_team: body?.meta?.team,
      selectedTeamId: state.cloud.selectedTeamId,
    });
  } catch (e) {
    // ignore logging errors
  }
  const response = await requestCloudLinkApi({
    method: "POST",
    code: link.code,
    pathSuffix: "/reports",
    body,
    includeSecret: true,
    preferOrigin: link.origin,
  });
  if (!response?.ok) {
    const err = new Error("Cloud report upload failed.");
    err.status = response?.status;
    throw err;
  }
  return response.data;
}

async function handleGenerateReport(event) {
  event?.preventDefault();
  if (!enforceTermsAccess({ showModal: true })) {
    return;
  }
  if (state.isGeneratingReport) {
    return;
  }

  const ready = await ensureReportPrerequisites();
  if (!ready) {
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
  if (dom.shareReportShareBtn) {
    dom.shareReportShareBtn.addEventListener("click", handleShareReportShare);
  }
  if (dom.shareReportConnectBtn) {
    dom.shareReportConnectBtn.addEventListener("click", handleShareReportConnect);
  }
  if (dom.shareReportCopyBtn) {
    dom.shareReportCopyBtn.addEventListener("click", async () => {
      const link = dom.shareReportCopyBtn.dataset.link || state.cloud.lastShareUrl;
      if (!link) {
        return;
      }
      const copied = await copyTextToClipboard(link);
      if (copied) {
        setShareReportNote("Link copied to clipboard.", "success");
      }
    });
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
        state.leakSourceHost = null;
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

    if (changes[storageKeys.cloudLink]) {
      const nextLink = changes[storageKeys.cloudLink].newValue || null;
      state.cloud.link = nextLink;
      if (Array.isArray(nextLink?.teams)) {
        setCloudTeams(nextLink.teams, { persist: false }).catch((error) => {
          console.error("Failed to sync teams from storage", error);
        });
      }
      const hasUserSelection = Boolean(state.cloud.selectedTeamId);
      if (!hasUserSelection && nextLink && Object.prototype.hasOwnProperty.call(nextLink, "selectedTeamId") && nextLink.selectedTeamId !== undefined && nextLink.selectedTeamId !== null) {
        setSelectedTeam(nextLink.selectedTeamId, { persist: false, allowFallback: true }).catch((error) => {
          console.error("Failed to sync selected team from storage", error);
        });
      }
      updateLinkModalUi();
      if (nextLink?.status === CLOUD_STATUS.PENDING && !state.cloud.pollTimer) {
        scheduleCloudPolling({ immediate: false });
      }
      if (!nextLink) {
        clearCloudPolling();
      }
    }

    if (changes[storageKeys.cloudIdentity]) {
      state.cloud.identity = changes[storageKeys.cloudIdentity].newValue || null;
      updateLinkModalUi();
    }

    if (changes[storageKeys.cloudOrigin]) {
      state.cloud.origin = normalizeOrigin(changes[storageKeys.cloudOrigin].newValue);
    }

    if (changes[storageKeys.cloudTeams]) {
      const record = changes[storageKeys.cloudTeams].newValue || null;
      const teams = Array.isArray(record?.teams) ? record.teams.map(normalizeTeam).filter(Boolean) : [];
      const fetchedAt = typeof record?.fetchedAt === "number" ? record.fetchedAt : 0;
      state.cloud.teams = teams;
      state.cloud.teamsFetchedAt = fetchedAt;
      updateTeamPickerUi();
    }

    if (changes[storageKeys.cloudSelectedTeam]) {
      const nextId = typeof changes[storageKeys.cloudSelectedTeam].newValue === "string"
        ? changes[storageKeys.cloudSelectedTeam].newValue
        : null;
      state.cloud.selectedTeamId = nextId;
      if (state.cloud.link) {
        state.cloud.link.selectedTeamId = nextId;
      }
      updateTeamPickerUi();
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
  setShareReportLink(null);
  initTermsUi();
  initEventListeners();
  initShareReportUi();
  initLinkingUi();
  registerGlobalListeners();
  await ensureTermsAccepted({ enforce: true });
  await bootstrapAfterTerms();
  await bootstrapCloudLinking();
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
