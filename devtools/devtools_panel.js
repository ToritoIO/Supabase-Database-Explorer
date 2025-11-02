const MAX_REQUESTS = 50;
const INTERESTING_HEADERS = ["authorization", "apikey", "api-key", "x-client-info", "x-apikey"];
const SUPABASE_DETECTION_MESSAGE = "SBDE_SUPABASE_REQUEST";
const ASSET_DETECTION_RECORD_MESSAGE = "SBDE_REGISTER_ASSET_DETECTION";
const STATIC_SCAN_MAX_BYTES = 1024 * 1024; // Guard asset scanning to 1MB payloads
const STATIC_SCAN_CONTEXT_CHARS = 400;
const STATIC_SCAN_MIME_HINTS = ["javascript", "json", "text"];
const SUPABASE_URL_REGEX = /https:\/\/([a-z0-9-]+)\.supabase\.co/gi;
const SUPABASE_KEY_REGEX = /['"](?<token>ey[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,})['"]/g;

const TAB_CONFIG = [
  { key: "requests", label: "Requests" },
  { key: "assets", label: "Assets" },
];

const dom = {
  status: document.getElementById("status"),
  nav: document.getElementById("request-list"),
  detail: document.getElementById("request-detail"),
  clearBtn: document.getElementById("clear-btn"),
  template: document.getElementById("request-template"),
  navTemplate: document.getElementById("nav-item-template"),
  openSidePanelBtn: document.getElementById("open-sidepanel-btn"),
  authFilterCheckbox: document.getElementById("auth-filter-checkbox"),
  tabButtons: {},
};

const state = {
  requests: [],
  showOnlyAuth: true,
  selectedId: null,
  pendingScrollReset: false,
  activeTab: "requests",
};

TAB_CONFIG.forEach(({ key }) => {
  const button = document.querySelector(`.tab-btn[data-tab="${key}"]`);
  if (!button) {
    return;
  }
  dom.tabButtons[key] = button;
  button.addEventListener("click", () => {
    if (state.activeTab === key) {
      return;
    }
    state.activeTab = key;
    state.pendingScrollReset = true;
    renderRequests();
  });
});

const staticDetectionCache = new Set();

function generateId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `req_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`;
}

function setStatus(message) {
  dom.status.textContent = message;
}

function normalizeHeaders(headers) {
  const list = Array.isArray(headers) ? headers : [];
  const map = {};
  const normalized = [];
  list.forEach((header) => {
    const name = header?.name || header?.Name;
    if (!name) return;
    const value = header?.value ?? header?.Value ?? "";
    map[name.toLowerCase()] = value;
    normalized.push({ name, value });
  });
  return { list: normalized, map };
}

function createEntry(request) {
  const { list, map } = normalizeHeaders(request.request?.headers);
  const hasAuthHeaders = list.some((header) =>
    INTERESTING_HEADERS.includes((header.name || "").toLowerCase())
  );
  return {
    id: request._requestId || request.requestId || generateId(),
    method: request.request?.method || "GET",
    url: request.request?.url || "",
    status: request.response?.status || 0,
    statusText: request.response?.statusText || "",
    startedDateTime: request.startedDateTime || new Date().toISOString(),
    time: request.time || 0,
    initiator: request.initiator?.type || "unknown",
    headers: list,
    headerMap: map,
    requestId: request._requestId || request.requestId || null,
    tabId: chrome.devtools.inspectedWindow.tabId,
    hasAuthHeaders,
  };
}

function extractProjectId(url) {
  try {
    const { hostname } = new URL(url);
    return hostname.split(".")[0] || "";
  } catch (error) {
    return "";
  }
}

function deriveConnectionPayload(entry) {
  const headers = entry.headerMap || {};
  const projectId = extractProjectId(entry.url || "");
  const rawAuthorization = headers["authorization"] || "";
  const bearer = rawAuthorization.toLowerCase().startsWith("bearer ")
    ? rawAuthorization.slice(7)
    : rawAuthorization || headers["apikey"] || headers["api-key"] || headers["x-apikey"] || "";
  const apiKey = headers["apikey"] || headers["api-key"] || headers["x-apikey"] || "";
  const schema = headers["accept-profile"] || "public";

  return {
    projectId,
    schema,
    apiKey,
    bearer,
  };
}

function shouldCapture(request) {
  const url = request.request?.url;
  if (!url) return false;
  try {
    const { hostname } = new URL(url);
    return hostname.includes(".supabase.co");
  } catch (error) {
    return false;
  }
}

function shouldScanForEmbeddedCredentials(request) {
  if (!request || typeof request.getContent !== "function") {
    return false;
  }
  if (shouldCapture(request)) {
    // Live Supabase responses are already inspected via headers.
    return false;
  }

  const url = request.request?.url || "";
  if (!url) {
    return false;
  }

  const response = request.response || {};
  const content = response.content || {};
  const mimeType = String(content.mimeType || "").toLowerCase();
  const size = Number(content.size);

  if (Number.isFinite(size) && size > STATIC_SCAN_MAX_BYTES) {
    return false;
  }

  const hasMimeHint = STATIC_SCAN_MIME_HINTS.some((hint) => mimeType.includes(hint));
  const extensionHint = url.split("?")[0];
  const hasExtensionHint = /\.(?:js|mjs|cjs|ts|tsx|json)$/i.test(extensionHint);

  return hasMimeHint || hasExtensionHint;
}

function scanRequestForEmbeddedCredentials(request) {
  try {
    request.getContent((body, encoding) => {
      if (!body || typeof body !== "string") {
        return;
      }

      let source = body;
      if (encoding === "base64") {
        try {
          source = atob(body);
        } catch (error) {
          console.warn("SBDE failed to decode base64 asset", error);
          return;
        }
      }

      if (!source || typeof source !== "string") {
        return;
      }

      if (source.length > STATIC_SCAN_MAX_BYTES * 2) {
        // Skip oversized decoded payloads to avoid work on massive bundles.
        return;
      }

      const detections = detectSupabaseCredentials(source, request);
      if (!detections.length) {
        return;
      }

      detections.forEach((detection) => handleStaticDetection(request, detection));
    });
  } catch (error) {
    console.warn("SBDE static asset scan failed", error);
  }
}

function detectSupabaseCredentials(source, request) {
  if (typeof source !== "string" || !source) {
    return [];
  }

  const assetUrl = request?.request?.url || "";
  const detections = [];
  const seenPairs = new Set();
  const urlMatches = [];

  SUPABASE_URL_REGEX.lastIndex = 0;
  let urlMatch;
  while ((urlMatch = SUPABASE_URL_REGEX.exec(source))) {
    urlMatches.push({ url: urlMatch[0], index: urlMatch.index });
  }

  SUPABASE_KEY_REGEX.lastIndex = 0;
  let keyMatch;
  while ((keyMatch = SUPABASE_KEY_REGEX.exec(source))) {
    const token = keyMatch?.groups?.token;
    if (!token) {
      continue;
    }

    const tokenIndex = keyMatch.index || 0;
    const contextStart = Math.max(0, tokenIndex - STATIC_SCAN_CONTEXT_CHARS);
    const contextEnd = Math.min(source.length, tokenIndex + STATIC_SCAN_CONTEXT_CHARS);
    const context = source.slice(contextStart, contextEnd);

    const nearbyUrl = urlMatches.find((match) => Math.abs(match.index - tokenIndex) <= STATIC_SCAN_CONTEXT_CHARS);
    let supabaseUrl = nearbyUrl?.url || null;

    if (!supabaseUrl && /supabase/i.test(context)) {
      const projectId = decodeProjectRefFromKey(token);
      if (projectId) {
        supabaseUrl = `https://${projectId}.supabase.co`;
      }
    }

    if (!supabaseUrl) {
      continue;
    }

    const keyLabel = inferKeyLabel(source, tokenIndex);
    const keyType = inferKeyType(context, keyLabel);
    const cacheKey = `${supabaseUrl}|${token}`;

    if (seenPairs.has(cacheKey)) {
      continue;
    }
    seenPairs.add(cacheKey);

    detections.push({
      supabaseUrl,
      apiKey: token,
      keyLabel,
      keyType,
      assetUrl,
    });
  }

  return detections;
}

function inferKeyLabel(source, tokenIndex) {
  const lookBehindStart = Math.max(0, tokenIndex - 80);
  const prefix = source.slice(lookBehindStart, tokenIndex);

  const propertyMatch = prefix.match(/([A-Za-z0-9_\-$]{3,40})\s*[:=]\s*$/);
  if (propertyMatch) {
    return propertyMatch[1];
  }

  const quotedPropertyMatch = prefix.match(/['"]([A-Za-z0-9_\-$]{3,40})['"]\s*[:=]\s*$/);
  if (quotedPropertyMatch) {
    return quotedPropertyMatch[1];
  }

  return null;
}

function inferKeyType(context, keyLabel) {
  const haystack = `${context || ""} ${keyLabel || ""}`.toLowerCase();
  if (haystack.includes("service_role") || haystack.includes("service-role")) {
    return "service role key";
  }
  if (haystack.includes("secret")) {
    return "secret";
  }
  if (haystack.includes("anon")) {
    return "anon key";
  }
  if (haystack.includes("service")) {
    return "service key";
  }
  return "";
}

function decodeProjectRefFromKey(apiKey) {
  if (!apiKey || typeof apiKey !== "string") {
    return null;
  }
  const parts = apiKey.split(".");
  if (parts.length < 2) {
    return null;
  }
  try {
    let payloadPart = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = payloadPart.length % 4;
    if (pad) {
      payloadPart += "=".repeat(4 - pad);
    }
    const payloadRaw = atob(payloadPart);
    const payload = JSON.parse(payloadRaw);
    if (payload?.ref && typeof payload.ref === "string") {
      return payload.ref;
    }
    if (typeof payload?.iss === "string") {
      const segments = payload.iss.split("/");
      if (segments.length >= 4) {
        return segments[3];
      }
    }
    if (typeof payload?.sub === "string") {
      return payload.sub.split(":")[0] || null;
    }
    return null;
  } catch (error) {
    return null;
  }
}

function handleStaticDetection(request, detection) {
  if (!detection?.apiKey || !detection.supabaseUrl) {
    return;
  }

  const cacheKey = `${detection.assetUrl}|${detection.supabaseUrl}|${detection.apiKey}`;
  if (staticDetectionCache.has(cacheKey)) {
    return;
  }
  staticDetectionCache.add(cacheKey);

  const entry = createStaticEntry(request, detection);
  state.requests.unshift(entry);
  if (state.requests.length > MAX_REQUESTS) {
    state.requests.length = MAX_REQUESTS;
  }
  recordAssetDetection(entry, detection);
  focusEntry(entry);
  renderRequests();
  notifySupabaseDetection(detection);
}

function createStaticEntry(request, detection) {
  const assetUrl = detection.assetUrl || request.request?.url || "";
  const headers = [
    { name: "Exposed API key", value: detection.apiKey },
    { name: "Asset URL", value: assetUrl },
  ];

  if (detection.supabaseUrl) {
    headers.unshift({ name: "Supabase URL", value: detection.supabaseUrl });
  }

  if (detection.keyType) {
    headers.push({ name: "Detected type", value: detection.keyType });
  }

  if (detection.keyLabel) {
    headers.push({ name: "Source label", value: detection.keyLabel });
  }

  const headerMap = {
    authorization: `Bearer ${detection.apiKey}`,
    apikey: detection.apiKey,
  };

  return {
    id: generateId(),
    method: "ASSET",
    url: detection.supabaseUrl || assetUrl,
    status: 0,
    statusText: detection.keyType ? `Embedded ${detection.keyType}` : "Embedded Supabase credential",
    startedDateTime: new Date().toISOString(),
    time: request.time || 0,
    initiator: request.initiator?.type || "parser",
    headers,
    headerMap,
    requestId: null,
    tabId: chrome.devtools.inspectedWindow.tabId,
    hasAuthHeaders: true,
    isStaticDetection: true,
    supabaseUrl: detection.supabaseUrl || "",
    assetUrl,
    keyType: detection.keyType || "",
    keyLabel: detection.keyLabel || "",
    apiKeySnippet: detection.apiKey ? summarizeApiKeySnippet(detection.apiKey) : "",
  };
}

function notifySupabaseDetection(detection) {
  try {
    chrome.runtime.sendMessage({
      type: SUPABASE_DETECTION_MESSAGE,
      url: detection.supabaseUrl,
      apiKey: detection.apiKey,
      schema: "public",
    });
  } catch (error) {
    console.warn("SBDE failed to notify background of static detection", error);
  }
}

function summarizeApiKeySnippet(apiKey) {
  if (!apiKey || typeof apiKey !== "string") {
    return "";
  }
  const trimmed = apiKey.trim();
  if (!trimmed) return "";
  if (trimmed.length <= 12) {
    return trimmed;
  }
  const prefix = trimmed.slice(0, 6);
  const suffix = trimmed.slice(-4);
  return `${prefix}...${suffix}`;
}

function recordAssetDetection(entry, detection) {
  try {
    const projectSource = detection?.supabaseUrl || entry?.supabaseUrl || entry?.url || detection?.assetUrl || "";
    const projectId = extractProjectId(projectSource);
    if (!projectId) {
      return;
    }
    const snippet = summarizeApiKeySnippet(detection?.apiKey);
    if (!snippet) {
      return;
    }
    const payload = {
      projectId,
      supabaseUrl: detection?.supabaseUrl || entry?.supabaseUrl || "",
      assetUrl: detection?.assetUrl || entry?.assetUrl || "",
      keyType: detection?.keyType || entry?.keyType || "",
      keyLabel: detection?.keyLabel || entry?.keyLabel || "",
      apiKeySnippet: snippet,
      detectedAt: new Date().toISOString(),
    };
    chrome.runtime.sendMessage({ type: ASSET_DETECTION_RECORD_MESSAGE, payload }, () => {});
  } catch (error) {
    console.warn("SBDE failed to persist asset detection", error);
  }
}

function focusEntry(entry) {
  if (!entry) {
    return;
  }
  if (state.showOnlyAuth && !entry.hasAuthHeaders && !entry.isStaticDetection) {
    // Entry will be hidden; keep current tab.
    return;
  }
  const targetTab = entry.isStaticDetection ? "assets" : "requests";
  state.activeTab = targetTab;
  state.selectedId = entry.id;
  state.pendingScrollReset = true;
}

function renderRequests() {
  const previousScroll = dom.nav.scrollTop;
  let shouldResetScroll = state.pendingScrollReset;
  state.pendingScrollReset = false;
  dom.nav.innerHTML = "";
  const grouped = {
    requests: [],
    assets: [],
  };

  if (!state.requests.length) {
    updateTabs(grouped);
    state.selectedId = null;
    setStatus("Requests will appear as the inspected page talks to Supabase.");
    renderNavigationPlaceholder("Requests will appear as the page talks to Supabase.");
    renderDetailPlaceholder("Capture Supabase traffic to inspect connection details.");
    dom.nav.scrollTop = 0;
    return;
  }

  const filtered = state.requests.filter((entry) => !state.showOnlyAuth || entry.hasAuthHeaders);
  filtered.forEach((entry) => {
    const bucket = entry.isStaticDetection ? "assets" : "requests";
    grouped[bucket].push(entry);
  });
  updateTabs(grouped);

  if (!filtered.length) {
    state.selectedId = null;
    const filterMessage = state.showOnlyAuth
      ? "No items match the current filter. Disable “Only auth headers” to see all traffic."
      : "No items captured yet.";
    setStatus(filterMessage);
    const activeLabel = state.activeTab === "assets" ? "assets" : "requests";
    renderNavigationPlaceholder(`No ${activeLabel} match the current filter.`);
    renderDetailPlaceholder("Adjust the filter to see matching requests or assets.");
    dom.nav.scrollTop = 0;
    return;
  }

  const activeEntries = grouped[state.activeTab] || [];
  const totalDescriptor = filtered.length === 1 ? "item" : "items";
  const activeLabelSingular = state.activeTab === "assets" ? "asset" : "request";
  const activeLabelPlural = state.activeTab === "assets" ? "assets" : "requests";
  const activeDescriptor = activeEntries.length === 1 ? activeLabelSingular : activeLabelPlural;
  const filterDescriptor = state.showOnlyAuth ? "with auth headers captured this session" : "captured this session";
  setStatus(`${activeEntries.length} ${activeDescriptor} shown (${filtered.length} ${totalDescriptor} ${filterDescriptor}).`);

  if (!activeEntries.length) {
    state.selectedId = null;
    const emptyLabel = activeLabelPlural;
    renderNavigationPlaceholder(`No ${emptyLabel} captured in this tab.`);
    renderDetailPlaceholder(`Switch tabs or adjust filters to inspect ${emptyLabel}.`);
    dom.nav.scrollTop = shouldResetScroll ? 0 : previousScroll;
    return;
  }

  if (!state.selectedId || !activeEntries.some((entry) => entry.id === state.selectedId)) {
    state.selectedId = activeEntries[0]?.id || null;
    shouldResetScroll = true;
  }

  activeEntries.forEach((entry) => {
    const fragment = createNavItem(entry, entry.id === state.selectedId);
    dom.nav.appendChild(fragment);
  });

  dom.nav.scrollTop = shouldResetScroll ? 0 : previousScroll;

  const selectedEntry = activeEntries.find((entry) => entry.id === state.selectedId);
  renderDetail(selectedEntry || null);
}

function renderNavigationPlaceholder(message) {
  const empty = document.createElement("div");
  empty.className = "empty-state nav-empty";
  empty.textContent = message;
  dom.nav.appendChild(empty);
}

function renderDetailPlaceholder(message) {
  dom.detail.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "empty-state detail-empty";
  empty.textContent = message;
  dom.detail.appendChild(empty);
}

function renderDetail(entry) {
  dom.detail.innerHTML = "";
  if (!entry) {
    renderDetailPlaceholder("Select a request or asset to view its headers and connection details.");
    return;
  }
  const cardFragment = createRequestCard(entry);
  dom.detail.appendChild(cardFragment);
}

function updateTabs(groupedEntries) {
  TAB_CONFIG.forEach(({ key, label }) => {
    const button = dom.tabButtons[key];
    if (!button) {
      return;
    }
    const count = groupedEntries[key]?.length || 0;
    button.textContent = `${label} (${count})`;
    button.classList.toggle("active", state.activeTab === key);
  });
}

function createNavItem(entry, isActive) {
  const fragment = dom.navTemplate?.content
    ? dom.navTemplate.content.cloneNode(true)
    : null;

  let button;
  if (fragment) {
    button = fragment.querySelector(".request-nav-item");
  } else {
    button = document.createElement("button");
    button.className = "request-nav-item";
    button.innerHTML = `
      <div class="nav-top">
        <span class="nav-method"></span>
        <span class="nav-status"></span>
      </div>
      <div class="nav-url"></div>
      <div class="nav-meta"></div>
    `;
  }

  const methodEl = button.querySelector(".nav-method");
  const statusEl = button.querySelector(".nav-status");
  const urlEl = button.querySelector(".nav-url");
  const metaEl = button.querySelector(".nav-meta");

  if (methodEl) {
    methodEl.textContent = entry.method || "REQUEST";
  }

  if (statusEl) {
    const statusLabel = entry.status
      ? String(entry.status)
      : entry.isStaticDetection
        ? "KEY"
        : "";
    statusEl.textContent = statusLabel;
  }

  if (urlEl) {
    urlEl.textContent = formatNavUrl(entry.url);
    urlEl.title = entry.url || "";
  }

  if (metaEl) {
    const metaParts = [];
    if (entry.isStaticDetection) {
      const supabaseHeader = (entry.headers || []).find((header) => header.name === "Supabase URL");
      if (supabaseHeader?.value) {
        metaParts.push(supabaseHeader.value);
      }
      metaParts.push(entry.statusText || "Embedded Supabase credential");
    } else {
      if (entry.statusText) {
        metaParts.push(entry.statusText);
      }
      if (entry.initiator) {
        metaParts.push(`Initiator: ${entry.initiator}`);
      }
    }
    metaEl.textContent = metaParts.filter(Boolean).join(" • ");
  }

  button.classList.toggle("active", Boolean(isActive));
  button.classList.toggle("asset", Boolean(entry.isStaticDetection));
  button.classList.toggle("request", !entry.isStaticDetection);
  button.addEventListener("click", () => {
    if (state.selectedId === entry.id) {
      return;
    }
    state.selectedId = entry.id;
    renderRequests();
  });

  return fragment || button;
}

function formatNavUrl(url) {
  if (!url) {
    return "(no url)";
  }
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname === "/" ? "" : parsed.pathname;
    return `${parsed.host}${pathname}`;
  } catch (error) {
    return url;
  }
}

function createRequestCard(entry) {
  const fragment = dom.template.content.cloneNode(true);
  const card = fragment.querySelector(".request-card");
  const methodEl = fragment.querySelector(".request-method");
  const urlEl = fragment.querySelector(".request-url");
  const metaEl = fragment.querySelector(".request-meta");
  const headerListEl = fragment.querySelector(".header-list");
  const sendBtn = fragment.querySelector(".send-btn");

  card.classList.toggle("asset", Boolean(entry.isStaticDetection));
  card.classList.toggle("request", !entry.isStaticDetection);

  methodEl.textContent = entry.method;
  urlEl.textContent = entry.url;
  const statusDescriptor = entry.status
    ? `${entry.status} ${entry.statusText}`.trim()
    : entry.statusText || "No response status";
  metaEl.textContent = [statusDescriptor || "No response status", `Initiator: ${entry.initiator}`].join(" • ");

  const headersToDisplay = entry.isStaticDetection
    ? entry.headers || []
    : (entry.headers || []).filter((header) =>
        INTERESTING_HEADERS.includes((header.name || "").toLowerCase())
      );

  if (headersToDisplay.length) {
    headersToDisplay.forEach((header) => {
      const row = document.createElement("div");
      row.className = "header-row";
      const nameEl = document.createElement("span");
      nameEl.className = "header-name";
      nameEl.textContent = header.name;
      const valueEl = document.createElement("span");
      valueEl.className = "header-value";
      valueEl.textContent = header.value;
      row.appendChild(nameEl);
      row.appendChild(valueEl);
      headerListEl.appendChild(row);
    });
  } else {
    const empty = document.createElement("div");
    empty.className = "header-row";
    empty.textContent = entry.isStaticDetection
      ? "No metadata captured."
      : "No auth headers detected.";
    headerListEl.appendChild(empty);
  }

  sendBtn.addEventListener("click", () => sendEntry(entry, card));

  return fragment;
}

async function sendEntry(entry, card) {
  if (card.classList.contains("sending")) {
    return;
  }

  const connectionPayload = deriveConnectionPayload(entry);
  if (!connectionPayload.projectId) {
    setStatus("Unable to detect Supabase project id from this request.");
    return;
  }
  if (!connectionPayload.apiKey && !connectionPayload.bearer) {
    setStatus("No apiKey or bearer token found in this request.");
    return;
  }

  card.classList.add("sending");
  setStatus("Sending connection details to Supabase Database Explorer…");

  try {
    const response = await sendMessageAsync({ type: "SBDE_APPLY_CONNECTION", payload: connectionPayload });
    if (!response?.ok) {
      throw new Error(response?.reason || "Extension rejected the connection payload.");
    }
  } catch (error) {
    card.classList.remove("sending");
    setStatus(error?.message ? `Failed to send credentials: ${error.message}` : "Failed to send credentials.");
    return;
  }

  card.classList.remove("sending");
  setStatus("Connection sent. Opening Supabase Database Explorer side panel…");
  openSidePanel();
}

function handleRequestFinished(request) {
  if (shouldCapture(request)) {
    const entry = createEntry(request);
    state.requests.unshift(entry);
    if (state.requests.length > MAX_REQUESTS) {
      state.requests.length = MAX_REQUESTS;
    }
    focusEntry(entry);
    renderRequests();
  }

  if (shouldScanForEmbeddedCredentials(request)) {
    scanRequestForEmbeddedCredentials(request);
  }
}

dom.clearBtn.addEventListener("click", () => {
  state.requests = [];
  state.selectedId = null;
  state.activeTab = "requests";
  state.pendingScrollReset = true;
  renderRequests();
});

if (dom.openSidePanelBtn) {
  dom.openSidePanelBtn.addEventListener("click", () => {
    openSidePanel();
  });
}

if (dom.authFilterCheckbox) {
  state.showOnlyAuth = Boolean(dom.authFilterCheckbox.checked);
  dom.authFilterCheckbox.addEventListener("change", () => {
    state.showOnlyAuth = Boolean(dom.authFilterCheckbox.checked);
    state.pendingScrollReset = true;
    renderRequests();
  });
}

renderRequests();
chrome.devtools.network.onRequestFinished.addListener(handleRequestFinished);

async function openSidePanel() {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  if (!tabId) {
    setStatus("Cannot determine inspected tab. Open the side panel manually.");
    return;
  }

  setStatus("Opening Supabase Database Explorer side panel…");

  if (chrome?.sidePanel?.open) {
    try {
      if (typeof chrome.sidePanel.setOptions === "function") {
        await chrome.sidePanel.setOptions({ tabId, path: "panel/sidepanel.html" });
      }
      await chrome.sidePanel.open({ tabId });
      setStatus("Supabase Database Explorer side panel opened.");
      return;
    } catch (error) {
      console.warn("Direct side panel open from DevTools failed", error);
      if (!isUserGestureError(error)) {
        setStatus(error?.message ? `Side panel error: ${error.message}` : "Side panel error.");
        return;
      }
      // Fall through to message-based attempt for user-gesture errors.
    }
  }

  try {
    const response = await sendMessageAsync({ type: "SBDE_OPEN_SIDE_PANEL", tabId });
    if (!response?.ok) {
      throw new Error(response?.reason || "Side panel did not open.");
    }
    setStatus("Supabase Database Explorer side panel opened.");
  } catch (error) {
    if (isUserGestureError(error)) {
      setStatus("Chrome blocked the side panel because it wasn't triggered directly. Click again or open it via the toolbar icon.");
      return;
    }
    setStatus(error?.message ? `Side panel error: ${error.message}` : "Failed to open side panel.");
  }
}

function sendMessageAsync(payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(payload, (response) => {
      const lastError = chrome.runtime.lastError;
      if (lastError) {
        reject(new Error(lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

function isUserGestureError(error) {
  const message = error?.message || "";
  return /user gesture/i.test(message);
}
