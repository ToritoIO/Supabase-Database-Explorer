import { createLeakScanner, summarizeLeakMatch } from "../shared/leak_scanner.js";

const MAX_REQUESTS = 50;
const INTERESTING_HEADERS = ["authorization", "apikey", "api-key", "x-client-info", "x-apikey"];
const SUPABASE_DETECTION_MESSAGE = "SBDE_SUPABASE_REQUEST";
const ASSET_DETECTION_RECORD_MESSAGE = "SBDE_REGISTER_ASSET_DETECTION";
const LEAK_DETECTION_RECORD_MESSAGE = "SBDE_REGISTER_GENERIC_LEAK";
const STATIC_SCAN_MAX_BYTES = 1024 * 1024; // Guard asset scanning to 1MB payloads
const STATIC_SCAN_CONTEXT_CHARS = 400;
const STATIC_SCAN_MIME_HINTS = ["javascript", "json", "text"];
const SUPABASE_URL_REGEX = /https:\/\/([a-z0-9-]+)\.supabase\.co/gi;
const SUPABASE_KEY_REGEX = /['"](?<token>ey[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,})['"]/g;
const TERMS_STORAGE_KEY = "sbde_terms_acceptance";
const TERMS_VERSION = "1.0";

const TAB_CONFIG = [
  { key: "requests", label: "Requests" },
  { key: "assets", label: "Assets" },
  { key: "leaks", label: "Leaks" },
];

const CATEGORY_LABELS = {
  requests: { singular: "request", plural: "requests" },
  assets: { singular: "asset", plural: "assets" },
  leaks: { singular: "leak", plural: "leaks" },
};

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

let termsAccepted = false;

const isTermsAcceptedRecord = (record) => Boolean(record && record.version === TERMS_VERSION);

function applyTermsAcceptance(accepted) {
  termsAccepted = accepted;
  if (!accepted) {
    state.requests = [];
    state.selectedId = null;
    state.activeTab = "requests";
    state.pendingScrollReset = false;
    renderRequests();
    setStatus("Accept the Terms & Conditions in the SupaExplorer side panel to enable monitoring.");
  } else {
    setStatus("Monitoring Supabase requests…");
  }
}

function initializeTermsGate() {
  if (!chrome?.storage?.local) {
    applyTermsAcceptance(false);
    return;
  }

  chrome.storage.local.get([TERMS_STORAGE_KEY], (result) => {
    applyTermsAcceptance(isTermsAcceptedRecord(result?.[TERMS_STORAGE_KEY]));
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes[TERMS_STORAGE_KEY]) {
      return;
    }
    applyTermsAcceptance(isTermsAcceptedRecord(changes[TERMS_STORAGE_KEY].newValue));
  });
}

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

initializeTermsGate();

const staticDetectionCache = new Set();
const leakDetectionCache = new Set();
const leakScanner = createLeakScanner();

const pageScope = {
  origin: null,
  hostname: null,
  rootDomain: null,
};

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

function updatePageScopeFromUrl(url) {
  if (!url || typeof url !== "string") {
    return;
  }
  try {
    const parsed = new URL(url);
    pageScope.origin = parsed.origin;
    pageScope.hostname = parsed.hostname;
    pageScope.rootDomain = deriveRootDomain(parsed.hostname);
  } catch (error) {
    // Ignore invalid URLs.
  }
}

function isUrlInPageScope(url) {
  if (!url || typeof url !== "string") {
    return false;
  }
  // Strict check: if pageScope isn't set yet, don't match anything
  if (!pageScope.hostname && !pageScope.rootDomain) {
    return false;
  }
  try {
    const { hostname } = new URL(url);
    if (!hostname) {
      return false;
    }
    if (hostname === pageScope.hostname) {
      return true;
    }
    if (pageScope.rootDomain) {
      if (hostname === pageScope.rootDomain) {
        return true;
      }
      if (hostname.endsWith(`.${pageScope.rootDomain}`)) {
        return true;
      }
    }
  } catch (error) {
    return false;
  }
  return false;
}

chrome.devtools.inspectedWindow.eval("location.href", (result, exceptionInfo) => {
  if (exceptionInfo && exceptionInfo.isException) {
    return;
  }
  if (!termsAccepted) {
    return;
  }
  if (typeof result === "string" && result) {
    updatePageScopeFromUrl(result);
    // Now that pageScope is set, load stored detections with proper filtering
    loadStoredAssetDetections();
  }
});

chrome.devtools.network.onNavigated.addListener((url) => {
  if (!termsAccepted) {
    return;
  }
  updatePageScopeFromUrl(url);
  // Clear detection caches on navigation to allow re-scanning on page reload
  staticDetectionCache.clear();
  leakDetectionCache.clear();
  // Clear all stored detections from state to start fresh on new page
  state.requests = [];
  state.selectedId = null;
  state.activeTab = "requests";
  renderRequests();
  // Reload detections for new page
  setTimeout(() => loadStoredAssetDetections(), 500);
});

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
    category: "requests",
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
    inspectedHost: pageScope.hostname || "",
  };
}

function isSupabaseAssetUrl(url) {
  if (!url) {
    return false;
  }
  try {
    const { hostname } = new URL(url);
    return hostname.includes(".supabase.co");
  } catch (error) {
    return false;
  }
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
  const supabaseAsset = isSupabaseAssetUrl(url);
  if (!supabaseAsset && !isUrlInPageScope(url)) {
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

      const supabaseDetections = detectSupabaseCredentials(source, request);
      if (supabaseDetections.length) {
        supabaseDetections.forEach((detection) => handleStaticDetection(request, detection));
      }

      const requestURL = request?.request?.url || "";
      const leakDetections = leakScanner.scan(source, requestURL);
      if (leakDetections.length) {
        handleLeakDetections(request, leakDetections);
      }
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
    category: "assets",
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

function handleLeakDetections(request, detections) {
  if (!Array.isArray(detections) || detections.length === 0) {
    return;
  }
  const assetUrl = request?.request?.url || "";
  if (!isSupabaseAssetUrl(assetUrl) && !isUrlInPageScope(assetUrl)) {
    return;
  }
  const newEntries = [];

  detections.forEach((rawDetection) => {
    if (!rawDetection?.match) {
      return;
    }
    const sourceUrl = rawDetection.sourceUrl || assetUrl || "";
    const cacheKey = `${rawDetection.key}|${rawDetection.match}|${sourceUrl}|${rawDetection.encodedFrom || ""}`;
    if (leakDetectionCache.has(cacheKey)) {
      return;
    }
    leakDetectionCache.add(cacheKey);

    const detection = {
      ...rawDetection,
      sourceUrl,
      assetUrl,
      matchSnippet: summarizeLeakMatch(rawDetection.match),
    };

    const entry = createLeakEntry(request, detection);
    if (entry) {
      newEntries.push(entry);
      recordLeakDetection(entry);
    }
  });

  if (!newEntries.length) {
    return;
  }

  newEntries
    .slice()
    .reverse()
    .forEach((entry) => {
      state.requests.unshift(entry);
    });

  if (state.requests.length > MAX_REQUESTS) {
    state.requests.length = MAX_REQUESTS;
  }

  focusEntry(newEntries[0]);
  renderRequests();
}

function createLeakEntry(request, detection) {
  const sourceUrl = detection.sourceUrl || detection.assetUrl || request?.request?.url || "";
  const timestamp = new Date().toISOString();
  const contextSnippet =
    typeof detection.context === "string" && detection.context.length > 240
      ? `${detection.context.slice(0, 240)}...`
      : detection.context;
  const encodedSnippet =
    typeof detection.encodedFrom === "string" && detection.encodedFrom.length > 120
      ? `${detection.encodedFrom.slice(0, 120)}...`
      : detection.encodedFrom;

  const headers = [
    { name: "Pattern", value: detection.key },
    { name: "Matched value", value: detection.match },
  ];

  if (contextSnippet) {
    headers.push({ name: "Context", value: contextSnippet });
  }

  headers.push({ name: "Source asset", value: sourceUrl || "(unknown source)" });

  if (encodedSnippet) {
    headers.push({ name: "Decoded from", value: encodedSnippet });
  }

  return {
    id: generateId(),
    method: "LEAK",
    url: sourceUrl || "(unknown)",
    status: 0,
    statusText: detection.key || "Potential API credential",
    startedDateTime: timestamp,
    time: request.time || 0,
    initiator: request.initiator?.type || "scanner",
    headers,
    headerMap: {},
    requestId: null,
    tabId: chrome.devtools.inspectedWindow.tabId,
    hasAuthHeaders: true,
    isLeakDetection: true,
    category: "leaks",
    leak: {
      patternKey: detection.key,
      match: detection.match,
      matchSnippet: detection.matchSnippet,
      context: detection.context,
      encodedFrom: detection.encodedFrom || null,
      sourceUrl,
      assetUrl: detection.assetUrl || "",
      detectedAt: timestamp,
    },
  };
}

function recordLeakDetection(entry) {
  try {
    const leak = entry.leak || {};
    const payload = {
      sourceUrl: leak.sourceUrl || entry.url || "",
      assetUrl: leak.assetUrl || "",
      pattern: leak.patternKey || entry.statusText || "",
      matchSnippet: leak.matchSnippet || summarizeLeakMatch(leak.match || ""),
      contextSnippet:
        typeof leak.context === "string" ? leak.context.slice(0, 200) : undefined,
      encodedSnippet:
        typeof leak.encodedFrom === "string" ? leak.encodedFrom.slice(0, 80) : undefined,
      detectedAt: leak.detectedAt || new Date().toISOString(),
    };
    Object.keys(payload).forEach((key) => {
      if (payload[key] === undefined) {
        delete payload[key];
      }
    });
    chrome.runtime.sendMessage({ type: LEAK_DETECTION_RECORD_MESSAGE, payload }, () => {});
  } catch (error) {
    console.warn("SBDE failed to persist generic leak detection", error);
  }
}

function focusEntry(entry) {
  if (!entry) {
    return;
  }
  if (entry.category === "requests" && state.showOnlyAuth && !entry.hasAuthHeaders) {
    // Entry will be hidden; keep current tab.
    return;
  }
  const targetTab = entry.category || (entry.isStaticDetection ? "assets" : "requests");
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
    leaks: [],
  };

  if (!state.requests.length) {
    updateTabs(grouped);
    state.selectedId = null;
    setStatus("Requests and detections will appear as the inspected page talks to Supabase.");
    renderNavigationPlaceholder("Requests or detections will appear as the page talks to Supabase.");
    renderDetailPlaceholder("Capture traffic to inspect connection details and potential leaks.");
    dom.nav.scrollTop = 0;
    return;
  }

  const filtered = state.requests.filter((entry) => {
    if (entry.category === "requests") {
      return !state.showOnlyAuth || entry.hasAuthHeaders;
    }
    return true;
  });
  filtered.forEach((entry) => {
    const bucket = entry.category || (entry.isStaticDetection ? "assets" : "requests");
    if (!grouped[bucket]) {
      grouped[bucket] = [];
    }
    grouped[bucket].push(entry);
  });
  updateTabs(grouped);

  if (!filtered.length) {
    state.selectedId = null;
    const filterMessage = state.showOnlyAuth
      ? 'No network requests match the current filter. Disable "Only auth headers" to see all traffic.'
      : "No items captured yet.";
    setStatus(filterMessage);
    const labels = CATEGORY_LABELS[state.activeTab] || CATEGORY_LABELS.requests;
    renderNavigationPlaceholder(`No ${labels.plural} match the current filter.`);
    renderDetailPlaceholder("Adjust the filter to see matching requests or detections.");
    dom.nav.scrollTop = 0;
    return;
  }

  const activeEntries = grouped[state.activeTab] || [];
  const totalDescriptor = filtered.length === 1 ? "item" : "items";
  const labels = CATEGORY_LABELS[state.activeTab] || CATEGORY_LABELS.requests;
  const activeDescriptor = activeEntries.length === 1 ? labels.singular : labels.plural;
  const filterDescriptor = state.showOnlyAuth
    ? "captured items (requests filtered to auth headers)"
    : "captured this session";
  setStatus(`${activeEntries.length} ${activeDescriptor} shown (${filtered.length} ${totalDescriptor} ${filterDescriptor}).`);

  if (!activeEntries.length) {
    state.selectedId = null;
    renderNavigationPlaceholder(`No ${labels.plural} captured in this tab.`);
    renderDetailPlaceholder(`Switch tabs or adjust filters to inspect ${labels.plural}.`);
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
    renderDetailPlaceholder("Select a request, asset, or leak to view its details.");
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
    let statusLabel = "";
    if (entry.category === "requests" && entry.status) {
      statusLabel = String(entry.status);
    } else if (entry.category === "assets") {
      statusLabel = "KEY";
    } else if (entry.category === "leaks") {
      statusLabel = "!";
    }
    statusEl.textContent = statusLabel;
  }

  if (urlEl) {
    urlEl.textContent = formatNavUrl(entry.url);
    urlEl.title = entry.url || "";
  }

  if (metaEl) {
    const metaParts = [];
    if (entry.isLeakDetection) {
      if (entry.statusText) {
        metaParts.push(entry.statusText);
      }
      if (entry.leak?.sourceUrl) {
        metaParts.push(formatNavUrl(entry.leak.sourceUrl));
      }
    } else if (entry.isStaticDetection) {
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
  button.classList.toggle("asset", entry.category === "assets");
  button.classList.toggle("request", entry.category === "requests");
  button.classList.toggle("leak", entry.category === "leaks");
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

  card.classList.toggle("asset", entry.category === "assets");
  card.classList.toggle("request", entry.category === "requests");
  card.classList.toggle("leak", entry.category === "leaks");

  methodEl.textContent = entry.method;
  urlEl.textContent = entry.url;

  if (entry.category === "leaks") {
    const leakMeta = [];
    leakMeta.push(entry.statusText || "Potential API credential");
    leakMeta.push("Static asset scan");
    if (entry.leak?.encodedFrom) {
      leakMeta.push("Decoded from base64");
    }
    metaEl.textContent = leakMeta.filter(Boolean).join(" • ");
  } else {
    const statusDescriptor = entry.status
      ? `${entry.status} ${entry.statusText}`.trim()
      : entry.statusText || "No response status";
    const metaParts = [statusDescriptor || "No response status"];
    if (entry.initiator) {
      metaParts.push(`Initiator: ${entry.initiator}`);
    }
    metaEl.textContent = metaParts.filter(Boolean).join(" • ");
  }

  const headersToDisplay =
    entry.isStaticDetection || entry.isLeakDetection
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
      : entry.isLeakDetection
        ? "No leak metadata captured."
        : "No auth headers detected.";
    headerListEl.appendChild(empty);
  }

  if (entry.isLeakDetection) {
    sendBtn.textContent = "Copy match";
    if (!entry.leak?.match) {
      sendBtn.disabled = true;
    }
    sendBtn.addEventListener("click", async () => {
      const match = entry.leak?.match;
      if (!match) {
        setStatus("No match to copy for this leak.");
        return;
      }
      const ok = await copyToClipboard(match);
      if (ok) {
        const previous = sendBtn.textContent;
        sendBtn.textContent = "Copied!";
        setStatus("Leak copied to clipboard.");
        setTimeout(() => {
          sendBtn.textContent = previous;
        }, 1500);
      } else {
        setStatus("Clipboard copy failed. Check clipboard permissions.");
      }
    });
  } else {
    sendBtn.addEventListener("click", () => sendEntry(entry, card));
  }

  return fragment;
}

async function copyToClipboard(text) {
  if (!text) {
    return false;
  }
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (error) {
    // Fallback below
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (error) {
    copied = false;
  }
  document.body.removeChild(textarea);
  return copied;
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
  if (!termsAccepted) {
    return;
  }
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
  if (!termsAccepted) {
    setStatus("Accept the Terms & Conditions in the SupaExplorer side panel to enable monitoring.");
    return;
  }
  state.requests = [];
  state.selectedId = null;
  state.activeTab = "requests";
  state.pendingScrollReset = true;
  renderRequests();
});

if (dom.openSidePanelBtn) {
  dom.openSidePanelBtn.addEventListener("click", () => {
    if (!termsAccepted) {
      setStatus("Opening Supabase Database Explorer so you can review the Terms & Conditions.");
      openSidePanel();
      return;
    }
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

// Load stored asset detections from the background script (only from current page)
async function loadStoredAssetDetections() {
  if (!termsAccepted) {
    return;
  }
  try {
    const ASSET_DETECTIONS_KEY = "sbde_asset_detections";
    const result = await chrome.storage.local.get([ASSET_DETECTIONS_KEY]);
    const storedMap = result?.[ASSET_DETECTIONS_KEY];
    
    if (!storedMap || typeof storedMap !== 'object') {
      return;
    }

    // Convert stored detections to entries, but only for current page scope
    let loadedCount = 0;
    let skippedCount = 0;
    
    Object.values(storedMap).forEach(projectDetections => {
      if (!Array.isArray(projectDetections)) return;
      
      projectDetections.forEach(detection => {
        // Only load detections from the current page scope
        if (!isUrlInPageScope(detection.assetUrl)) {
          skippedCount++;
          return;
        }

        // Skip if no full API key available
        if (!detection.apiKey || detection.apiKey.length < 20) {
          console.debug('[SBDE] Skipping detection - no full API key:', detection.assetUrl);
          skippedCount++;
          return;
        }

        const cacheKey = `${detection.assetUrl}|${detection.supabaseUrl}|${detection.apiKey}`;
        if (staticDetectionCache.has(cacheKey)) {
          return;
        }
        staticDetectionCache.add(cacheKey);
        loadedCount++;

        // Create a mock request object for createStaticEntry
        const mockRequest = {
          request: { url: detection.assetUrl },
          time: 0,
          initiator: { type: 'static-scan' }
        };

        // Convert stored detection to full detection format
        const fullDetection = {
          supabaseUrl: detection.supabaseUrl,
          apiKey: detection.apiKey, // Use full key
          keyLabel: detection.keyLabel,
          keyType: detection.keyType,
          assetUrl: detection.assetUrl
        };

        const entry = createStaticEntry(mockRequest, fullDetection);
        state.requests.push(entry);
      });
    });

    console.debug(`[SBDE] Loaded ${loadedCount} stored detections, skipped ${skippedCount} (out of scope or missing full key)`);
    
    if (state.requests.length > 0) {
      renderRequests();
    }
  } catch (error) {
    console.warn('[SBDE] Failed to load stored asset detections:', error);
  }
}

// Listen for storage changes to detect new asset detections in real-time
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') return;
  if (!termsAccepted) return;
  
  const ASSET_DETECTIONS_KEY = "sbde_asset_detections";
  if (changes[ASSET_DETECTIONS_KEY]) {
    console.debug('[SBDE DevTools] Asset detections updated in storage');
    // Clear cache and reload to pick up new detections
    staticDetectionCache.clear();
    state.requests = state.requests.filter(entry => entry.category !== 'assets');
    loadStoredAssetDetections();
  }
});

renderRequests();
// Don't load stored detections immediately - wait for pageScope to be initialized first
// (see chrome.devtools.inspectedWindow.eval callback above)
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
