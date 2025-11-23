const CONNECTION_STORAGE_KEY = "sbde_connection";
const CONNECTION_META_KEY = "sbde_connection_meta";
const DETECTOR_SOURCE = "detector";
const PANEL_OPEN_COOLDOWN_MS = 5000;
const REPORT_STORAGE_KEY = "sbde_security_reports";
const REPORT_MAX_ENTRIES = 10;
const REPORT_TTL_MS = 1000 * 60 * 60 * 24;
const ASSET_DETECTIONS_KEY = "sbde_asset_detections";
const ASSET_DETECTIONS_MAX_PER_PROJECT = 25;
const ASSET_DETECTION_TTL_MS = 1000 * 60 * 60 * 24;
const LEAK_DETECTIONS_KEY = "sbde_generic_leaks";
const LEAK_DETECTIONS_MAX_PER_HOST = 25;
const LEAK_DETECTION_TTL_MS = 1000 * 60 * 60 * 24;

const TERMS_STORAGE_KEY = "sbde_terms_acceptance";
const TERMS_VERSION = "1.0";

const tabDetectionCache = new Map();
const panelOpenTimestamps = new Map();
const SHOW_BUBBLE_MESSAGE = "SBDE_SHOW_BUBBLE";
const HIDE_BUBBLE_MESSAGE = "SBDE_HIDE_BUBBLE";
const MESSAGE_ALLOWLIST_WITHOUT_TERMS = new Set(["SBDE_OPEN_SIDE_PANEL", "SBDE_CLOSE_OVERLAY"]);

let termsAccepted = false;

function isValidTermsAcceptance(record) {
  return Boolean(record && typeof record.version === "string" && record.version === TERMS_VERSION);
}

async function refreshTermsAcceptance() {
  try {
    const stored = await chrome.storage.local.get([TERMS_STORAGE_KEY]);
    const record = stored?.[TERMS_STORAGE_KEY];
    termsAccepted = isValidTermsAcceptance(record);
  } catch (error) {
    termsAccepted = false;
    console.error("Failed to read terms acceptance", error);
  }
  return termsAccepted;
}

refreshTermsAcceptance();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes[TERMS_STORAGE_KEY]) {
    return;
  }
  const record = changes[TERMS_STORAGE_KEY].newValue;
  termsAccepted = isValidTermsAcceptance(record);
  if (!termsAccepted) {
    tabDetectionCache.clear();
  }
});

function respondTermsRequired(sendResponse) {
  if (typeof sendResponse === "function") {
    sendResponse({ ok: false, reason: "Accept the Terms & Conditions to use SupaExplorer." });
  }
}

const cleanApiKey = (raw) => {
  if (!raw || typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  return trimmed.startsWith("Bearer ") ? trimmed.slice(7).trim() : trimmed;
};

function resolveTabHostname(tabId) {
  return new Promise((resolve) => {
    if (tabId === undefined || tabId < 0 || !chrome.tabs?.get) {
      resolve(null);
      return;
    }
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab?.url) {
        resolve(null);
        return;
      }
      try {
        const { hostname } = new URL(tab.url);
        resolve(hostname || null);
      } catch (error) {
        resolve(null);
      }
    });
  });
}

const extractProjectIdFromUrl = (url) => {
  if (!url) return null;
  try {
    const { hostname } = new URL(url);
    const match = hostname.match(/^([^.]+)\.supabase\.co$/i);
    return match ? match[1] : null;
  } catch (error) {
    return null;
  }
};

const decodeProjectRefFromKey = (apiKey) => {
  if (!apiKey || typeof apiKey !== "string") return null;
  const parts = apiKey.split(".");
  if (parts.length < 2) return null;
  try {
    let payloadPart = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = payloadPart.length % 4;
    if (pad) {
      payloadPart += "=".repeat(4 - pad);
    }
    const payloadRaw = atob(payloadPart);
    const payload = JSON.parse(payloadRaw);
    return (
      payload?.ref ||
      (typeof payload?.sub === "string" ? payload.sub.split(":")[0] : null) ||
      (typeof payload?.iss === "string" ? payload.iss.split("/")[3] : null)
    );
  } catch (error) {
    return null;
  }
};

const determineProjectId = (url, apiKey) => {
  return extractProjectIdFromUrl(url) || decodeProjectRefFromKey(apiKey);
};

const normalizeSchema = (schema) => {
  if (!schema || typeof schema !== "string") return "public";
  const trimmed = schema.trim();
  return trimmed || "public";
};

const detectionCacheKey = (tabId) => (tabId !== undefined && tabId >= 0 ? `tab:${tabId}` : "global");

const isSupabaseUrl = (url) => {
  if (!url || typeof url !== "string") return false;
  try {
    const { hostname } = new URL(url);
    return hostname.includes(".supabase.co");
  } catch (error) {
    return url.includes(".supabase.co");
  }
};

function normalizeReportPayload(report) {
  if (!report || typeof report !== "object") {
    throw new Error("Invalid report payload.");
  }
  if (!report.id || typeof report.id !== "string") {
    throw new Error("Report payload missing id.");
  }
  const createdAt = typeof report.createdAt === "string" ? report.createdAt : new Date().toISOString();
  return { ...report, createdAt };
}

async function persistSecurityReport(report) {
  if (!termsAccepted) {
    throw new Error("Terms not accepted.");
  }
  const normalized = normalizeReportPayload(report);
  const stored = await chrome.storage.local.get([REPORT_STORAGE_KEY]);
  const current = stored?.[REPORT_STORAGE_KEY];
  const map = current && typeof current === "object" ? { ...current } : {};
  map[normalized.id] = normalized;

  const now = Date.now();
  const entries = Object.values(map)
    .filter((entry) => entry && typeof entry.id === "string")
    .sort((a, b) => {
      const aTime = new Date(a.createdAt || 0).getTime();
      const bTime = new Date(b.createdAt || 0).getTime();
      return bTime - aTime;
    });

  const trimmed = [];
  for (const entry of entries) {
    const createdAtMs = new Date(entry.createdAt || 0).getTime();
    if (Number.isFinite(createdAtMs) && now - createdAtMs > REPORT_TTL_MS) {
      continue;
    }
    trimmed.push(entry);
    if (trimmed.length >= REPORT_MAX_ENTRIES) {
      break;
    }
  }

  const nextStore = {};
  trimmed.forEach((entry) => {
    nextStore[entry.id] = entry;
  });

  await chrome.storage.local.set({ [REPORT_STORAGE_KEY]: nextStore });
  return normalized;
}

async function createSecurityReportTab(report) {
  if (!termsAccepted) {
    throw new Error("Terms not accepted.");
  }
  const saved = await persistSecurityReport(report);
  const url = chrome.runtime.getURL(`report/report.html?id=${encodeURIComponent(saved.id)}`);
  await chrome.tabs.create({ url });
  return saved.id;
}

function normalizeAssetDetection(summary) {
  if (!summary || typeof summary !== "object") {
    throw new Error("Invalid asset detection payload.");
  }
  const projectId = typeof summary.projectId === "string" ? summary.projectId.trim() : "";
  if (!projectId) {
    throw new Error("Asset detection payload missing project id.");
  }

  const detectedAt = typeof summary.detectedAt === "string" ? summary.detectedAt : new Date().toISOString();
  const supabaseUrl = typeof summary.supabaseUrl === "string" ? summary.supabaseUrl : "";
  const assetUrl = typeof summary.assetUrl === "string" ? summary.assetUrl : "";
  const keyType = typeof summary.keyType === "string" ? summary.keyType : "";
  const keyLabel = typeof summary.keyLabel === "string" ? summary.keyLabel : "";
  const apiKeySnippet = typeof summary.apiKeySnippet === "string" ? summary.apiKeySnippet : "";
  const apiKey = typeof summary.apiKey === "string" ? summary.apiKey : ""; // Store full key for DevTools

  return {
    projectId,
    supabaseUrl,
    assetUrl,
    keyType,
    keyLabel,
    apiKeySnippet,
    apiKey,
    detectedAt,
  };
}

async function recordAssetDetectionSummary(summary) {
  if (!termsAccepted) {
    return null;
  }
  const normalized = normalizeAssetDetection(summary);
  const stored = await chrome.storage.local.get([ASSET_DETECTIONS_KEY]);
  const current = stored?.[ASSET_DETECTIONS_KEY];
  const map = current && typeof current === "object" ? { ...current } : {};
  const now = Date.now();

  const existing = Array.isArray(map[normalized.projectId]) ? map[normalized.projectId] : [];
  const filtered = existing.filter((item) => {
    if (!item || typeof item !== "object") return false;
    const age = now - new Date(item.detectedAt || 0).getTime();
    if (Number.isFinite(age) && age > ASSET_DETECTION_TTL_MS) {
      return false;
    }
    const sameAsset = item.assetUrl === normalized.assetUrl && item.apiKeySnippet === normalized.apiKeySnippet;
    return !sameAsset;
  });

  filtered.unshift({
    supabaseUrl: normalized.supabaseUrl,
    assetUrl: normalized.assetUrl,
    keyType: normalized.keyType,
    keyLabel: normalized.keyLabel,
    apiKeySnippet: normalized.apiKeySnippet,
    apiKey: normalized.apiKey, // Include full key for DevTools
    detectedAt: normalized.detectedAt,
  });

  if (filtered.length > ASSET_DETECTIONS_MAX_PER_PROJECT) {
    filtered.length = ASSET_DETECTIONS_MAX_PER_PROJECT;
  }

  map[normalized.projectId] = filtered;
  await chrome.storage.local.set({ [ASSET_DETECTIONS_KEY]: map });

  return normalized;
}

function normalizeLeakDetection(summary) {
  if (!summary || typeof summary !== "object") {
    throw new Error("Invalid leak detection payload.");
  }

  const sourceUrl = typeof summary.sourceUrl === "string" ? summary.sourceUrl.trim() : "";
  const assetUrl = typeof summary.assetUrl === "string" ? summary.assetUrl.trim() : "";
  const pattern = typeof summary.pattern === "string" ? summary.pattern : "Unknown pattern";
  const matchSnippet = typeof summary.matchSnippet === "string" ? summary.matchSnippet : "";
  const contextSnippet = typeof summary.contextSnippet === "string" ? summary.contextSnippet : "";
  const encodedSnippet = typeof summary.encodedSnippet === "string" ? summary.encodedSnippet : "";
  const detectedAt = typeof summary.detectedAt === "string" ? summary.detectedAt : new Date().toISOString();

  let host = "unknown";
  const hostSource = sourceUrl || assetUrl;
  if (hostSource) {
    try {
      host = new URL(hostSource).hostname || host;
    } catch (error) {
      host = hostSource;
    }
  }

  return {
    host,
    sourceUrl,
    assetUrl,
    pattern,
    matchSnippet,
    contextSnippet,
    encodedSnippet,
    detectedAt,
  };
}

async function recordLeakDetectionSummary(summary) {
  if (!termsAccepted) {
    return null;
  }
  const normalized = normalizeLeakDetection(summary);
  const stored = await chrome.storage.local.get([LEAK_DETECTIONS_KEY]);
  const current = stored?.[LEAK_DETECTIONS_KEY];
  const map = current && typeof current === "object" ? { ...current } : {};
  const now = Date.now();

  const existing = Array.isArray(map[normalized.host]) ? map[normalized.host] : [];
  const filtered = existing.filter((item) => {
    if (!item || typeof item !== "object") return false;
    const age = now - new Date(item.detectedAt || 0).getTime();
    if (Number.isFinite(age) && age > LEAK_DETECTION_TTL_MS) {
      return false;
    }
    return !(
      item.sourceUrl === normalized.sourceUrl &&
      item.pattern === normalized.pattern &&
      item.matchSnippet === normalized.matchSnippet
    );
  });

  filtered.unshift({
    host: normalized.host,
    sourceUrl: normalized.sourceUrl,
    assetUrl: normalized.assetUrl,
    pattern: normalized.pattern,
    matchSnippet: normalized.matchSnippet,
    contextSnippet: normalized.contextSnippet,
    encodedSnippet: normalized.encodedSnippet,
    detectedAt: normalized.detectedAt,
  });

  if (filtered.length > LEAK_DETECTIONS_MAX_PER_HOST) {
    filtered.length = LEAK_DETECTIONS_MAX_PER_HOST;
  }

  map[normalized.host] = filtered;
  await chrome.storage.local.set({ [LEAK_DETECTIONS_KEY]: map });

  return normalized;
}

async function handleSupabaseDetection({ tabId, url, apiKey, schema }) {
  if (!termsAccepted) {
    return;
  }
  const cleanKey = cleanApiKey(apiKey);
  if (!cleanKey) return;

  const projectId = determineProjectId(url, cleanKey);
  if (!projectId) return;

  const normalizedSchema = normalizeSchema(schema);
  const cacheKey = detectionCacheKey(tabId);
  const previous = tabDetectionCache.get(cacheKey);
  if (
    previous &&
    previous.projectId === projectId &&
    previous.apiKey === cleanKey &&
    previous.schema === normalizedSchema
  ) {
    return;
  }

  tabDetectionCache.set(cacheKey, {
    projectId,
    apiKey: cleanKey,
    schema: normalizedSchema,
    timestamp: Date.now(),
  });

  const stored = await chrome.storage.local.get([CONNECTION_STORAGE_KEY]);
  const current = stored?.[CONNECTION_STORAGE_KEY];

  const inspectedHost = await resolveTabHostname(tabId);

  const connection = {
    projectId,
    schema: normalizedSchema,
    apiKey: cleanKey,
    bearer: cleanKey,
    inspectedHost: inspectedHost || "",
  };

  const isSameConnection =
    current &&
    current.projectId === connection.projectId &&
    current.apiKey === connection.apiKey &&
    normalizeSchema(current.schema) === connection.schema &&
    (current.inspectedHost || "") === (connection.inspectedHost || "");

  const metaPayload = {
    source: DETECTOR_SOURCE,
    updatedAt: Date.now(),
    tabId: tabId !== undefined && tabId >= 0 ? tabId : undefined,
  };

  notifyBubble(tabId, true);

  if (isSameConnection) {
    await chrome.storage.local.set({ [CONNECTION_META_KEY]: metaPayload });
    return;
  }

  await chrome.storage.local.set({
    [CONNECTION_STORAGE_KEY]: connection,
    [CONNECTION_META_KEY]: metaPayload,
  });

  if (tabId !== undefined && tabId >= 0) {
    openSidePanelForTab(tabId).catch(() => {});
  }
}

async function clearTabDetection(tabId) {
  if (tabId === undefined || tabId < 0) return;
  const cacheKey = detectionCacheKey(tabId);
  tabDetectionCache.delete(cacheKey);

  notifyBubble(tabId, false);

  const stored = await chrome.storage.local.get([CONNECTION_STORAGE_KEY, CONNECTION_META_KEY]);
  const meta = stored?.[CONNECTION_META_KEY];
  const connection = stored?.[CONNECTION_STORAGE_KEY];

  if (!meta || meta.source !== DETECTOR_SOURCE || meta.tabId !== tabId) {
    return;
  }

  if (!connection) {
    await chrome.storage.local.set({
      [CONNECTION_META_KEY]: { source: DETECTOR_SOURCE, updatedAt: Date.now(), tabId, cleared: true },
    });
    return;
  }

  await chrome.storage.local.set({
    [CONNECTION_STORAGE_KEY]: null,
    [CONNECTION_META_KEY]: { source: DETECTOR_SOURCE, updatedAt: Date.now(), tabId, cleared: true },
  });
}

async function openSidePanelForTab(tabId, { force = false } = {}) {
  const now = Date.now();
  const lastOpened = panelOpenTimestamps.get(tabId) || 0;
  if (!force && now - lastOpened < PANEL_OPEN_COOLDOWN_MS) {
    return;
  }
  panelOpenTimestamps.set(tabId, now);
  try {
    await chrome.sidePanel.setOptions({ tabId, path: "panel/sidepanel.html" });
    await chrome.sidePanel.open({ tabId });
  } catch (error) {
    if (error?.message?.toLowerCase().includes("user gesture")) {
      panelOpenTimestamps.delete(tabId);
    }
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  try {
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  } catch (error) {
    console.error("Failed to configure side panel behavior:", error);
  }
});

chrome.action.onClicked.addListener(async (tab) => {
  if (!tab.id) return;

  try {
    await openSidePanelForTab(tab.id, { force: true });
  } catch (error) {
    console.error("Failed to open side panel:", error);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const messageType = message?.type;
  if (!termsAccepted && !MESSAGE_ALLOWLIST_WITHOUT_TERMS.has(messageType)) {
    respondTermsRequired(sendResponse);
    return false;
  }
  if (message?.type === "SBDE_OPEN_EXPLORER") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];

      if (!tab?.id) {
        sendResponse({ ok: false, reason: "No active tab found." });
        return;
      }

      if (tab.url?.startsWith("chrome://") || tab.url?.startsWith("edge://") || tab.url?.startsWith("about:")) {
        sendResponse({ ok: false, reason: "Cannot open overlay on browser chrome pages." });
        return;
      }

      const trySendOverlay = () => new Promise((resolve, reject) => {
        chrome.tabs.sendMessage(tab.id, { type: "SBDE_OPEN_OVERLAY" }, () => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve(true);
          }
        });
      });

      trySendOverlay()
        .then(() => sendResponse({ ok: true }))
        .catch((error) => {
          chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content/content.js"] })
            .then(() => trySendOverlay()
              .then(() => sendResponse({ ok: true }))
              .catch((err) => sendResponse({ ok: false, reason: err?.message || "Failed to open overlay." })))
            .catch((injectErr) => sendResponse({ ok: false, reason: injectErr?.message || "Failed to inject overlay script." }));
        });
    });
    return true;
  }

  if (message?.type === "SBDE_CLOSE_OVERLAY") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (tab?.id) {
        chrome.tabs.sendMessage(tab.id, { type: "SBDE_CLOSE_OVERLAY" }, () => {
          if (chrome.runtime.lastError) {
            // Ignore missing content script
          }
        });
      }
    });
    return;
  }

  if (message?.type === "SBDE_SUPABASE_REQUEST") {
    const tabId = sender?.tab?.id;
    handleSupabaseDetection({
      tabId,
      url: message.url,
      apiKey: message.apiKey,
      schema: message.schema,
    })
      .then(() => sendResponse?.({ ok: true }))
      .catch((error) => sendResponse?.({ ok: false, reason: error?.message || "Detection failed." }));
    return true;
  }

  if (message?.type === "SBDE_REGISTER_ASSET_DETECTION" && message?.payload) {
    recordAssetDetectionSummary(message.payload)
      .then(() => sendResponse?.({ ok: true }))
      .catch((error) => sendResponse?.({ ok: false, reason: error instanceof Error ? error.message : String(error || "Failed to persist detection.") }));
    return true;
  }

  if (message?.type === "SBDE_REGISTER_GENERIC_LEAK" && message?.payload) {
    recordLeakDetectionSummary(message.payload)
      .then(() => sendResponse?.({ ok: true }))
      .catch((error) =>
        sendResponse?.({
          ok: false,
          reason: error instanceof Error ? error.message : String(error || "Failed to persist leak detection."),
        })
      );
    return true;
  }

  if (message?.type === "SBDE_APPLY_CONNECTION" && message?.payload) {
    const payload = {
      projectId: message.payload.projectId || "",
      schema: message.payload.schema || "public",
      apiKey: message.payload.apiKey || "",
      bearer: message.payload.bearer || message.payload.apiKey || "",
      inspectedHost: message.payload.inspectedHost || "",
    };

    chrome.storage.local.set({
      [CONNECTION_STORAGE_KEY]: payload,
      [CONNECTION_META_KEY]: { source: "devtools", updatedAt: Date.now() },
    }, () => {
      if (chrome.runtime.lastError) {
        sendResponse?.({ ok: false, reason: chrome.runtime.lastError.message });
        return;
      }
      sendResponse?.({ ok: true });
    });
    return true;
  }

  if (message?.type === "SBDE_CREATE_SECURITY_REPORT" && message?.payload) {
    (async () => {
      try {
        const id = await createSecurityReportTab(message.payload);
        sendResponse?.({ ok: true, id });
      } catch (error) {
        sendResponse?.({ ok: false, reason: error instanceof Error ? error.message : String(error || "Failed to create report.") });
      }
    })();
    return true;
  }

  if (message?.type === "SBDE_OPEN_SIDE_PANEL") {
    const targetTabId = message.tabId ?? sender?.tab?.id;
    if (!targetTabId) {
      sendResponse?.({ ok: false, reason: "No tabId provided for side panel request." });
      return;
    }

    openSidePanelForTab(targetTabId, { force: true })
      .then(() => sendResponse?.({ ok: true }))
      .catch((error) => sendResponse?.({ ok: false, reason: error?.message || "Failed to open side panel." }));
    return true;
  }
});

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!termsAccepted) {
      return;
    }
    const headers = details.requestHeaders || [];
    let apiKey;
    let schema;
    for (const header of headers) {
      const name = header?.name?.toLowerCase();
      if (!name) continue;
      if (name === "apikey" || name === "authorization") {
        apiKey = header?.value;
      } else if (name === "accept-profile") {
        schema = header?.value;
      }
    }
    if (apiKey) {
      handleSupabaseDetection({
        tabId: details.tabId,
        url: details.url,
        apiKey,
        schema,
      }).catch(() => {});
    }
  },
  { urls: ["https://*.supabase.co/*"] },
  ["requestHeaders", "extraHeaders"]
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (!changeInfo || typeof changeInfo.url !== "string") {
    return;
  }
  if (isSupabaseUrl(changeInfo.url)) {
    return;
  }
  clearTabDetection(tabId).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  panelOpenTimestamps.delete(tabId);
  clearTabDetection(tabId).catch(() => {});
});

function notifyBubble(tabId, shouldShow) {
  if (tabId === undefined || tabId < 0) return;
  chrome.tabs.sendMessage(tabId, { type: shouldShow ? SHOW_BUBBLE_MESSAGE : HIDE_BUBBLE_MESSAGE }, () => {
    const err = chrome.runtime.lastError;
    if (err) {
      // Ignore missing content scripts; they may not be injected yet.
    }
  });
}
