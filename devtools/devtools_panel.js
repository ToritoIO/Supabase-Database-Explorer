const MAX_REQUESTS = 50;
const INTERESTING_HEADERS = ["authorization", "apikey", "api-key", "x-client-info", "x-apikey"];

const dom = {
  status: document.getElementById("status"),
  list: document.getElementById("request-list"),
  clearBtn: document.getElementById("clear-btn"),
  template: document.getElementById("request-template"),
  openSidePanelBtn: document.getElementById("open-sidepanel-btn"),
  authFilterCheckbox: document.getElementById("auth-filter-checkbox"),
};

const state = {
  requests: [],
  showOnlyAuth: true,
};

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

function renderRequests() {
  dom.list.innerHTML = "";
  if (!state.requests.length) {
    setStatus("Requests will appear as the inspected page talks to Supabase.");
    return;
  }

  const visible = state.requests.filter((entry) => !state.showOnlyAuth || entry.hasAuthHeaders);

  if (!visible.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No requests match the current filter.";
    dom.list.appendChild(empty);
    setStatus("No requests match the current filter. Disable “Only auth headers” to see all traffic.");
    return;
  }

  const descriptor = visible.length === 1 ? "request" : "requests";
  const totalDescriptor = state.requests.length === 1 ? "request" : "requests";
  if (state.showOnlyAuth) {
    setStatus(`${visible.length} auth ${descriptor} shown (${state.requests.length} ${totalDescriptor} captured this session).`);
  } else {
    setStatus(`${visible.length} ${descriptor} captured this session.`);
  }

  visible.forEach((entry) => {
    const fragment = dom.template.content.cloneNode(true);
    const card = fragment.querySelector(".request-card");
    const methodEl = fragment.querySelector(".request-method");
    const urlEl = fragment.querySelector(".request-url");
    const metaEl = fragment.querySelector(".request-meta");
    const headerListEl = fragment.querySelector(".header-list");
    const sendBtn = fragment.querySelector(".send-btn");

    methodEl.textContent = entry.method;
    urlEl.textContent = entry.url;
    metaEl.textContent = [
      entry.status ? `${entry.status} ${entry.statusText}`.trim() : "No response status",
      `Initiator: ${entry.initiator}`,
    ].join(" • ");

    const interesting = entry.headers.filter((header) =>
      INTERESTING_HEADERS.includes((header.name || "").toLowerCase())
    );

    if (interesting.length) {
      interesting.forEach((header) => {
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
      empty.textContent = "No auth headers detected.";
      headerListEl.appendChild(empty);
    }

    sendBtn.addEventListener("click", () => sendEntry(entry, card));

    dom.list.appendChild(fragment);
  });
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
  if (!shouldCapture(request)) {
    return;
  }
  const entry = createEntry(request);
  state.requests.unshift(entry);
  if (state.requests.length > MAX_REQUESTS) {
    state.requests.length = MAX_REQUESTS;
  }
  renderRequests();
}

dom.clearBtn.addEventListener("click", () => {
  state.requests = [];
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
