const storageKeys = {
  connection: "sbde_connection",
  selectedTable: "sbde_currentTable",
  theme: "sbde_theme",
};

const state = {
  connection: null,
  baseUrl: "",
  openApi: null,
  tables: [],
  columnCache: {},
  currentTable: null,
  theme: "dark",
};

const dom = {
  closeBtn: document.getElementById("close-modal-btn"),
  tabButtons: Array.from(document.querySelectorAll(".tab-btn")),
  tabPanels: Array.from(document.querySelectorAll(".tab-panel")),
  modalStatus: document.getElementById("modal-status"),
  modalTableName: document.getElementById("modal-table-name"),
  browseForm: document.getElementById("browse-form"),
  browseColumns: document.getElementById("browse-columns"),
  browseLimit: document.getElementById("browse-limit"),
  browsePage: document.getElementById("browse-page"),
  browseOrderColumn: document.getElementById("browse-order-column"),
  browseOrderDirection: document.getElementById("browse-order-direction"),
  browseFilterColumn: document.getElementById("browse-filter-column"),
  browseFilterOperator: document.getElementById("browse-filter-operator"),
  browseFilterValue: document.getElementById("browse-filter-value"),
  browseResults: document.getElementById("browse-results"),
  browseCount: document.getElementById("browse-count"),
  insertForm: document.getElementById("insert-form"),
  insertFields: document.getElementById("insert-fields"),
  insertFeedback: document.getElementById("insert-feedback"),
  updateForm: document.getElementById("update-form"),
  updateFields: document.getElementById("update-fields"),
  updateFilterColumn: document.getElementById("update-filter-column"),
  updateFilterOperator: document.getElementById("update-filter-operator"),
  updateFilterValue: document.getElementById("update-filter-value"),
  updateFeedback: document.getElementById("update-feedback"),
  deleteForm: document.getElementById("delete-form"),
  deleteFilterColumn: document.getElementById("delete-filter-column"),
  deleteFilterOperator: document.getElementById("delete-filter-operator"),
  deleteFilterValue: document.getElementById("delete-filter-value"),
  deleteFeedback: document.getElementById("delete-feedback"),
};

function sanitize(value) {
  return (value || "").trim();
}

function setStatus(message, type = "idle") {
  const el = dom.modalStatus;
  el.textContent = message;
  el.classList.remove("status-idle", "status-success", "status-error", "status-progress");
  if (type === "success") el.classList.add("status-success");
  else if (type === "error") el.classList.add("status-error");
  else if (type === "progress") el.classList.add("status-progress");
  else el.classList.add("status-idle");
}

function buildBaseUrl(projectId) {
  const cleanId = sanitize(projectId);
  if (!cleanId) return "";
  return `https://${cleanId}.supabase.co/rest/v1`;
}

function buildHeaders(accept = "application/json") {
  if (!state.connection) return {};
  const apiKey = sanitize(state.connection.apiKey);
  const bearer = sanitize(state.connection.bearer || state.connection.apiKey);
  const schema = sanitize(state.connection.schema || "public");
  return {
    apikey: apiKey,
    authorization: `Bearer ${bearer}`,
    "Accept-Profile": schema,
    accept,
    "cache-control": "no-cache",
  };
}

function applyTheme(theme) {
  const nextTheme = theme === "light" ? "light" : "dark";
  state.theme = nextTheme;
  document.body.dataset.theme = nextTheme;
}

async function storageGet(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get(key, resolve);
  });
}

async function fetchOpenApi() {
  const url = `${state.baseUrl.replace(/\/$/, "")}/`;
  const headers = buildHeaders("application/openapi+json;version=3.0");
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

function extractColumnsFromOpenApi(table, schema) {
  const components = state.openApi?.components?.schemas || {};
  const candidates = [
    `${schema}_${table}`,
    table,
    `${schema}.${table}`,
    `${table}_insert`,
    `${table}_update`,
  ];

  const columns = new Set();
  candidates.forEach((name) => {
    const entry = components[name];
    if (entry && typeof entry === "object" && entry.properties) {
      Object.keys(entry.properties).forEach((col) => columns.add(col));
    }
  });
  return columns.size ? Array.from(columns).sort() : null;
}

async function inferColumnsFromData(table) {
  const url = new URL(`${state.baseUrl.replace(/\/$/, "")}/${table}`);
  const headers = buildHeaders();
  url.searchParams.set("select", "*");
  url.searchParams.set("limit", "10");

  try {
    const response = await fetch(url.toString(), { headers });
    if (!response.ok) return null;
    const body = await response.json();
    if (Array.isArray(body) && body.length > 0) {
      const set = new Set();
      body.forEach((row) => {
        if (row && typeof row === "object") {
          Object.keys(row).forEach((key) => set.add(key));
        }
      });
      return Array.from(set).sort();
    }
  } catch (error) {
    console.error("Failed to infer columns", error);
  }
  return null;
}

async function getColumnsForTable(table) {
  const key = `${table}::${state.connection.schema}`;
  if (state.columnCache[key]) {
    return state.columnCache[key];
  }

  const fromOpenApi = extractColumnsFromOpenApi(table, state.connection.schema);
  const inferred = await inferColumnsFromData(table);
  let combined = null;

  if (fromOpenApi && inferred) {
    combined = Array.from(new Set([...fromOpenApi, ...inferred])).sort();
  } else if (fromOpenApi) {
    combined = fromOpenApi;
  } else if (inferred) {
    combined = inferred;
  } else {
    combined = [];
  }

  const payload = { combined, fromOpenApi, inferred };
  state.columnCache[key] = payload;
  return payload;
}

function activateTab(name) {
  dom.tabButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
  dom.tabPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.id === `tab-${name}`);
  });
}

function renderColumnOptions(columns) {
  const selects = [
    dom.browseColumns,
    dom.browseOrderColumn,
    dom.browseFilterColumn,
    dom.updateFilterColumn,
    dom.deleteFilterColumn,
  ];

  selects.forEach((select) => {
    select.innerHTML = "";
    columns.forEach((col) => {
      const option = document.createElement("option");
      option.value = col;
      option.textContent = col;
      select.appendChild(option.cloneNode(true));
    });
  });

  dom.browseColumns.querySelectorAll("option").forEach((option) => {
    option.selected = true;
  });
}

function renderDynamicFieldSet(container, columns, prefix) {
  container.innerHTML = "";
  columns.forEach((col) => {
    const label = document.createElement("label");
    label.innerHTML = `
      <span>${col}</span>
      <input type="text" data-column="${col}" data-prefix="${prefix}" placeholder="Leave blank to ignore" />
    `;
    container.appendChild(label);
  });
}

async function hydrateForTable() {
  if (!state.currentTable) {
    setStatus("No table selected.", "error");
    return;
  }
  setStatus("Loading columns…", "progress");

  try {
    const { combined } = await getColumnsForTable(state.currentTable);
    const columns = combined || [];
    if (!columns.length) {
      setStatus("Could not discover columns. Table may be empty.", "error");
      return;
    }

    renderColumnOptions(columns);
    renderDynamicFieldSet(dom.insertFields, columns, "insert");
    renderDynamicFieldSet(dom.updateFields, columns, "update");
    dom.modalTableName.textContent = `${state.connection.schema}.${state.currentTable}`;
    setStatus("Columns ready.", "success");
    activateTab("browse");
    dom.insertFeedback.textContent = "";
    dom.updateFeedback.textContent = "";
    dom.deleteFeedback.textContent = "";
    await runBrowseQuery();
  } catch (error) {
    console.error(error);
    setStatus(error.message, "error");
  }
}

function collectSelectedColumns(select) {
  return Array.from(select.selectedOptions || []).map((opt) => opt.value);
}

function serializeFilter(column, operator, value) {
  if (!column || !value) return null;
  return { [column]: `${operator}.${value}` };
}

function coerceValue(raw) {
  const value = sanitize(raw);
  if (value === "") return null;
  if (value.toLowerCase() === "true") return true;
  if (value.toLowerCase() === "false") return false;
  if (!Number.isNaN(Number(value)) && value !== "") {
    return Number(value);
  }
  return value;
}

async function runBrowseQuery(event) {
  event?.preventDefault();
  if (!state.currentTable) return;

  const selectedColumns = collectSelectedColumns(dom.browseColumns);
  const limit = Number(dom.browseLimit.value) || 100;
  const page = Math.max(1, Number(dom.browsePage.value) || 1);
  const orderColumn = dom.browseOrderColumn.value;
  const orderDir = dom.browseOrderDirection.value || "asc";
  const filterColumn = dom.browseFilterColumn.value;
  const filterOperator = dom.browseFilterOperator.value;
  const filterValue = sanitize(dom.browseFilterValue.value);

  const url = new URL(`${state.baseUrl.replace(/\/$/, "")}/${state.currentTable}`);
  const headers = buildHeaders();
  headers.Prefer = "count=exact";

  if (selectedColumns.length) {
    url.searchParams.set("select", selectedColumns.join(","));
  }
  url.searchParams.set("limit", String(limit));
  url.searchParams.set("offset", String((page - 1) * limit));

  if (orderColumn) {
    url.searchParams.set("order", `${orderColumn}.${orderDir}`);
  }

  const filter = serializeFilter(filterColumn, filterOperator, filterValue);
  if (filter) {
    Object.entries(filter).forEach(([key, val]) => url.searchParams.set(key, val));
  }

  setStatus("Fetching rows…", "progress");

  try {
    const response = await fetch(url.toString(), { headers });
    const text = await response.text();
    const body = text && text.trim() ? JSON.parse(text) : [];
    if (!response.ok) {
      throw new Error(`Browse failed (${response.status}): ${text}`);
    }
    renderBrowseResults(body);

    const contentRange = response.headers.get("Content-Range");
    if (contentRange && contentRange.includes("/")) {
      const total = contentRange.split("/").pop();
      dom.browseCount.textContent = total && total !== "*" ? `${total} rows total` : "";
    } else {
      dom.browseCount.textContent = "";
    }

    setStatus("Rows loaded.", "success");
  } catch (error) {
    console.error(error);
    dom.browseResults.innerHTML = "<p>Query failed.</p>";
    setStatus(error.message, "error");
  }
}

function renderBrowseResults(rows) {
  if (!Array.isArray(rows) || !rows.length) {
    dom.browseResults.innerHTML = "<p>No rows found.</p>";
    return;
  }

  const columns = Object.keys(rows[0]);
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headerRow = document.createElement("tr");
  columns.forEach((col) => {
    const th = document.createElement("th");
    th.textContent = col;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);

  const tbody = document.createElement("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    columns.forEach((col) => {
      const td = document.createElement("td");
      const value = row[col];
      if (value === null || value === undefined) {
        td.textContent = "—";
      } else if (typeof value === "object") {
        td.textContent = JSON.stringify(value);
      } else {
        td.textContent = String(value);
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });

  table.appendChild(thead);
  table.appendChild(tbody);
  dom.browseResults.innerHTML = "";
  dom.browseResults.appendChild(table);
  enableColumnResize(table);
}

function collectDynamicFormValues(container) {
  const inputs = Array.from(container.querySelectorAll("input[data-column]"));
  const payload = {};
  inputs.forEach((input) => {
    const value = coerceValue(input.value);
    if (value !== null && value !== "") {
      payload[input.dataset.column] = value;
    }
  });
  return payload;
}

async function handleInsert(event) {
  event.preventDefault();
  if (!state.currentTable) return;

  const data = collectDynamicFormValues(dom.insertFields);
  if (!Object.keys(data).length) {
    dom.insertFeedback.textContent = "Enter at least one column to insert.";
    dom.insertFeedback.className = "feedback error";
    return;
  }

  const url = `${state.baseUrl.replace(/\/$/, "")}/${state.currentTable}`;
  const headers = buildHeaders();
  headers["Content-Type"] = "application/json";
  headers.Prefer = "return=representation";

  setStatus("Inserting row…", "progress");
  dom.insertFeedback.textContent = "";

  try {
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(data),
    });
    const text = await response.text();
    const payload = text && text.trim() ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error(`Insert failed (${response.status}): ${text}`);
    }
    dom.insertFeedback.textContent = payload ? JSON.stringify(payload, null, 2) : "Row inserted.";
    dom.insertFeedback.className = "feedback success";
    setStatus("Insert successful.", "success");
    await runBrowseQuery();
  } catch (error) {
    console.error(error);
    dom.insertFeedback.textContent = error.message;
    dom.insertFeedback.className = "feedback error";
    setStatus(error.message, "error");
  }
}

function enableColumnResize(table) {
  const headers = table.querySelectorAll("th");
  table.style.tableLayout = "fixed";
  headers.forEach((th, index) => {
    th.style.position = "relative";
    const resizer = document.createElement("span");
    resizer.className = "column-resizer";
    resizer.dataset.columnIndex = String(index);
    th.appendChild(resizer);

    let startX = 0;
    let startWidth = 0;

    const onMouseMove = (event) => {
      const delta = event.pageX - startX;
      const newWidth = Math.max(80, startWidth + delta);
      applyColumnWidth(table, index, newWidth);
    };

    const onMouseUp = () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };

    resizer.addEventListener("mousedown", (event) => {
      event.preventDefault();
      startX = event.pageX;
      startWidth = th.offsetWidth;
      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    });
  });
}

function applyColumnWidth(table, columnIndex, width) {
  const px = `${width}px`;
  const selector = `:nth-child(${columnIndex + 1})`;
  table.querySelectorAll(`th${selector}`).forEach((th) => {
    th.style.width = px;
    th.style.minWidth = px;
  });
  table.querySelectorAll(`td${selector}`).forEach((td) => {
    td.style.width = px;
    td.style.minWidth = px;
  });
}

async function handleUpdate(event) {
  event.preventDefault();
  if (!state.currentTable) return;

  const data = collectDynamicFormValues(dom.updateFields);
  if (!Object.keys(data).length) {
    dom.updateFeedback.textContent = "Provide at least one column to update.";
    dom.updateFeedback.className = "feedback error";
    return;
  }

  const filterColumn = dom.updateFilterColumn.value;
  const filterOperator = dom.updateFilterOperator.value;
  const filterValue = sanitize(dom.updateFilterValue.value);

  if (!filterColumn || !filterValue) {
    dom.updateFeedback.textContent = "Filter column and value are required.";
    dom.updateFeedback.className = "feedback error";
    return;
  }

  const params = new URLSearchParams();
  params.set(filterColumn, `${filterOperator}.${filterValue}`);

  const url = `${state.baseUrl.replace(/\/$/, "")}/${state.currentTable}?${params.toString()}`;
  const headers = buildHeaders();
  headers["Content-Type"] = "application/json";
  headers.Prefer = "return=representation";

  setStatus("Updating rows…", "progress");
  dom.updateFeedback.textContent = "";

  try {
    const response = await fetch(url, {
      method: "PATCH",
      headers,
      body: JSON.stringify(data),
    });
    const text = await response.text();
    const payload = text && text.trim() ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error(`Update failed (${response.status}): ${text}`);
    }
    dom.updateFeedback.textContent = payload ? JSON.stringify(payload, null, 2) : "Rows updated.";
    dom.updateFeedback.className = "feedback success";
    setStatus("Update successful.", "success");
    await runBrowseQuery();
  } catch (error) {
    console.error(error);
    dom.updateFeedback.textContent = error.message;
    dom.updateFeedback.className = "feedback error";
    setStatus(error.message, "error");
  }
}

async function handleDelete(event) {
  event.preventDefault();
  if (!state.currentTable) return;

  const filterColumn = dom.deleteFilterColumn.value;
  const filterOperator = dom.deleteFilterOperator.value;
  const filterValue = sanitize(dom.deleteFilterValue.value);

  if (!filterColumn || !filterValue) {
    dom.deleteFeedback.textContent = "Filter column and value are required for deletes.";
    dom.deleteFeedback.className = "feedback error";
    return;
  }

  const params = new URLSearchParams();
  params.set(filterColumn, `${filterOperator}.${filterValue}`);

  const url = `${state.baseUrl.replace(/\/$/, "")}/${state.currentTable}?${params.toString()}`;
  const headers = buildHeaders();
  headers.Prefer = "return=representation";

  setStatus("Deleting rows…", "progress");
  dom.deleteFeedback.textContent = "";

  try {
    const response = await fetch(url, {
      method: "DELETE",
      headers,
    });
    const text = await response.text();
    const payload = text && text.trim() ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error(`Delete failed (${response.status}): ${text}`);
    }
    dom.deleteFeedback.textContent = payload ? JSON.stringify(payload, null, 2) : "Rows deleted.";
    dom.deleteFeedback.className = "feedback success";
    setStatus("Delete successful.", "success");
    await runBrowseQuery();
  } catch (error) {
    console.error(error);
    dom.deleteFeedback.textContent = error.message;
    dom.deleteFeedback.className = "feedback error";
    setStatus(error.message, "error");
  }
}

function handleClose() {
  if (chrome?.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ type: "SBDE_CLOSE_OVERLAY" });
  } else {
    window.parent?.postMessage({ type: "SBDE_CLOSE_OVERLAY" }, "*");
  }
}

async function loadStateFromStorage() {
  const connectionStored = await storageGet(storageKeys.connection);
  const connection = connectionStored?.[storageKeys.connection];
  if (!connection || !connection.projectId || !connection.apiKey) {
    throw new Error("Connect from the side panel first.");
  }

  state.connection = {
    projectId: connection.projectId,
    schema: connection.schema || "public",
    apiKey: connection.apiKey,
    bearer: connection.bearer || connection.apiKey,
  };
  state.baseUrl = buildBaseUrl(state.connection.projectId);

  const tableStored = await storageGet(storageKeys.selectedTable);
  state.currentTable = tableStored?.[storageKeys.selectedTable] || null;
  if (!state.currentTable) {
    throw new Error("Select a table in the side panel.");
  }

  const themeStored = await storageGet(storageKeys.theme);
  applyTheme(themeStored?.[storageKeys.theme] || "dark");
}

function registerEventListeners() {
  dom.closeBtn.addEventListener("click", handleClose);
  dom.tabButtons.forEach((button) => {
    button.addEventListener("click", () => activateTab(button.dataset.tab));
  });
  dom.browseForm.addEventListener("submit", runBrowseQuery);
  dom.insertForm.addEventListener("submit", handleInsert);
  dom.updateForm.addEventListener("submit", handleUpdate);
  dom.deleteForm.addEventListener("submit", handleDelete);
  window.addEventListener("message", async (event) => {
    if (event.data?.type === "SBDE_REFRESH_TABLE") {
      await refreshSelectedTable();
    }
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes[storageKeys.theme]) {
      applyTheme(changes[storageKeys.theme].newValue);
    }
  });
}

async function init() {
  applyTheme(state.theme);
  registerEventListeners();
  try {
    await loadStateFromStorage();
  } catch (error) {
    setStatus(error.message, "error");
    dom.browseResults.innerHTML = `<p>${error.message}</p>`;
    return;
  }

  try {
    setStatus("Fetching metadata…", "progress");
    state.openApi = await fetchOpenApi();
    state.tables = parseTablesFromOpenApi(state.openApi);
    await hydrateForTable();
  } catch (error) {
    console.error(error);
    setStatus(error.message, "error");
  }
}

init();

async function refreshSelectedTable() {
  try {
    const tableStored = await storageGet(storageKeys.selectedTable);
    const nextTable = tableStored?.[storageKeys.selectedTable];
    if (!nextTable) {
      setStatus("Select a table in the side panel.", "error");
      return;
    }
    state.currentTable = nextTable;
    await hydrateForTable();
  } catch (error) {
    console.error("Refresh failed", error);
    setStatus(error.message, "error");
  }
}
