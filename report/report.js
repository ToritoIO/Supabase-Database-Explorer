const REPORT_STORAGE_KEY = "sbde_security_reports";
const CLOUD_LINK_STORAGE_KEY = "sbde_cloud_link_state";
const CLOUD_STATUS_LINKED = "linked";

const dom = {
  root: document.getElementById("report-root"),
  meta: document.getElementById("report-meta"),
  version: document.getElementById("report-version"),
  downloadBtn: document.getElementById("download-pdf"),
};

function storageGet(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get(key, resolve);
  });
}

function setDownloadVisibility(isVisible) {
  if (!dom.downloadBtn) return;
  dom.downloadBtn.style.display = isVisible ? "inline-flex" : "none";
}

async function syncDownloadVisibility() {
  if (!dom.downloadBtn || !chrome?.storage?.local?.get) {
    setDownloadVisibility(false);
    return;
  }
  try {
    const stored = await storageGet([CLOUD_LINK_STORAGE_KEY]);
    const link = stored?.[CLOUD_LINK_STORAGE_KEY];
    setDownloadVisibility(link?.status === CLOUD_STATUS_LINKED);
  } catch (error) {
    setDownloadVisibility(false);
  }
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString();
}

function formatCount(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toLocaleString();
  }
  return "—";
}

function createRiskBadge(level) {
  const badge = document.createElement("span");
  badge.className = "risk-badge";
  badge.dataset.level = level || "unknown";
  const label = {
    critical: "Critical risk",
    high: "High risk",
    medium: "Medium risk",
    low: "Low risk",
  }[level || ""] || "Unknown risk";
  badge.textContent = label;
  return badge;
}

function createRiskChip(level) {
  const chip = document.createElement("span");
  chip.className = "risk-chip";
  chip.dataset.level = level || "unknown";
  chip.textContent = (level || "unknown").toUpperCase();
  return chip;
}

function describePolicyState(finding) {
  if (finding.policyState === "likely-unprotected") return "Likely unprotected";
  if (finding.policyState === "protected") return "Protected";
  return "Unknown";
}

function renderMeta(report) {
  dom.meta.innerHTML = "";
  const items = [
    {
      label: "Supabase Project ID",
      value: report.projectId || "Unknown",
    },
    {
      label: "Schema",
      value: report.schema || "public",
    },
    {
      label: "Generated",
      value: formatDate(report.createdAt),
    },
  ];

  const domainValue = typeof report.domain === "string" ? report.domain.trim() : "";
  const inspectedHost = typeof report.inspectedHost === "string" ? report.inspectedHost.trim() : "";
  const domainLabel = domainValue || inspectedHost;
  if (domainLabel) {
    items.splice(1, 0, {
      label: "Domain",
      value: domainLabel,
    });
  }

  if (
    report.connectionSummary?.usesDistinctBearer &&
    report.connectionSummary?.bearerRole &&
    report.connectionSummary?.bearerRole !== report.connectionSummary?.apiKeyRole
  ) {
    items.push({ label: "Bearer role", value: report.connectionSummary.bearerRole });
  }

  items.forEach((item) => {
    const span = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = `${item.label}: `;
    span.appendChild(strong);
    span.append(item.value);
    dom.meta.appendChild(span);
  });

  if (dom.version) {
    dom.version.textContent = "";
  }
}

function createSummarySection(report) {
  const section = document.createElement("section");
  section.className = "report-section";

  const header = document.createElement("div");
  header.style.display = "flex";
  header.style.alignItems = "center";
  header.style.gap = "12px";
  header.style.justifyContent = "space-between";

  const title = document.createElement("h2");
  title.textContent = "Overview";

  const badge = createRiskBadge(report.summary?.riskLevel);
  header.appendChild(title);
  header.appendChild(badge);

  section.appendChild(header);

  const findings = Array.isArray(report.summary?.keyFindings) ? report.summary.keyFindings : [];
  if (findings.length) {
    const list = document.createElement("ul");
    list.className = "key-findings";
    findings.forEach((finding) => {
      const li = document.createElement("li");
      li.textContent = finding;
      list.appendChild(li);
    });
    section.appendChild(list);
  }

  const summaryGrid = document.createElement("div");
  summaryGrid.className = "summary-grid";
  const stats = [
    { label: "Tables analyzed", value: formatCount(report.summary?.tableCount) },
    { label: "Accessible tables", value: formatCount(report.summary?.accessibleCount) },
    { label: "Protected tables", value: formatCount(report.summary?.protectedCount) },
    { label: "Unknown state", value: formatCount(report.summary?.unknownCount) },
  ];

  if (Array.isArray(report.assetDetections) && report.assetDetections.length) {
    stats.push({ label: "Static asset exposures", value: formatCount(report.assetDetections.length) });
  }
  if (Array.isArray(report.leakDetections) && report.leakDetections.length) {
    stats.push({ label: "API leaks detected", value: formatCount(report.leakDetections.length) });
  }

  stats.forEach((stat) => {
    const card = document.createElement("div");
    card.className = "summary-card";
    const value = document.createElement("strong");
    value.textContent = stat.value;
    const label = document.createElement("span");
    label.textContent = stat.label;
    card.appendChild(value);
    card.appendChild(label);
    summaryGrid.appendChild(card);
  });

  section.appendChild(summaryGrid);
  return section;
}

function createFindingRow(finding) {
  const tr = document.createElement("tr");

  const nameCell = document.createElement("td");
  const nameWrap = document.createElement("div");
  nameWrap.className = "finding-name";

  const nameTitle = document.createElement("div");
  nameTitle.className = "finding-name__title";
  nameTitle.textContent = finding.name || "-";
  nameWrap.appendChild(nameTitle);

  const riskChip = createRiskChip(finding.riskLevel || "unknown");
  nameWrap.appendChild(riskChip);

  nameCell.appendChild(nameWrap);

  const accessCell = document.createElement("td");
  const status = document.createElement("div");
  status.className = "finding-status";
  status.dataset.state = finding.policyState || "unknown";
  status.dataset.risk = finding.riskLevel || "unknown";

  const label = document.createElement("div");
  label.className = "finding-status__label";
  label.textContent = describePolicyState(finding);
  status.appendChild(label);

  accessCell.appendChild(status);

  const rowsCell = document.createElement("td");
  rowsCell.textContent = formatCount(finding.rowCount);

  const detailCell = document.createElement("td");
  const messages = [];
  if (Array.isArray(finding.warnings) && finding.warnings.length) {
    messages.push(...finding.warnings);
  }
  if (Array.isArray(finding.notes) && finding.notes.length) {
    messages.push(...finding.notes);
  }
  if (messages.length) {
    const list = document.createElement("ul");
    list.className = "finding-list";
    messages.forEach((message) => {
      const li = document.createElement("li");
      li.textContent = message;
      list.appendChild(li);
    });
    detailCell.appendChild(list);
  } else {
    detailCell.textContent = "No additional details.";
  }

  tr.appendChild(nameCell);
  tr.appendChild(accessCell);
  tr.appendChild(rowsCell);
  tr.appendChild(detailCell);
  return tr;
}

function createFindingsSection(report) {
  const section = document.createElement("section");
  section.className = "report-section";

  const title = document.createElement("h2");
  title.textContent = "Table Findings";
  section.appendChild(title);

  if (!Array.isArray(report.findings) || !report.findings.length) {
    const empty = document.createElement("p");
    empty.textContent = "No tables were analyzed for this report.";
    section.appendChild(empty);
    return section;
  }

  const table = document.createElement("table");
  table.className = "findings-table table-findings";

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  ["Table", "Access", "Rows", "Highlights"].forEach((label) => {
    const th = document.createElement("th");
    th.textContent = label;
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  report.findings.forEach((finding) => {
    tbody.appendChild(createFindingRow(finding));
  });
  table.appendChild(tbody);

  section.appendChild(table);
  return section;
}

function createAssetDetectionsSection(report) {
  const detections = Array.isArray(report.assetDetections) ? report.assetDetections : [];
  if (!detections.length) {
    return null;
  }

  const section = document.createElement("section");
  section.className = "report-section";

  const title = document.createElement("h2");
  title.textContent = "Static Asset Exposures";
  section.appendChild(title);

  const table = document.createElement("table");
  table.className = "findings-table asset-table";

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  ["Supabase URL", "Asset URL", "Key snippet"].forEach((label) => {
    const th = document.createElement("th");
    th.textContent = label;
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  detections.forEach((detection) => {
    const tr = document.createElement("tr");

    const supabaseCell = document.createElement("td");
    supabaseCell.textContent = detection.supabaseUrl || "—";
    tr.appendChild(supabaseCell);

    const assetCell = document.createElement("td");
    assetCell.textContent = detection.assetUrl || "—";
    tr.appendChild(assetCell);

    const snippetCell = document.createElement("td");
    snippetCell.textContent = detection.apiKeySnippet || "—";
    tr.appendChild(snippetCell);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  section.appendChild(table);
  return section;
}

function createLeakDetectionsSection(report) {
  const leaks = Array.isArray(report.leakDetections) ? report.leakDetections : [];
  if (!leaks.length) {
    return null;
  }

  const section = document.createElement("section");
  section.className = "report-section";

  const title = document.createElement("h2");
  title.textContent = "API Credential Leaks";
  section.appendChild(title);

  const table = document.createElement("table");
  table.className = "findings-table leak-table";

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  ["Pattern", "Snippet", "Source"].forEach((label) => {
    const th = document.createElement("th");
    th.textContent = label;
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  leaks.forEach((leak) => {
    const tr = document.createElement("tr");

    const patternCell = document.createElement("td");
    patternCell.textContent = leak.pattern || "—";
    tr.appendChild(patternCell);

    const snippetCell = document.createElement("td");
    const snippetValue = leak.matchSnippet || "";
    snippetCell.textContent = snippetValue
      ? (snippetValue.length > 80 ? `${snippetValue.slice(0, 80)}…` : snippetValue)
      : "—";
    tr.appendChild(snippetCell);

    const sourceCell = document.createElement("td");
    sourceCell.textContent = leak.sourceUrl || leak.assetUrl || "—";
    tr.appendChild(sourceCell);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  section.appendChild(table);
  return section;
}

function createRecommendationsSection(report) {
  const section = document.createElement("section");
  section.className = "report-section";

  const title = document.createElement("h2");
  title.textContent = "Recommendations";
  section.appendChild(title);

  if (!Array.isArray(report.recommendations) || !report.recommendations.length) {
    const empty = document.createElement("p");
    empty.textContent = "No recommendations available for this report.";
    section.appendChild(empty);
    return section;
  }

  const list = document.createElement("ul");
  list.className = "recommendations-list";
  report.recommendations.forEach((rec) => {
    const item = document.createElement("li");
    item.className = "recommendation-card";

    const severity = document.createElement("span");
    severity.className = "recommendation-severity";
    severity.dataset.severity = rec.severity || "medium";
    severity.textContent = `${(rec.severity || "medium").toUpperCase()} priority`;

    const heading = document.createElement("h3");
    heading.textContent = rec.title || "Recommendation";

    const detail = document.createElement("p");
    detail.textContent = rec.detail || "";

    item.appendChild(severity);
    item.appendChild(heading);
    item.appendChild(detail);
    list.appendChild(item);
  });

  section.appendChild(list);
  return section;
}

function renderReport(report) {
  dom.root.innerHTML = "";
  renderMeta(report);
  dom.root.appendChild(createSummarySection(report));
  const assetsSection = createAssetDetectionsSection(report);
  if (assetsSection) {
    dom.root.appendChild(assetsSection);
  }
  const leaksSection = createLeakDetectionsSection(report);
  if (leaksSection) {
    dom.root.appendChild(leaksSection);
  }
  dom.root.appendChild(createFindingsSection(report));
  dom.root.appendChild(createRecommendationsSection(report));
}

function renderError(message) {
  dom.root.innerHTML = "";
  const errorCard = document.createElement("section");
  errorCard.className = "report-section";
  const title = document.createElement("h2");
  title.textContent = "Report unavailable";
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  errorCard.appendChild(title);
  errorCard.appendChild(paragraph);
  dom.root.appendChild(errorCard);
}

async function loadReport() {
  const params = new URLSearchParams(window.location.search);
  const id = params.get("id");
  if (!id) {
    renderError("Missing report id.");
    return;
  }

  try {
    const stored = await storageGet([REPORT_STORAGE_KEY]);
    const reports = stored?.[REPORT_STORAGE_KEY];
    if (!reports || typeof reports !== "object" || !reports[id]) {
      renderError("Report not found or has expired. Generate a new report from the side panel.");
      return;
    }
    renderReport(reports[id]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error || "Failed to load report.");
    renderError(message);
  }
}

loadReport();

// Only paid (cloud-linked) users can access PDF download.
setDownloadVisibility(false);
syncDownloadVisibility();

if (chrome?.storage?.onChanged?.addListener) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local" || !changes[CLOUD_LINK_STORAGE_KEY]) {
      return;
    }
    const nextLink = changes[CLOUD_LINK_STORAGE_KEY]?.newValue || null;
    setDownloadVisibility(nextLink?.status === CLOUD_STATUS_LINKED);
  });
}

if (dom.downloadBtn) {
  dom.downloadBtn.addEventListener("click", () => {
    window.print();
  });
}
