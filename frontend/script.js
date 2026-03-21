const app = document.getElementById("app");
const apiBase = `${window.location.origin}/api/v1`;
document.getElementById("apiBaseTag").textContent = apiBase;

const state = {
  currentPage: "dashboard",
  latestScanId: null,
  latestScan: null,
  latestAttackId: null,
  riskHistory: [],
};

const toastStack = document.getElementById("toastStack");

function showToast(message, tone = "info") {
  const styles = {
    info: "border-blue-400/30 bg-blue-500/10 text-blue-100",
    success: "border-emerald-400/30 bg-emerald-500/10 text-emerald-100",
    warning: "border-amber-400/30 bg-amber-500/10 text-amber-100",
    danger: "border-rose-400/30 bg-rose-500/10 text-rose-100",
  };
  const toast = document.createElement("div");
  toast.className = `glass border rounded-xl px-4 py-3 shadow-glass transition-all duration-300 ease-in-out opacity-0 translate-x-5 ${styles[tone]}`;
  toast.textContent = message;
  toastStack.appendChild(toast);
  requestAnimationFrame(() => toast.classList.remove("opacity-0", "translate-x-5"));
  setTimeout(() => {
    toast.classList.add("opacity-0", "translate-x-5");
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

function createRipple(event) {
  const button = event.currentTarget;
  const rect = button.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  const ripple = document.createElement("span");
  ripple.className = "ripple";
  ripple.style.width = `${size}px`;
  ripple.style.height = `${size}px`;
  ripple.style.left = `${event.clientX - rect.left - size / 2}px`;
  ripple.style.top = `${event.clientY - rect.top - size / 2}px`;
  button.appendChild(ripple);
  setTimeout(() => ripple.remove(), 620);
}

function toggleSkeleton(elId, visible) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.classList.toggle("hidden", !visible);
}

async function apiFetch(path, options = {}) {
  const response = await fetch(`${apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API ${response.status}: ${text || response.statusText}`);
  }
  return response.json();
}

function severityClass(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "bg-rose-600/20 text-rose-300";
  if (s === "high") return "bg-orange-500/20 text-orange-300";
  if (s === "medium") return "bg-amber-500/20 text-amber-300";
  return "bg-blue-500/20 text-blue-300";
}

function getOverallRisk(score) {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function setPage(page) {
  document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
  const selected = document.getElementById(`page-${page}`);
  if (selected) selected.classList.add("active");
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    if (btn.dataset.page === page) {
      btn.classList.add("bg-gradient-to-r", "from-blue-500/20", "to-purple-500/20", "border-blue-400/30", "shadow-glow");
    } else {
      btn.classList.remove("bg-gradient-to-r", "from-blue-500/20", "to-purple-500/20", "border-blue-400/30", "shadow-glow");
    }
  });
  state.currentPage = page;
  runRevealAnimation();
}

function drawBarChart(canvasId, values, labels, colors) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 400;
  const height = canvas.clientHeight || 180;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);
  const max = Math.max(...values, 1);
  const barGap = 14;
  const barWidth = Math.max(28, (width - barGap * (values.length + 1)) / values.length);
  values.forEach((val, i) => {
    const barHeight = (val / max) * (height - 45);
    const x = barGap + i * (barWidth + barGap);
    const y = height - barHeight - 24;
    ctx.fillStyle = colors[i] || "#60A5FA";
    ctx.fillRect(x, y, barWidth, barHeight);
    ctx.fillStyle = "#9AA4BF";
    ctx.font = "12px Inter";
    ctx.fillText(labels[i], x, height - 8);
    ctx.fillStyle = "#E2E8F0";
    ctx.fillText(String(val), x, y - 6);
  });
}

function drawLineChart(canvasId, values) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 400;
  const height = canvas.clientHeight || 180;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);
  const max = Math.max(...values, 100);
  const min = Math.min(...values, 0);
  const pad = 20;
  const stepX = (width - pad * 2) / Math.max(values.length - 1, 1);
  ctx.strokeStyle = "rgba(148,163,184,.25)";
  ctx.beginPath();
  ctx.moveTo(pad, height - pad);
  ctx.lineTo(width - pad, height - pad);
  ctx.stroke();
  const gradient = ctx.createLinearGradient(0, 0, width, 0);
  gradient.addColorStop(0, "#3B82F6");
  gradient.addColorStop(1, "#8B5CF6");
  ctx.strokeStyle = gradient;
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  values.forEach((v, i) => {
    const x = pad + i * stepX;
    const y = height - pad - ((v - min) / Math.max(max - min, 1)) * (height - pad * 2);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function updateCharts(scan) {
  const vulnerabilities = scan?.vulnerabilities || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  vulnerabilities.forEach((v) => {
    const k = String(v.severity || "low").toLowerCase();
    counts[k] = (counts[k] || 0) + 1;
  });
  drawBarChart(
    "vulnChart",
    [counts.critical, counts.high, counts.medium, counts.low],
    ["Critical", "High", "Medium", "Low"],
    ["#F43F5E", "#FB923C", "#FBBF24", "#60A5FA"]
  );
  if (typeof scan?.risk_score === "number") {
    state.riskHistory.push(scan.risk_score);
    if (state.riskHistory.length > 8) state.riskHistory.shift();
  }
  const trend = state.riskHistory.length ? state.riskHistory : [0, 0, 0, 0];
  drawLineChart("riskTrendChart", trend);
}

function renderDashboard(scan) {
  const scoreEl = document.getElementById("overallRiskScore");
  const riskEl = document.getElementById("overallRiskLabel");
  const body = document.getElementById("recentScansBody");
  body.innerHTML = "";

  if (!scan) {
    scoreEl.textContent = "--";
    riskEl.textContent = "No scan selected";
    return;
  }

  const vulnerabilities = scan.vulnerabilities || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  vulnerabilities.forEach((v) => {
    const key = String(v.severity || "low").toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  });
  document.getElementById("sevCritical").textContent = counts.critical || 0;
  document.getElementById("sevHigh").textContent = counts.high || 0;
  document.getElementById("sevMedium").textContent = counts.medium || 0;
  updateCharts(scan);

  scoreEl.textContent = Number(scan.risk_score || 0).toFixed(1);
  riskEl.textContent = `${getOverallRisk(scan.risk_score)} risk`;

  const row = document.createElement("tr");
  row.className = "hover:bg-white/5 transition-all duration-300";
  row.innerHTML = `
    <td class="py-3">${state.latestScanId}</td>
    <td>${scan.url || "unknown"}</td>
    <td><span class="px-2 py-1 rounded-md ${severityClass(getOverallRisk(scan.risk_score))}">${getOverallRisk(scan.risk_score)}</span></td>
    <td><button class="text-blue-300 hover:text-blue-200 transition-all duration-300" id="openResultBtn">Open</button></td>
  `;
  body.appendChild(row);
  document.getElementById("openResultBtn").addEventListener("click", () => setPage("results"));
}

function renderResults(scan) {
  document.getElementById("resultsScanId").textContent = state.latestScanId || "--";
  const tbody = document.getElementById("vulnTableBody");
  tbody.innerHTML = "";
  const vulnerabilities = scan?.vulnerabilities || [];
  if (!vulnerabilities.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="py-4 text-textdim">No vulnerabilities found.</td></tr>`;
    return;
  }
  const frag = document.createDocumentFragment();
  vulnerabilities.forEach((v, idx) => {
    const row = document.createElement("tr");
    row.className = "hover:bg-white/5 transition-all duration-300";
    row.innerHTML = `
      <td class="py-3">${v.title || "Unknown"}</td>
      <td><span class="px-2 py-1 rounded-md ${severityClass(v.severity)}">${v.severity || "low"}</span></td>
      <td>${(v.cvss_score || 0) >= 7 ? "Open" : "Review"}</td>
      <td><button data-expand="${idx}" class="expand-btn text-blue-300 hover:text-blue-200">Expand</button></td>
    `;
    frag.appendChild(row);
    const detail = document.createElement("tr");
    detail.className = "hidden detail-row";
    detail.innerHTML = `
      <td colspan="4" class="pb-4">
        <div class="rounded-xl bg-slate-900/40 border border-white/10 p-4">
          <p class="text-sm mb-2">${v.description || "No description available."}</p>
          <p class="text-xs text-textdim mb-2"><strong>Fix steps:</strong> ${v.remediation || "Patch and enforce secure defaults."}</p>
          <pre class="text-xs bg-black/30 rounded-lg p-3 overflow-x-auto border border-white/10"># Code fix
# Apply secure header in Django middleware
response["X-Content-Type-Options"] = "nosniff"</pre>
        </div>
      </td>
    `;
    frag.appendChild(detail);
  });
  tbody.appendChild(frag);
  document.querySelectorAll(".expand-btn").forEach((btn, i) => {
    btn.addEventListener("click", () => {
      const row = document.querySelectorAll(".detail-row")[i];
      row.classList.toggle("hidden");
    });
  });
}

function renderVisualAnalysis(scan) {
  const visualWrap = document.getElementById("visualWrap");
  const imagePath = scan?.image_path || scan?.raw_output?.image_path;
  const detections = scan?.detections || scan?.raw_output?.detections || [];
  if (!imagePath) {
    visualWrap.innerHTML = `<p class="text-textdim text-sm">No visual analysis image provided by backend.</p>`;
    return;
  }
  let overlays = "";
  detections.forEach((det) => {
    const [x, y, w, h] = det.bbox || [10, 10, 80, 40];
    overlays += `<div class="absolute border-2 border-rose-400/80 rounded-md" style="left:${x}px;top:${y}px;width:${w}px;height:${h}px;">
      <span class="absolute -top-6 left-0 text-[10px] px-1.5 py-0.5 rounded bg-rose-500/80">${det.type || "detection"}</span>
    </div>`;
  });
  visualWrap.innerHTML = `
    <div class="relative w-full">
      <img src="${imagePath}" alt="Visual analysis" class="w-full max-h-[540px] object-contain"/>
      ${overlays}
    </div>
  `;
}

function renderAiReport(report) {
  const container = document.getElementById("aiCards");
  container.innerHTML = "";
  if (!report || !Array.isArray(report.issues)) {
    container.innerHTML = `<article class="glass rounded-2xl p-5 border border-white/10"><p class="text-textdim text-sm">No AI report yet. Run a scan first.</p></article>`;
    return;
  }
  report.issues.forEach((item) => {
    const card = document.createElement("article");
    card.className = "glass rounded-2xl p-5 border border-white/10 hover:-translate-y-1 transition-all duration-300";
    card.innerHTML = `
      <div class="flex items-center justify-between mb-2">
        <h4 class="font-semibold">${item.title || "Issue"}</h4>
        <span class="px-2 py-1 rounded-md text-xs ${severityClass(item.severity)}">${item.severity || "Low"}</span>
      </div>
      <p class="text-sm text-slate-200 mb-2">${item.description || ""}</p>
      <p class="text-xs text-textdim mb-3">${item.reasoning || ""}</p>
      <ul class="text-sm list-disc list-inside mb-3">${(item.fix_steps || []).map((s) => `<li>${s}</li>`).join("")}</ul>
      <pre class="code-block text-xs rounded-lg p-3 overflow-x-auto"><span class="cm"># ${item.code_fix?.language || "code"}</span>
<span class="kw">${(item.code_fix?.example || "").replace(/</g, "&lt;")}</span></pre>
    `;
    container.appendChild(card);
  });
}

function renderAttackTimeline(attack) {
  const timeline = document.getElementById("attackTimeline");
  timeline.innerHTML = "";
  const logs = attack?.logs || [];
  if (!logs.length) {
    timeline.innerHTML = `<p class="text-sm text-textdim">No attack logs available.</p>`;
    return;
  }
  logs.forEach((log) => {
    const ok = log.status === "success" || log.validated;
    const item = document.createElement("div");
    item.className = "timeline-item relative pl-10";
    item.innerHTML = `
      <div class="absolute left-0 top-1 h-5 w-5 rounded-full grid place-items-center text-xs ${ok ? "bg-emerald-500/20 text-emerald-300" : "bg-rose-500/20 text-rose-300"}">
        ${ok ? "✓" : "!"}
      </div>
      <div class="glass rounded-xl p-3 border border-white/10">
        <p class="text-sm font-medium">${log.attack_type || "attack_step"}</p>
        <p class="text-xs text-textdim mt-1">status: ${log.status} | response: ${log.response_status ?? "-"}</p>
      </div>
    `;
    timeline.appendChild(item);
  });
}

async function pollScan(scanId) {
  const progress = document.getElementById("scanProgress");
  const progressText = document.getElementById("scanProgressText");
  progress.classList.remove("hidden");
  toggleSkeleton("dashboardSkeleton", true);
  toggleSkeleton("resultsSkeleton", true);
  for (let i = 0; i < 30; i += 1) {
    progressText.textContent = `Polling scan #${scanId}...`;
    const data = await apiFetch(`/scanner/scan/${scanId}/`, { method: "GET" });
    if (data) {
      state.latestScanId = scanId;
      state.latestScan = data;
      renderDashboard(data);
      renderResults(data);
      renderVisualAnalysis(data);
      toggleSkeleton("dashboardSkeleton", false);
      toggleSkeleton("resultsSkeleton", false);
      progress.classList.add("hidden");
      showToast(`Scan #${scanId} completed.`, "success");
      return data;
    }
    await new Promise((res) => setTimeout(res, 2000));
  }
  progress.classList.add("hidden");
  toggleSkeleton("dashboardSkeleton", false);
  toggleSkeleton("resultsSkeleton", false);
  throw new Error("Scan polling timeout");
}

async function startScanFlow(url) {
  const payload = { url };
  const created = await apiFetch("/scanner/scan/", { method: "POST", body: JSON.stringify(payload) });
  const scanId = created.scan_id;
  if (!scanId) throw new Error("Scan ID not returned");
  return pollScan(scanId);
}

async function fetchAiReport() {
  if (!state.latestScanId) return null;
  return apiFetch(`/ai/report/?scan_id=${state.latestScanId}`, { method: "GET" });
}

async function runAttack() {
  if (!state.latestScanId) throw new Error("Run a scan first");
  const created = await apiFetch("/attack/run/", {
    method: "POST",
    body: JSON.stringify({ scan_id: state.latestScanId }),
  });
  const attackId = created.attack_id;
  state.latestAttackId = attackId;
  const detail = await apiFetch(`/attack/${attackId}/`, { method: "GET" });
  renderAttackTimeline(detail);
  return detail;
}

document.getElementById("sidebarToggle").addEventListener("click", () => app.classList.toggle("sidebar-collapsed"));
document.querySelectorAll(".nav-btn").forEach((btn) => btn.addEventListener("click", () => setPage(btn.dataset.page)));
document.querySelectorAll(".interactive-btn").forEach((btn) => btn.addEventListener("click", createRipple));
document.getElementById("navMenu").addEventListener("keydown", (event) => {
  const items = [...document.querySelectorAll(".nav-btn")];
  const idx = items.indexOf(document.activeElement);
  if (idx < 0) return;
  if (event.key === "ArrowDown") {
    event.preventDefault();
    items[(idx + 1) % items.length].focus();
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    items[(idx - 1 + items.length) % items.length].focus();
  } else if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    document.activeElement.click();
  }
});

document.getElementById("scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = document.getElementById("scanUrlInput").value.trim();
  if (!url) return;
  const button = document.getElementById("startScanBtn");
  button.disabled = true;
  button.textContent = "Starting...";
  try {
    await startScanFlow(url);
    setPage("results");
    const report = await fetchAiReport();
    renderAiReport(report);
  } catch (error) {
    showToast(error.message, "danger");
  } finally {
    button.disabled = false;
    button.textContent = "Start Scan";
  }
});

document.getElementById("runAttackBtn").addEventListener("click", async () => {
  try {
    await runAttack();
    showToast("Attack simulation completed.", "success");
  } catch (error) {
    showToast(error.message, "danger");
  }
});

document.getElementById("searchInput").addEventListener("input", (e) => {
  const q = e.target.value.toLowerCase();
  document.querySelectorAll("#vulnTableBody tr").forEach((row) => {
    if (row.classList.contains("detail-row")) return;
    row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
  });
});

renderDashboard(null);
renderResults(null);
renderAiReport(null);
renderAttackTimeline(null);
updateCharts(null);

function runRevealAnimation() {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry, idx) => {
        if (!entry.isIntersecting) return;
        setTimeout(() => entry.target.classList.add("visible"), idx * 50);
        observer.unobserve(entry.target);
      });
    },
    { threshold: 0.18 }
  );
  document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));
}

runRevealAnimation();
