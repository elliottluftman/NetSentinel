const state = {
  startTime: Date.now(),
  trafficTimeline: [],
  protocolChart: null,
  trafficChart: null,
  topSourcesChart: null,
  apiKey: localStorage.getItem("netsentinel_api_key") || "",
  authPrompted: false,
};

function formatTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", { hour12: false });
}

function formatBytes(bytes) {
  const num = Number(bytes || 0);
  if (num < 1024) return `${num} B`;
  if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
  return `${(num / (1024 * 1024)).toFixed(2)} MB`;
}

function formatUptime() {
  const total = Math.floor((Date.now() - state.startTime) / 1000);
  const hrs = String(Math.floor(total / 3600)).padStart(2, "0");
  const mins = String(Math.floor((total % 3600) / 60)).padStart(2, "0");
  const secs = String(total % 60).padStart(2, "0");
  return `${hrs}:${mins}:${secs}`;
}

function severityClass(severity) {
  return `severity-${String(severity || "low").toLowerCase()}`;
}

function protocolClass(protocol) {
  const p = String(protocol || "other").toLowerCase();
  if (["tcp", "udp", "dns", "icmp", "http", "https", "ssh"].includes(p)) {
    return `proto-${p}`;
  }
  return "proto-other";
}

function buildCharts() {
  const commonPlugins = {
    legend: {
      labels: { color: "#d7deef", font: { family: "JetBrains Mono" } },
    },
  };

  state.protocolChart = new Chart(document.getElementById("protocolChart"), {
    type: "doughnut",
    data: {
      labels: ["TCP", "UDP", "DNS", "ICMP", "HTTP", "HTTPS", "SSH", "Other"],
      datasets: [{
        data: [0, 0, 0, 0, 0, 0, 0, 0],
        backgroundColor: ["#00e5ff", "#2ddf78", "#ffd166", "#ff9f40", "#50b2ff", "#22d3ee", "#8b9bff", "#6b748f"],
        borderColor: "#12121a",
        borderWidth: 2,
      }],
    },
    options: { maintainAspectRatio: false, plugins: commonPlugins },
  });

  const trafficCtx = document.getElementById("trafficChart").getContext("2d");
  const gradient = trafficCtx.createLinearGradient(0, 0, 0, 260);
  gradient.addColorStop(0, "rgba(0, 229, 255, 0.45)");
  gradient.addColorStop(1, "rgba(0, 229, 255, 0)");

  state.trafficChart = new Chart(document.getElementById("trafficChart"), {
    type: "line",
    data: { labels: [], datasets: [{ label: "Packets/sec", data: [], borderColor: "#00e5ff", backgroundColor: gradient, fill: true, tension: 0.35, pointRadius: 0 }] },
    options: {
      maintainAspectRatio: false,
      plugins: commonPlugins,
      scales: {
        x: { ticks: { color: "#8f95aa", maxTicksLimit: 8 }, grid: { color: "rgba(255,255,255,0.04)" } },
        y: { ticks: { color: "#8f95aa" }, grid: { color: "rgba(255,255,255,0.04)" } },
      },
    },
  });

  state.topSourcesChart = new Chart(document.getElementById("topSourcesChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Packet Count", data: [], borderWidth: 1, borderColor: "#00e5ff", backgroundColor: "rgba(0, 229, 255, 0.45)" }] },
    options: {
      indexAxis: "y",
      maintainAspectRatio: false,
      plugins: commonPlugins,
      scales: {
        x: { ticks: { color: "#8f95aa" }, grid: { color: "rgba(255,255,255,0.04)" } },
        y: { ticks: { color: "#d7deef", font: { family: "JetBrains Mono", size: 11 } }, grid: { color: "rgba(255,255,255,0.04)" } },
      },
    },
  });
}

function renderTraffic(packets) {
  const body = document.getElementById("trafficBody");
  body.innerHTML = "";

  packets.slice(0, 50).forEach((packet) => {
    const tr = document.createElement("tr");
    tr.classList.add("new-row");
    const src = `${packet.src_ip || "-"}${packet.src_port ? `:${packet.src_port}` : ""}`;
    const dst = `${packet.dst_ip || "-"}${packet.dst_port ? `:${packet.dst_port}` : ""}`;

    tr.innerHTML = `
      <td>${formatTime(packet.timestamp)}</td>
      <td>${src}</td>
      <td>${dst}</td>
      <td class="protocol ${protocolClass(packet.protocol)}">${packet.protocol || "Other"}</td>
      <td>${formatBytes(packet.size)}</td>
    `;
    body.appendChild(tr);
  });
}

function renderAlerts(alerts) {
  const stack = document.getElementById("alertStack");
  stack.innerHTML = "";

  const now = Date.now();
  const recent = alerts.filter((a) => now - Date.parse(a.timestamp) <= 5 * 60 * 1000);
  if (!recent.length) {
    stack.innerHTML = '<div class="empty-state">No active alerts in the last 5 minutes.</div>';
    return;
  }

  recent.slice(0, 12).forEach((alert) => {
    const card = document.createElement("div");
    const isCritical = String(alert.severity).toUpperCase() === "CRITICAL";
    card.className = `alert-card ${isCritical ? "critical" : ""}`;

    card.innerHTML = `
      <div class="alert-head">
        <span class="badge ${severityClass(alert.severity)}">${alert.severity}</span>
        <span class="alert-type">${alert.alert_type}</span>
      </div>
      <div class="alert-desc">${alert.description}</div>
      <div class="alert-meta">
        <span>${alert.source_ip || "?"} -> ${alert.target_ip || "?"}</span>
        <span>${formatTime(alert.timestamp)}</span>
      </div>
    `;

    card.addEventListener("click", () => {
      const details = JSON.stringify(alert.details || {}, null, 2);
      card.querySelector(".alert-desc").textContent = `${alert.description} | details: ${details}`;
    });

    stack.appendChild(card);
  });
}

function renderStats(stats) {
  const header = document.getElementById("headerStats");
  header.textContent = `Packets: ${(stats.total_packets || 0).toLocaleString()} | Alerts: ${(stats.total_alerts || 0).toLocaleString()} | Uptime: ${formatUptime()}`;

  const protoMap = stats.protocol_distribution || {};
  const labels = ["TCP", "UDP", "DNS", "ICMP", "HTTP", "HTTPS", "SSH", "Other"];
  state.protocolChart.data.datasets[0].data = labels.map((label) => protoMap[label] || 0);
  state.protocolChart.update();

  const timestampLabel = new Date().toLocaleTimeString("en-US", { hour12: false });
  state.trafficTimeline.push({ t: timestampLabel, v: stats.packets_per_second || 0 });
  if (state.trafficTimeline.length > 30) {
    state.trafficTimeline.shift();
  }
  state.trafficChart.data.labels = state.trafficTimeline.map((x) => x.t);
  state.trafficChart.data.datasets[0].data = state.trafficTimeline.map((x) => x.v);
  state.trafficChart.update();

  const topSources = stats.top_source_ips || [];
  state.topSourcesChart.data.labels = topSources.map((x) => x.src_ip);
  state.topSourcesChart.data.datasets[0].data = topSources.map((x) => x.count);
  state.topSourcesChart.update();
}

async function fetchJSON(path) {
  const headers = {};
  if (state.apiKey) {
    headers["X-API-Key"] = state.apiKey;
  }
  const resp = await fetch(path, { headers });

  if (resp.status === 401 && !state.authPrompted) {
    state.authPrompted = true;
    const key = window.prompt("Dashboard API key required. Enter X-API-Key:", "");
    if (key) {
      state.apiKey = key;
      localStorage.setItem("netsentinel_api_key", key);
      return fetchJSON(path);
    }
  }

  if (!resp.ok) {
    throw new Error(`Request failed: ${path} (${resp.status})`);
  }
  return resp.json();
}

async function refresh() {
  try {
    const [traffic, alerts, stats] = await Promise.all([
      fetchJSON("/api/traffic?limit=100"),
      fetchJSON("/api/alerts?limit=50"),
      fetchJSON("/api/stats"),
    ]);

    renderTraffic(traffic);
    renderAlerts(alerts);
    renderStats(stats);
  } catch (err) {
    console.error("Failed dashboard refresh:", err);
  }
}

function init() {
  buildCharts();
  refresh();
  setInterval(refresh, 2000);
}

document.addEventListener("DOMContentLoaded", init);
