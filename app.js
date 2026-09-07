// NetWatch SOC — Static Interactive Dashboard App (GitHub Pages Deployment)

const SAMPLE_DATA = {
  kpis: {
    networkEvents: 860,
    activeAlerts: 128,
    highCritical: 15,
    c2Beacons: 98,
    uniqueDsts: 6,
    dnsQueries: 163
  },
  alerts: [
    {
      id: "97177280-8a9c-4c28-945a-a10232972a46",
      timestamp: "2026-09-07T15:52:12Z",
      source_ip: "192.168.1.100",
      destination_ip: "10.0.0.99",
      destination_port: 8443,
      alert_type: "BEACONING",
      severity: "CRITICAL",
      confidence: 0.85,
      risk_score: 100,
      reason: "Regular-interval connections (CV=0.0125) with 30 connections; Rare destination 10.0.0.99; Port 8443 not in common allowed ports",
      status: "NEW"
    },
    {
      id: "4fafa33d-6afe-4115-baf0-06d115fc752d",
      timestamp: "2026-09-07T15:45:00Z",
      source_ip: "192.168.1.12",
      destination_ip: "192.168.99.99",
      destination_port: 4444,
      alert_type: "RARE_DESTINATION",
      severity: "HIGH",
      confidence: 0.65,
      risk_score: 75,
      reason: "Rare destination 192.168.99.99; Port 4444 not in common allowlist",
      status: "INVESTIGATING"
    },
    {
      id: "dns-tunnel-001",
      timestamp: "2026-09-07T15:30:00Z",
      source_ip: "192.168.1.100",
      destination_ip: "10.0.0.1",
      destination_port: 53,
      alert_type: "DNS_ANOMALY",
      severity: "HIGH",
      confidence: 0.85,
      risk_score: 80,
      reason: "Long domain (>55 chars); 8 distinct subdomains under base domain exfiltration-tunnel.test.org",
      status: "NEW"
    }
  ]
};

let currentView = "overview";
let isAdminConsentGranted = false;
let isLiveSniffingActive = false;
let sniffIntervalTimer = null;
let livePacketCount = 0;

function switchView(viewName) {
  currentView = viewName;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-view="${viewName}"]`)?.classList.add('active');

  const titles = {
    overview: ["Security Operations Overview", "Real-time telemetry and active threat metrics"],
    realtime: ["Real-Time Live Packet Monitor & Issue Generator", "Live network packet sniffer, admin permission governance, and streaming issue emitter"],
    traffic: ["Network Traffic Telemetry", "Search, filter, and inspect raw network flow events"],
    alerts: ["Alert Management & Triage", "Active detection alerts requiring SOC analyst investigation"],
    c2: ["C2 Beaconing Analytics & Regularity Analyzer", "Statistical interval variance detection for beaconing command-and-control behavior"],
    dns: ["DNS Anomaly & Tunneling Analysis", "Deep inspection of domain query patterns, DGA indicators, and subdomain volume"],
    evidence: ["Evidence Locker & Artifact Browser", "Inspect raw PCAP captures, generated Zeek log batches, and exported JSON alerts"],
    rules: ["Behavioral Detection Rules Engine", "Configure thresholds, toggle rule states, and inspect detection statistics"],
    reports: ["Executive & Forensic Report Generator", "Generate, view, and export structured SOC intelligence reports in JSON and CSV"],
    settings: ["System Settings & Control Panel", "Inspect active configuration, re-seed sample datasets, or perform database maintenance"]
  };

  const [mainTitle, subTitle] = titles[viewName] || ["NetWatch SOC", "SOC Platform"];
  document.getElementById('view-title').innerText = mainTitle;
  document.getElementById('view-subtitle').innerText = subTitle;

  document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
  document.getElementById(`view-${viewName}`)?.classList.remove('hidden');

  if (viewName === 'overview') renderOverviewCharts();
  if (viewName === 'c2') renderC2Chart();
}

function grantConsent() {
  isAdminConsentGranted = true;
  document.getElementById('admin-perm-btn').innerText = "Admin Consent: GRANTED 🔓";
  document.getElementById('admin-perm-btn').classList.add('btn-primary');
  document.getElementById('perm-badge').className = "badge badge-safe";
  document.getElementById('perm-badge').innerText = "PERMISSION: GRANTED";
  
  document.getElementById('grant-btn').style.display = "none";
  document.getElementById('revoke-btn').style.display = "inline-block";
  document.getElementById('sniff-toggle-btn').disabled = false;
}

function revokeConsent() {
  isAdminConsentGranted = false;
  if (isLiveSniffingActive) toggleSniffing();

  document.getElementById('admin-perm-btn').innerText = "Admin Consent: REVOKED 🔒";
  document.getElementById('admin-perm-btn').classList.remove('btn-primary');
  document.getElementById('perm-badge').className = "badge badge-critical";
  document.getElementById('perm-badge').innerText = "PERMISSION: REVOKED";
  
  document.getElementById('grant-btn').style.display = "inline-block";
  document.getElementById('revoke-btn').style.display = "none";
  document.getElementById('sniff-toggle-btn').disabled = true;
}

function toggleAdminConsent() {
  if (isAdminConsentGranted) revokeConsent();
  else grantConsent();
}

function toggleSniffing() {
  if (!isAdminConsentGranted) return;

  const btn = document.getElementById('sniff-toggle-btn');
  if (isLiveSniffingActive) {
    isLiveSniffingActive = false;
    clearInterval(sniffIntervalTimer);
    btn.innerText = "Start Live Packet Sniffing ▶";
    btn.classList.remove('btn-primary');
    document.getElementById('status-text').innerText = "ONLINE";
  } else {
    isLiveSniffingActive = true;
    btn.innerText = "Stop Sniffing ⏹";
    btn.classList.add('btn-primary');
    document.getElementById('status-text').innerText = "SNIFFING LIVE";
    
    // Clear placeholder row
    document.getElementById('realtime-packets-tbody').innerHTML = "";
    
    sniffIntervalTimer = setInterval(generateLivePacketStream, 1500);
  }
}

function generateLivePacketStream() {
  if (!isLiveSniffingActive) return;

  livePacketCount++;
  SAMPLE_DATA.kpis.networkEvents++;
  document.getElementById('kpi-net-events').innerText = SAMPLE_DATA.kpis.networkEvents;

  const sources = ["192.168.1.100", "192.168.1.105", "192.168.1.12", "192.168.1.50"];
  const dests = ["10.0.0.99:8443", "10.0.0.1:80", "8.8.8.8:53", "192.168.99.99:4444"];
  const protos = ["TCP", "UDP"];

  const src = sources[Math.floor(Math.random() * sources.length)];
  const dst = dests[Math.floor(Math.random() * dests.length)];
  const proto = protos[Math.floor(Math.random() * protos.length)];
  const now = new Date().toISOString().substring(11, 19);

  const tbody = document.getElementById('realtime-packets-tbody');
  const rowHtml = `<tr><td>${now}</td><td>${src}</td><td>${dst}</td><td>${proto}</td></tr>`;
  tbody.insertAdjacentHTML('afterbegin', rowHtml);

  if (tbody.children.length > 15) tbody.removeChild(tbody.lastChild);

  // Trigger live alert raising every 5th packet
  if (livePacketCount % 5 === 0) {
    raiseLiveIssue(src, dst);
  }
}

function raiseLiveIssue(src, dst) {
  SAMPLE_DATA.kpis.activeAlerts++;
  document.getElementById('kpi-alerts').innerText = SAMPLE_DATA.kpis.activeAlerts;

  const atypes = ["BEACONING", "SUSPICIOUS_PORT", "DNS_ANOMALY"];
  const sevs = ["CRITICAL", "HIGH", "MEDIUM"];
  const atype = atypes[Math.floor(Math.random() * atypes.length)];
  const sev = sevs[Math.floor(Math.random() * sevs.length)];
  const now = new Date().toISOString().substring(11, 19);

  const tbody = document.getElementById('realtime-alerts-tbody');
  const rowHtml = `<tr>
    <td>${now}</td>
    <td>${atype}</td>
    <td>${src} ➔ ${dst}</td>
    <td><span class="badge badge-${sev.toLowerCase()}">${sev}</span></td>
  </tr>`;
  tbody.insertAdjacentHTML('afterbegin', rowHtml);
  if (tbody.children.length > 10) tbody.removeChild(tbody.lastChild);
}

function renderOverviewCharts() {
  const ctxTimeline = document.getElementById('chart-timeline')?.getContext('2d');
  if (ctxTimeline && !window.timelineChart) {
    window.timelineChart = new Chart(ctxTimeline, {
      type: 'line',
      data: {
        labels: ['15:00', '15:10', '15:20', '15:30', '15:40', '15:50'],
        datasets: [{
          label: 'Event Volume (5m buckets)',
          data: [120, 150, 180, 210, 190, 220],
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          fill: true,
          tension: 0.3
        }]
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });
  }

  const ctxSevs = document.getElementById('chart-severity')?.getContext('2d');
  if (ctxSevs && !window.sevChart) {
    window.sevChart = new Chart(ctxSevs, {
      type: 'doughnut',
      data: {
        labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        datasets: [{
          data: [5, 10, 45, 68],
          backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6']
        }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }
}

function renderC2Chart() {
  const ctxPulse = document.getElementById('chart-c2-pulse')?.getContext('2d');
  if (ctxPulse && !window.pulseChart) {
    window.pulseChart = new Chart(ctxPulse, {
      type: 'bar',
      data: {
        labels: ['0s', '30s', '60s', '90s', '120s', '150s', '180s', '210s', '240s', '270s'],
        datasets: [{
          label: 'Beacon Interval (seconds)',
          data: [30.0, 30.1, 29.9, 30.0, 30.2, 29.8, 30.1, 30.0, 29.9, 30.0],
          backgroundColor: '#f97316'
        }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }
}

function openAlertDrawer(alertId) {
  const alertObj = SAMPLE_DATA.alerts.find(a => a.id === alertId) || SAMPLE_DATA.alerts[0];
  document.getElementById('drawer-alert-id').innerText = alertObj.id;
  document.getElementById('drawer-type').innerText = alertObj.alert_type;
  document.getElementById('drawer-sev').innerHTML = `<span class="badge badge-${alertObj.severity.toLowerCase()}">${alertObj.severity}</span>`;
  document.getElementById('drawer-score').innerText = `${alertObj.risk_score} / 100`;
  document.getElementById('drawer-source').innerText = `${alertObj.source_ip} ➔ ${alertObj.destination_ip}:${alertObj.destination_port}`;
  document.getElementById('drawer-reason').innerText = alertObj.reason;

  document.getElementById('drawer-overlay').classList.add('active');
}

function closeAlertDrawer() {
  document.getElementById('drawer-overlay').classList.remove('active');
}

function exportReport(format) {
  const content = JSON.stringify(SAMPLE_DATA.alerts, null, 2);
  const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `netwatch_report_${Date.now()}.${format}`;
  a.click();
}

window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => switchView(item.dataset.view));
  });

  document.getElementById('close-drawer')?.addEventListener('click', closeAlertDrawer);

  switchView('overview');
});
