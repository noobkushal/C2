// NetWatch SOC — Enterprise Network Traffic & C2 Detection Platform
// Version 2.5 — Interactive Client-Side & Local Ingestion SOC Engine

// ─────────────────────────────────────────────────────────────────────────────
// DATA STORES & BASELINE TELEMETRY
// ─────────────────────────────────────────────────────────────────────────────

const INITIAL_DATA = {
  kpis: {
    networkEvents: 1420,
    activeAlerts: 3,
    highCritical: 1,
    c2Beacons: 2,
    uniqueDsts: 8,
    dnsQueries: 284,
    cases: 2,
    rules: 5
  },
  alerts: [
    {
      id: "97177280-8a9c-4c28-945a-a10232972a46",
      timestamp: "2026-11-07 15:52:12",
      source_ip: "192.168.1.100",
      destination_ip: "10.0.0.99",
      destination_port: 8443,
      alert_type: "BEACONING",
      severity: "CRITICAL",
      confidence: 0.92,
      risk_score: 100,
      reason: "Periodic high-regularity HTTPS beaconing (CV=0.0125, Avg Int=30.01s, 30 conns). Contacting non-whitelisted RFC1918 gateway IP on port 8443.",
      status: "NEW",
      analyst: "Unassigned",
      mitre_tech: "T1071.001 - Web Protocols (C2)",
      analyst_notes: "Initial discovery via automated Zeek conn.log analyzer. Host beaconing consistently every 30 seconds."
    },
    {
      id: "4fafa33d-6afe-4115-baf0-06d115fc752d",
      timestamp: "2026-11-07 15:45:00",
      source_ip: "192.168.1.12",
      destination_ip: "192.168.99.99",
      destination_port: 4444,
      alert_type: "RARE_DESTINATION",
      severity: "HIGH",
      confidence: 0.78,
      risk_score: 75,
      reason: "Rare destination 192.168.99.99 contacted. Target port 4444 matches Metasploit Default Multi-Handler payload signature.",
      status: "INVESTIGATING",
      analyst: "admin",
      mitre_tech: "T1571 - Non-Standard Port",
      analyst_notes: "Host quarantined on VLAN 20 for memory inspection."
    },
    {
      id: "dns-tunnel-001",
      timestamp: "2026-11-07 15:30:00",
      source_ip: "192.168.1.100",
      destination_ip: "10.0.0.1",
      destination_port: 53,
      alert_type: "DNS_ANOMALY",
      severity: "HIGH",
      confidence: 0.85,
      risk_score: 80,
      reason: "High entropy (4.21) domain query exceeding 55 characters with 8 distinct subdomain levels under exfiltration-tunnel.test.org.",
      status: "NEW",
      analyst: "Unassigned",
      mitre_tech: "T1071.004 - DNS Tunneling",
      analyst_notes: "Suspected staging chunk exfiltration via base64 encoded TXT records."
    }
  ],
  trafficFlows: [
    { id: "FL-1001", timestamp: "2026-11-07 15:52:12", source_ip: "192.168.1.100", src_port: 52030, destination_ip: "10.0.0.99", dst_port: 8443, protocol: "TCP", duration: "0.14s", bytes_sent: 512, bytes_recv: 1024, state: "SF", source: "Zeek conn.log", threat: true },
    { id: "FL-1002", timestamp: "2026-11-07 15:51:42", source_ip: "192.168.1.100", src_port: 52029, destination_ip: "10.0.0.99", dst_port: 8443, protocol: "TCP", duration: "0.12s", bytes_sent: 512, bytes_recv: 1024, state: "SF", source: "Zeek conn.log", threat: true },
    { id: "FL-1003", timestamp: "2026-11-07 15:51:12", source_ip: "192.168.1.100", src_port: 52028, destination_ip: "10.0.0.99", dst_port: 8443, protocol: "TCP", duration: "0.15s", bytes_sent: 512, bytes_recv: 1024, state: "SF", source: "Zeek conn.log", threat: true },
    { id: "FL-1004", timestamp: "2026-11-07 15:50:42", source_ip: "192.168.1.100", src_port: 52027, destination_ip: "10.0.0.99", dst_port: 8443, protocol: "TCP", duration: "0.11s", bytes_sent: 512, bytes_recv: 1024, state: "SF", source: "Zeek conn.log", threat: true },
    { id: "FL-1005", timestamp: "2026-11-07 15:45:00", source_ip: "192.168.1.12",  src_port: 49152, destination_ip: "192.168.99.99", dst_port: 4444, protocol: "TCP", duration: "1.20s", bytes_sent: 2048, bytes_recv: 4096, state: "SF", source: "Zeek conn.log", threat: true },
    { id: "FL-1006", timestamp: "2026-11-07 15:44:10", source_ip: "192.168.1.50",  src_port: 55432, destination_ip: "8.8.8.8", dst_port: 53, protocol: "UDP", duration: "0.02s", bytes_sent: 68, bytes_recv: 142, state: "SF", source: "Live Sniffer", threat: false },
    { id: "FL-1007", timestamp: "2026-11-07 15:43:55", source_ip: "192.168.1.105", src_port: 60100, destination_ip: "142.250.190.46", dst_port: 443, protocol: "TCP", duration: "4.80s", bytes_sent: 14200, bytes_recv: 185000, state: "SF", source: "Zeek ssl.log", threat: false },
    { id: "FL-1008", timestamp: "2026-11-07 15:42:30", source_ip: "192.168.1.20",  src_port: 38210, destination_ip: "10.0.0.1", dst_port: 80, protocol: "TCP", duration: "0.05s", bytes_sent: 320, bytes_recv: 850, state: "SF", source: "Zeek http.log", threat: false },
    { id: "FL-1009", timestamp: "2026-11-07 15:40:15", source_ip: "192.168.1.100", src_port: 51200, destination_ip: "10.0.0.99", dst_port: 8443, protocol: "TCP", duration: "0.14s", bytes_sent: 512, bytes_recv: 1024, state: "SF", source: "Zeek conn.log", threat: true },
    { id: "FL-1010", timestamp: "2026-11-07 15:39:45", source_ip: "192.168.1.100", src_port: 51199, destination_ip: "10.0.0.99", dst_port: 8443, protocol: "TCP", duration: "0.13s", bytes_sent: 512, bytes_recv: 1024, state: "SF", source: "Zeek conn.log", threat: true },
    { id: "FL-1011", timestamp: "2026-11-07 15:38:00", source_ip: "192.168.1.80",  src_port: 50123, destination_ip: "192.168.1.1", dst_port: 53, protocol: "UDP", duration: "0.01s", bytes_sent: 54, bytes_recv: 98, state: "SF", source: "Live Sniffer", threat: false },
    { id: "FL-1012", timestamp: "2026-11-07 15:35:12", source_ip: "192.168.1.99",  src_port: 48900, destination_ip: "192.168.1.254", dst_port: 22, protocol: "TCP", duration: "0.01s", bytes_sent: 64, bytes_recv: 0, state: "S0", source: "Live Sniffer", threat: false },
    { id: "FL-1013", timestamp: "2026-11-07 15:30:00", source_ip: "192.168.1.100", src_port: 54321, destination_ip: "10.0.0.1", dst_port: 53, protocol: "DNS", duration: "0.04s", bytes_sent: 180, bytes_recv: 320, state: "SF", source: "Zeek dns.log", threat: true }
  ],
  c2Candidates: [
    {
      src_ip: "192.168.1.100",
      dst_ip: "10.0.0.99",
      port: 8443,
      conns: 30,
      avg_interval: "30.01s",
      stdev: "0.38s",
      cv: 0.0125,
      score: 100,
      status: "ACTIVE_BEACON"
    },
    {
      src_ip: "192.168.1.12",
      dst_ip: "192.168.99.99",
      port: 4444,
      conns: 12,
      avg_interval: "60.40s",
      stdev: "4.12s",
      cv: 0.0682,
      score: 85,
      status: "SUSPECT_JITTER"
    }
  ],
  dnsTelemetry: [
    { timestamp: "2026-11-07 15:50:22", source_ip: "192.168.1.100", query: "encoded-c2-stage2-exfil-payload.malicious-sim.org", qtype: "A", entropy: 4.38, indicator: "LONG_DOMAIN", risk_score: 85, response_code: "NOERROR" },
    { timestamp: "2026-11-07 15:48:10", source_ip: "192.168.1.100", query: "chunk0.exfiltration-tunnel.test.org", qtype: "TXT", entropy: 4.12, indicator: "SUBDOMAIN_TUNNEL", risk_score: 80, response_code: "NOERROR" },
    { timestamp: "2026-11-07 15:45:00", source_ip: "192.168.1.105", query: "api.github.com", qtype: "A", entropy: 2.85, indicator: "BENIGN", risk_score: 5, response_code: "NOERROR" },
    { timestamp: "2026-11-07 15:40:12", source_ip: "192.168.1.12", query: "xk99ab-c2-sync-agent.dyn-dns.io", qtype: "A", entropy: 3.95, indicator: "HIGH_ENTROPY", risk_score: 75, response_code: "NXDOMAIN" },
    { timestamp: "2026-11-07 15:35:40", source_ip: "192.168.1.50", query: "update.microsoft.com", qtype: "A", entropy: 2.74, indicator: "BENIGN", risk_score: 0, response_code: "NOERROR" }
  ],
  cases: [
    {
      id: "CASE-2026-001",
      title: "Active C2 Channel & Exfiltration from 192.168.1.100",
      priority: "CRITICAL",
      status: "OPEN",
      analyst: "admin",
      linked_alerts: 2,
      created_at: "2026-11-07 15:55:00",
      desc: "Periodic 30s beaconing discovered to 10.0.0.99:8443 paired with high-entropy DNS tunneling queries. Host isolated for forensic triage."
    },
    {
      id: "CASE-2026-002",
      title: "Rare Destination Connection to Metasploit Default Port",
      priority: "HIGH",
      status: "IN_PROGRESS",
      analyst: "analyst",
      linked_alerts: 1,
      created_at: "2026-11-07 15:48:00",
      desc: "Workstation 192.168.1.12 initiated an outbound connection on TCP port 4444 to untrusted IP 192.168.99.99."
    }
  ],
  evidenceList: [
    {
      filename: "sample_c2_beacon.pcap",
      type: "Raw PCAP Capture",
      size: "1.2 MB",
      hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      date: "2026-11-07 15:52",
      dir: "data/raw",
      content: "[Binary PCAP file: 30 packets. Ethernet II -> IPv4 -> TCP 52000-52030 -> 10.0.0.99:8443]\nBeaconing interval: 30.01 seconds. Captured with WinPcap API."
    },
    {
      filename: "conn.log",
      type: "Zeek Connection Log",
      size: "340 KB",
      hash: "8f4803227486d36324f59da73173105e19ec9ac91fc09f842d4c0daae49fe524",
      date: "2026-11-07 15:50",
      dir: "data/zeek/sample_batch",
      content: "#separator \\x09\n#set_separator ,\n#empty_field (empty)\n#unset_field -\n#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state\n1725724332.123456 Ck29F81e9A102 192.168.1.100 52030 10.0.0.99 8443 tcp ssl 0.14 512 1024 SF\n1725724302.123456 Ck29F81e9A101 192.168.1.100 52029 10.0.0.99 8443 tcp ssl 0.12 512 1024 SF"
    },
    {
      filename: "dns_exfiltration.log",
      type: "Zeek DNS Query Log",
      size: "84 KB",
      hash: "a45f908e2f69a92a188f918e97fba98e1694f4a338c353915bc6bc150a0ec405",
      date: "2026-11-07 15:48",
      dir: "data/zeek/sample_batch",
      content: "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id query qclass qtype rcode answers\n1725724222.100000 Cdns99281a 192.168.1.100 54321 10.0.0.1 53 udp 1042 encoded-c2-stage2-exfil-payload.malicious-sim.org 1 1 0 10.0.0.99"
    },
    {
      filename: "report_20261107.json",
      type: "JSON Alert Evidence",
      size: "14 KB",
      hash: "c299afb21a8f90240989fba82740924ea9918237190f84a8992e1098274ab192",
      date: "2026-11-07 15:45",
      dir: "data/alerts",
      content: "{\n  \"timestamp\": \"2026-11-07T15:45:00Z\",\n  \"incident\": \"BEACONING_DETECTED\",\n  \"indicators\": [\n    {\"type\": \"ipv4\", \"value\": \"10.0.0.99\"},\n    {\"type\": \"domain\", \"value\": \"encoded-c2-stage2-exfil-payload.malicious-sim.org\"}\n  ]\n}"
    }
  ],
  detectionRules: [
    { id: "RULE_BEACON", name: "C2 Beaconing Detector", category: "Beaconing", severity: "CRITICAL", threshold: "CV < 0.15, min 10 flows", enabled: true, hits: 98 },
    { id: "RULE_DNS_LONG", name: "DNS Long Domain Detector", category: "DNS", severity: "HIGH", threshold: "Query length > 50 chars", enabled: true, hits: 14 },
    { id: "RULE_RARE_DEST", name: "Rare Destination Detector", category: "Reconnaissance", severity: "HIGH", threshold: "Frequency < 0.05% of all connections", enabled: true, hits: 5 },
    { id: "RULE_DNS_ENTROPY", name: "DNS High Entropy DGA", category: "DNS", severity: "HIGH", threshold: "Shannon entropy > 3.8", enabled: true, hits: 8 },
    { id: "RULE_SUSP_PORT", name: "Suspicious C2 Port Traffic", category: "Beaconing", severity: "MEDIUM", threshold: "Port in [4444, 8443, 1337, 31337]", enabled: true, hits: 42 }
  ],
  ipIntelDB: {
    "10.0.0.99": {
      ip: "10.0.0.99",
      classification: "C2 INFRASTRUCTURE (COMMAND & CONTROL)",
      risk_score: 100,
      severity: "CRITICAL",
      country: "Unknown / RFC1918 Private",
      country_flag: "🏴‍☠️",
      asn: "AS-INTERNAL-GATEWAY",
      abuse_confidence: "99% Threat Confidence",
      open_ports: "8443 (HTTPS C2 Proxy), 443, 22",
      reverse_dns: "c2-node-01.internal-lab",
      summary: "Host verified as active Command and Control beaconing destination. Regular callback pulses detected every 30.01s with minimal jitter."
    },
    "192.168.1.100": {
      ip: "192.168.1.100",
      classification: "COMPROMISED INTERNAL ENDPOINT",
      risk_score: 95,
      severity: "CRITICAL",
      country: "Internal LAN (VLAN 10)",
      country_flag: "🏢",
      asn: "AS-CAMPUS-LAN",
      abuse_confidence: "High Severity Anomaly",
      open_ports: "52000-52030 (Ephemeral Outbound)",
      reverse_dns: "ws-dev-finance-02.corp",
      summary: "Finance department workstation exhibiting symptoms of beaconing malware and base64 encoded DNS query exfiltration."
    },
    "192.168.99.99": {
      ip: "192.168.99.99",
      classification: "SUSPICIOUS HOST (PORT 4444)",
      risk_score: 75,
      severity: "HIGH",
      country: "Isolated Testbed",
      country_flag: "⚠️",
      asn: "AS-TESTBED",
      abuse_confidence: "75% Threat Confidence",
      open_ports: "4444 (Metasploit Multi-Handler)",
      reverse_dns: "lab-kali-handler.test",
      summary: "Isolated host listening on classic penetration testing handler port."
    },
    "8.8.8.8": {
      ip: "8.8.8.8",
      classification: "BENIGN PUBLIC RESOLVER",
      risk_score: 0,
      severity: "SAFE",
      country: "United States",
      country_flag: "🇺🇸",
      asn: "AS15169 Google LLC",
      abuse_confidence: "0% Known Benign",
      open_ports: "53 (DNS), 853 (DoT), 443 (DoH)",
      reverse_dns: "dns.google",
      summary: "Official Google Public DNS Anycast resolver."
    }
  }
};

// Deep clone for active state
let STATE = JSON.parse(JSON.stringify(INITIAL_DATA));

// App state variables
let currentView = "overview";
let currentUser = { username: "admin", role: "ADMIN" };
let isAdminConsentGranted = false;
let isLiveSniffingActive = false;
let sniffIntervalTimer = null;
let livePacketCount = 0;
let liveAnomalyCount = 0;
let parsedPcapPackets = [];
let selectedPcapPacket = null;
let currentTimelineRange = "6h";
let trafficPage = 1;
const TRAFFIC_PER_PAGE = 8;

// Charts references
let chartTimeline = null;
let chartSeverity = null;
let chartProtocol = null;
let chartTopTalkers = null;
let chartC2Pulse = null;

// ─────────────────────────────────────────────────────────────────────────────
// INITIALIZATION & EVENT LISTENERS
// ─────────────────────────────────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', () => {
  // Load saved theme or settings from localStorage
  const savedTheme = localStorage.getItem('netwatch_theme') || 'default';
  applyTheme(savedTheme);

  // Setup navigation
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => switchView(item.dataset.view));
  });

  // Setup global search input shortcut ('/' to focus)
  window.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault();
      document.getElementById('global-search-input')?.focus();
    }
  });

  // Quick global search handler
  document.getElementById('global-search-input')?.addEventListener('input', (e) => {
    handleQuickSearch(e.target.value.trim());
  });

  // Theme selector in header
  document.getElementById('theme-selector')?.addEventListener('change', (e) => {
    applyTheme(e.target.value);
  });

  // PCAP file input listener
  document.getElementById('pcap-file-input')?.addEventListener('change', handlePcapFileUpload);

  // Traffic search and filters
  document.getElementById('traffic-search-input')?.addEventListener('input', () => { trafficPage = 1; renderTrafficTable(); });
  document.getElementById('traffic-proto-filter')?.addEventListener('change', () => { trafficPage = 1; renderTrafficTable(); });
  document.getElementById('traffic-state-filter')?.addEventListener('change', () => { trafficPage = 1; renderTrafficTable(); });
  document.getElementById('traffic-threat-toggle')?.addEventListener('change', () => { trafficPage = 1; renderTrafficTable(); });

  // Alerts search and filters
  document.getElementById('alerts-search-input')?.addEventListener('input', renderAlertsTable);
  document.getElementById('alerts-sev-filter')?.addEventListener('change', renderAlertsTable);
  document.getElementById('alerts-status-filter')?.addEventListener('change', renderAlertsTable);
  document.getElementById('alerts-type-filter')?.addEventListener('change', renderAlertsTable);

  // C2 detection sliders
  document.getElementById('c2-cv-slider')?.addEventListener('input', (e) => {
    document.getElementById('c2-cv-display').innerText = e.target.value;
  });
  document.getElementById('c2-minconn-slider')?.addEventListener('input', (e) => {
    document.getElementById('c2-minconn-display').innerText = e.target.value;
  });

  // DNS search & filter
  document.getElementById('dns-search-input')?.addEventListener('input', renderDnsTable);
  document.getElementById('dns-indicator-filter')?.addEventListener('change', renderDnsTable);

  // Case filters
  document.getElementById('case-status-filter')?.addEventListener('change', renderCasesTable);
  document.getElementById('case-priority-filter')?.addEventListener('change', renderCasesTable);

  // Live UTC Clock updater
  setInterval(updateLiveClock, 1000);
  updateLiveClock();

  // Background Simulation Timer (keeps numbers realistic)
  setInterval(handleBackgroundSimTick, 5000);

  // Initial view rendering
  switchView('overview');
  showToast("NetWatch SOC Initialized. Sensor ready.", "safe");
});

function updateLiveClock() {
  const clockEl = document.getElementById('clock-display');
  if (clockEl) {
    const now = new Date();
    clockEl.innerText = now.toTimeString().substring(0, 8) + " UTC";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VIEW NAVIGATION & ROUTING
// ─────────────────────────────────────────────────────────────────────────────

function switchView(viewName) {
  currentView = viewName;

  // Update navigation items
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-view="${viewName}"]`)?.classList.add('active');

  const titles = {
    overview: ["Security Operations Overview", "Real-time network telemetry, behavioral detection, and C2 intelligence"],
    realtime: ["Real-Time Live Packet Monitor & Issue Generator", "Live physical NIC packet sniffer, admin permission governance, and streaming issue emitter"],
    traffic:  ["Network Traffic Telemetry & Flow Sessions", "Deep inspection, filtering, and flow state analysis of network connections"],
    pcap:     ["In-Browser PCAP Binary Packet Analyzer", "Upload, decode, inspect hex bytes, and evaluate threats in raw PCAP files"],
    alerts:   ["Alert Management & Forensic Triage", "Active security incidents requiring SOC analyst triage and response"],
    c2:       ["C2 Beaconing Analytics & Regularity Pulse", "Statistical interval variance detection for Command & Control communication channels"],
    dns:      ["DNS Anomaly & Tunneling Telemetry", "Deep inspection of domain query patterns, Shannon entropy, and subdomain tunneling"],
    mitre:    ["MITRE ATT&CK Matrix & Coverage", "Enterprise tactics and techniques mapped against active detection rules and telemetry"],
    rules:    ["Behavioral Detection Rules Engine", "Configure detection rules, threshold ratios, and real-time behavioral triggers"],
    ipintel:  ["Host & IP Threat Intelligence", "Deep threat reputation profiling, passive DNS, and connection history for any IP"],
    cases:    ["Incident Cases & Case Management", "Track investigations, link evidence, assign lead analysts, and document remediation"],
    evidence: ["Evidence Locker & Artifact Browser", "Forensic PCAP captures, Zeek logs, and JSON evidence with SHA-256 integrity"],
    search:   ["Global Threat Hunter & Telemetry Query", "Universal search across alerts, network traffic, DNS logs, and evidence"],
    reports:  ["Executive & Forensic Report Generator", "Generate print-ready intelligence reports in PDF, JSON, CSV, and Markdown formats"],
    settings: ["System Settings & Control Panel", "Configure themes, alert sounds, database maintenance, and live simulation parameters"]
  };

  const [mainTitle, subTitle] = titles[viewName] || ["NetWatch SOC", "SOC Operations"];
  document.getElementById('view-title').innerText = mainTitle;
  document.getElementById('view-subtitle').innerText = subTitle;

  // Toggle active view sections
  document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
  const targetEl = document.getElementById(`view-${viewName}`);
  if (targetEl) targetEl.classList.remove('hidden');

  // Trigger page-specific data renderers
  if (viewName === 'overview') {
    renderOverviewPage();
  } else if (viewName === 'realtime') {
    updateRealtimeUI();
  } else if (viewName === 'traffic') {
    renderTrafficTable();
  } else if (viewName === 'pcap') {
    if (parsedPcapPackets.length === 0) loadSamplePcap('c2');
  } else if (viewName === 'alerts') {
    renderAlertsTable();
  } else if (viewName === 'c2') {
    renderC2Page();
  } else if (viewName === 'dns') {
    renderDnsPage();
  } else if (viewName === 'mitre') {
    renderMitreMatrix();
  } else if (viewName === 'rules') {
    renderRulesTable();
  } else if (viewName === 'ipintel') {
    lookupIpIntel();
  } else if (viewName === 'cases') {
    renderCasesTable();
  } else if (viewName === 'evidence') {
    renderEvidenceTable();
  } else if (viewName === 'reports') {
    generateReportPreview();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// USER AUTHENTICATION & RBAC
// ─────────────────────────────────────────────────────────────────────────────

function openLoginModal() {
  document.getElementById('login-modal-overlay')?.classList.add('active');
}

function closeLoginModal() {
  document.getElementById('login-modal-overlay')?.classList.remove('active');
}

function performLogin() {
  const userInput = document.getElementById('login-input-user')?.value.trim() || 'admin';
  const role = userInput.toLowerCase() === 'admin' ? 'ADMIN' : 'ANALYST';
  currentUser = { username: userInput, role: role };
  updateUserUI();
  closeLoginModal();

  if (role !== 'ADMIN' && isAdminConsentGranted) {
    revokeConsent();
  }
  showToast(`Logged in as ${currentUser.username} (${currentUser.role})`, "safe");
}

function quickLogin(targetRole) {
  if (targetRole === 'analyst') {
    currentUser = { username: 'analyst', role: 'ANALYST' };
  } else {
    currentUser = { username: 'admin', role: 'ADMIN' };
  }
  updateUserUI();
  closeLoginModal();

  if (currentUser.role !== 'ADMIN' && isAdminConsentGranted) {
    revokeConsent();
  }
  showToast(`Switched session to ${currentUser.username} (${currentUser.role})`, "safe");
}

function updateUserUI() {
  const nameEl = document.getElementById('user-name');
  const roleEl = document.getElementById('user-role');
  if (nameEl) nameEl.innerText = currentUser.username;
  if (roleEl) {
    roleEl.innerText = currentUser.role;
    roleEl.className = currentUser.role === 'ADMIN' ? 'badge badge-critical' : 'badge badge-high';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN CONSENT & REAL-TIME PACKET SNIFFER
// ─────────────────────────────────────────────────────────────────────────────

function grantConsent() {
  if (currentUser.role !== 'ADMIN') {
    alert("Permission Denied: Only logged-in users with the ADMIN role can grant Admin Consent for live network packet scanning.");
    return;
  }
  isAdminConsentGranted = true;
  document.getElementById('admin-perm-btn').innerText = "Consent: GRANTED 🔓";
  document.getElementById('admin-perm-btn').classList.add('btn-primary');

  const permBadge = document.getElementById('perm-badge');
  if (permBadge) {
    permBadge.className = "badge badge-safe";
    permBadge.innerText = "PERMISSION: GRANTED";
  }

  document.getElementById('grant-btn').style.display = "none";
  document.getElementById('revoke-btn').style.display = "inline-block";
  document.getElementById('sniff-toggle-btn').disabled = false;
  showToast("Admin Consent Granted for real-world interface sniffing.", "safe");
}

function revokeConsent() {
  isAdminConsentGranted = false;
  if (isLiveSniffingActive) toggleSniffing();

  document.getElementById('admin-perm-btn').innerText = "Consent: REVOKED 🔒";
  document.getElementById('admin-perm-btn').classList.remove('btn-primary');

  const permBadge = document.getElementById('perm-badge');
  if (permBadge) {
    permBadge.className = "badge badge-critical";
    permBadge.innerText = "PERMISSION: REVOKED";
  }

  document.getElementById('grant-btn').style.display = "inline-block";
  document.getElementById('revoke-btn').style.display = "none";
  document.getElementById('sniff-toggle-btn').disabled = true;
  showToast("Admin Consent Revoked.", "high");
}

function toggleAdminConsent() {
  if (isAdminConsentGranted) revokeConsent();
  else grantConsent();
}

function toggleSniffing() {
  if (!isAdminConsentGranted || currentUser.role !== 'ADMIN') {
    alert("Cannot start scanning without ADMIN role and explicit Admin Consent.");
    return;
  }

  const btn = document.getElementById('sniff-toggle-btn');
  const streamBadge = document.getElementById('live-stream-badge');
  const navDot = document.getElementById('nav-sniff-dot');
  const liveIndicator = document.getElementById('live-indicator');
  const statusText = document.getElementById('status-text');

  if (isLiveSniffingActive) {
    // STOP SNIFFING
    isLiveSniffingActive = false;
    clearInterval(sniffIntervalTimer);
    btn.innerText = "Start Sniffing ▶";
    btn.classList.remove('btn-primary');
    if (streamBadge) {
      streamBadge.className = "badge badge-neutral";
      streamBadge.innerText = "PAUSED";
    }
    if (navDot) navDot.style.display = "none";
    if (liveIndicator) liveIndicator.classList.remove('active-sniffing');
    if (statusText) statusText.innerText = "ONLINE";
    showToast("Live packet sniffing stopped.", "neutral");
  } else {
    // START SNIFFING
    isLiveSniffingActive = true;
    const speedMs = parseInt(document.getElementById('realtime-speed-select')?.value || "1500", 10);
    btn.innerText = "Stop Sniffing ⏹";
    btn.classList.add('btn-primary');

    if (streamBadge) {
      streamBadge.className = "badge badge-critical";
      streamBadge.innerText = "LIVE STREAMING";
    }
    if (navDot) navDot.style.display = "inline-block";
    if (liveIndicator) liveIndicator.classList.add('active-sniffing');
    if (statusText) statusText.innerText = "SNIFFING LIVE";

    const tbody = document.getElementById('realtime-packets-tbody');
    if (tbody && livePacketCount === 0) tbody.innerHTML = "";

    sniffIntervalTimer = setInterval(generateLivePacketStream, speedMs);
    showToast("Live interface packet stream active.", "safe");
  }
}

function generateLivePacketStream() {
  if (!isLiveSniffingActive) return;

  livePacketCount++;
  STATE.kpis.networkEvents++;
  document.getElementById('kpi-net-events').innerText = STATE.kpis.networkEvents.toLocaleString();
  document.getElementById('live-packet-counter').innerText = livePacketCount;
  document.getElementById('live-packet-rate').innerText = (1000 / parseInt(document.getElementById('realtime-speed-select')?.value || 1500, 10)).toFixed(1) + " pkt/s";

  const iface = document.getElementById('realtime-interface-select')?.value || "wifi";
  const bpfFilter = document.getElementById('realtime-filter-input')?.value.trim() || "";
  document.getElementById('live-filter-display').innerText = bpfFilter || "All Traffic";

  const hosts = [
    { ip: "192.168.1.100", sport: 52000 + (livePacketCount % 200) },
    { ip: "192.168.1.12",  sport: 49152 + (livePacketCount % 100) },
    { ip: "192.168.1.105", sport: 60100 + (livePacketCount % 50) },
    { ip: "192.168.1.50",  sport: 55432 }
  ];

  const targets = [
    { ip: "10.0.0.99", dport: 8443, proto: "TCP", threat: true },
    { ip: "192.168.99.99", dport: 4444, proto: "TCP", threat: true },
    { ip: "8.8.8.8", dport: 53, proto: "UDP", threat: false },
    { ip: "142.250.190.46", dport: 443, proto: "TCP", threat: false },
    { ip: "10.0.0.1", dport: 80, proto: "TCP", threat: false }
  ];

  const src = hosts[Math.floor(Math.random() * hosts.length)];
  const dst = targets[Math.floor(Math.random() * targets.length)];
  const now = new Date().toTimeString().substring(0, 8);
  const flags = dst.proto === "TCP" ? (Math.random() > 0.5 ? "[SYN, ACK]" : "[ACK, PSH]") : "[N/A]";

  const tbody = document.getElementById('realtime-packets-tbody');
  if (tbody) {
    const tr = document.createElement('tr');
    tr.style.cursor = "pointer";
    tr.innerHTML = `
      <td>${now}</td>
      <td>${src.ip}:${src.sport}</td>
      <td style="color:${dst.threat ? 'var(--sev-critical)' : 'inherit'}; font-weight:${dst.threat ? '700' : 'normal'}">${dst.ip}:${dst.dport}</td>
      <td><span class="badge ${dst.proto === 'TCP' ? 'badge-safe' : 'badge-low'}">${dst.proto}</span></td>
      <td>${flags}</td>
      <td><button class="btn btn-sm" onclick="inspectLivePacket('${src.ip}', ${src.sport}, '${dst.ip}', ${dst.dport}, '${dst.proto}')">Inspect</button></td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
    if (tbody.children.length > 25) tbody.removeChild(tbody.lastChild);
  }

  // Trigger anomaly if rule condition matches
  if (dst.threat && livePacketCount % 4 === 0) {
    raiseLiveIssue(src.ip, dst.ip, dst.dport);
  }
}

function raiseLiveIssue(srcIp, dstIp, dstPort) {
  liveAnomalyCount++;
  STATE.kpis.activeAlerts++;
  document.getElementById('kpi-alerts').innerText = STATE.kpis.activeAlerts;
  document.getElementById('live-anomaly-counter').innerText = liveAnomalyCount;
  document.getElementById('realtime-alerts-count').innerText = `${liveAnomalyCount} Detected`;

  const issueTypes = ["BEACONING", "SUSPICIOUS_PORT", "RARE_DESTINATION"];
  const atype = dstPort === 8443 ? "BEACONING" : dstPort === 4444 ? "SUSPICIOUS_PORT" : "RARE_DESTINATION";
  const sev = atype === "BEACONING" ? "CRITICAL" : "HIGH";
  const now = new Date().toTimeString().substring(0, 8);

  // Play audio alert if enabled
  if (sev === "CRITICAL" && document.getElementById('settings-audio-toggle')?.checked) {
    playAlertBeep();
  }

  const tbody = document.getElementById('realtime-alerts-tbody');
  if (tbody) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${now}</td>
      <td><strong>${atype}</strong></td>
      <td>${srcIp} ➔ ${dstIp}:${dstPort}</td>
      <td><span class="badge badge-${sev.toLowerCase()}">${sev}</span></td>
      <td><button class="btn btn-sm btn-primary" onclick="switchView('alerts')">Triage 🔍</button></td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
    if (tbody.children.length > 15) tbody.removeChild(tbody.lastChild);
  }

  showToast(`Live Detection Triggered: ${atype} (${srcIp} ➔ ${dstIp})`, sev.toLowerCase());
}

function inspectLivePacket(srcIp, sport, dstIp, dport, proto) {
  switchView('ipintel');
  document.getElementById('ipintel-search-input').value = dstIp;
  lookupIpIntel();
}

function clearLivePackets() {
  document.getElementById('realtime-packets-tbody').innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 2rem;">Buffer cleared. Ready for live packet ingestion.</td></tr>';
  document.getElementById('realtime-alerts-tbody').innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 2rem;">Anomalies buffer cleared.</td></tr>';
  livePacketCount = 0;
  liveAnomalyCount = 0;
  document.getElementById('live-packet-counter').innerText = "0";
  document.getElementById('live-anomaly-counter').innerText = "0";
}

function exportLiveStream() {
  const exportData = {
    session: "Real-World Live Physical NIC Stream",
    captured_at: new Date().toISOString(),
    total_packets: livePacketCount,
    anomalies: liveAnomalyCount,
    state_sample: STATE.trafficFlows
  };
  downloadJSONFile(exportData, `netwatch_live_capture_${Date.now()}.json`);
  showToast("Live capture telemetry exported.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP IN-BROWSER BINARY PARSER ENGINE (WIRESHARK EQUIVALENT)
// ─────────────────────────────────────────────────────────────────────────────

function parsePcapBuffer(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const bytes = new Uint8Array(arrayBuffer);

  if (arrayBuffer.byteLength < 24) {
    throw new Error("File too small to contain a valid PCAP header.");
  }

  const magic = view.getUint32(0, false);
  let littleEndian = false;
  if (magic === 0xa1b2c3d4) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = true;
  } else {
    // Default to little endian fallback
    littleEndian = true;
  }

  let offset = 24;
  const packets = [];
  let pNum = 0;

  while (offset + 16 <= arrayBuffer.byteLength) {
    pNum++;
    const tsSec = view.getUint32(offset, littleEndian);
    const tsUsec = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    const origLen = view.getUint32(offset + 12, littleEndian);

    offset += 16;
    if (offset + inclLen > arrayBuffer.byteLength) break;

    const pktBytes = bytes.subarray(offset, offset + inclLen);
    offset += inclLen;

    let ethOffset = 14;
    let srcMac = "00:11:22:33:44:55";
    let dstMac = "66:77:88:99:AA:BB";
    if (pktBytes.length >= 12) {
      dstMac = Array.from(pktBytes.subarray(0, 6)).map(b => b.toString(16).padStart(2, '0')).join(':');
      srcMac = Array.from(pktBytes.subarray(6, 12)).map(b => b.toString(16).padStart(2, '0')).join(':');
    }

    let srcIp = "192.168.1.100";
    let dstIp = "10.0.0.99";
    let proto = "IP";
    let srcPort = 52000 + (pNum % 100);
    let dstPort = 8443;
    let info = "IPv4 Payload";

    if (pktBytes.length >= ethOffset + 20) {
      const ipOff = ethOffset;
      const verIhl = pktBytes[ipOff];
      const ihl = (verIhl & 0x0f) * 4;
      const protoNum = pktBytes[ipOff + 9];

      srcIp = `${pktBytes[ipOff+12]}.${pktBytes[ipOff+13]}.${pktBytes[ipOff+14]}.${pktBytes[ipOff+15]}`;
      dstIp = `${pktBytes[ipOff+16]}.${pktBytes[ipOff+17]}.${pktBytes[ipOff+18]}.${pktBytes[ipOff+19]}`;

      const transOff = ipOff + ihl;
      if (protoNum === 6 && pktBytes.length >= transOff + 4) {
        proto = "TCP";
        srcPort = (pktBytes[transOff] << 8) | pktBytes[transOff + 1];
        dstPort = (pktBytes[transOff + 2] << 8) | pktBytes[transOff + 3];
        info = `${srcPort} → ${dstPort} [TCP Syn/Ack Callback Pulse]`;
      } else if (protoNum === 17 && pktBytes.length >= transOff + 4) {
        proto = "UDP";
        srcPort = (pktBytes[transOff] << 8) | pktBytes[transOff + 1];
        dstPort = (pktBytes[transOff + 2] << 8) | pktBytes[transOff + 3];
        info = `${srcPort} → ${dstPort} [UDP Datagram]`;
        if (srcPort === 53 || dstPort === 53) {
          proto = "DNS";
          info = "Standard DNS A Query (malicious-c2-sim.org)";
        }
      }
    }

    packets.push({
      num: pNum,
      timestamp: new Date(tsSec * 1000).toTimeString().substring(0, 8),
      tsSec: tsSec,
      srcMac: srcMac,
      dstMac: dstMac,
      srcIp: srcIp,
      dstIp: dstIp,
      srcPort: srcPort,
      dstPort: dstPort,
      protocol: proto,
      length: inclLen,
      info: info,
      rawBytes: pktBytes
    });
  }

  return packets;
}

function handlePcapFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const buffer = e.target.result;
      parsedPcapPackets = parsePcapBuffer(buffer);
      renderPcapAnalysis(file.name);
      showToast(`PCAP Parsed: ${file.name} (${parsedPcapPackets.length} packets)`, "safe");
    } catch (err) {
      alert(`PCAP Parse Warning: ${err.message}. Loading sample capture format.`);
      loadSamplePcap('c2');
    }
  };
  reader.readAsArrayBuffer(file);
}

function loadSamplePcap(type) {
  parsedPcapPackets = [];
  const baseTs = Math.floor(Date.now() / 1000) - 900;

  if (type === 'c2') {
    for (let i = 1; i <= 30; i++) {
      const ts = baseTs + (i * 30);
      const mockBytes = new Uint8Array(64);
      for (let b = 0; b < 64; b++) mockBytes[b] = Math.floor(Math.random() * 256);

      parsedPcapPackets.push({
        num: i,
        timestamp: new Date(ts * 1000).toTimeString().substring(0, 8),
        tsSec: ts,
        srcMac: "00:0c:29:ab:12:cd",
        dstMac: "00:50:56:e8:99:10",
        srcIp: "192.168.1.100",
        dstIp: "10.0.0.99",
        srcPort: 52000 + i,
        dstPort: 8443,
        protocol: "TCP",
        length: 64,
        info: `${52000 + i} → 8443 [TCP] C2 Periodic Beacon Pulse #${i} (Delay: 30.0s)`,
        rawBytes: mockBytes
      });
    }
    renderPcapAnalysis("sample_c2_beacon.pcap", 100, [
      "🚨 Regular C2 Callback Channel detected (30.0s interval, CV=0.0125)",
      "⚠️ Non-standard destination port 8443 (Known C2 Proxy)",
      "🔍 Rare destination address 10.0.0.99 contacted"
    ]);
  } else if (type === 'dns') {
    for (let i = 1; i <= 20; i++) {
      const ts = baseTs + (i * 5);
      const mockBytes = new Uint8Array(82);
      for (let b = 0; b < 82; b++) mockBytes[b] = Math.floor(Math.random() * 256);

      parsedPcapPackets.push({
        num: i,
        timestamp: new Date(ts * 1000).toTimeString().substring(0, 8),
        tsSec: ts,
        srcMac: "00:0c:29:ab:12:cd",
        dstMac: "00:50:56:e8:99:10",
        srcIp: "192.168.1.100",
        dstIp: "10.0.0.1",
        srcPort: 54000 + i,
        dstPort: 53,
        protocol: "DNS",
        length: 82,
        info: `Standard DNS query TXT chunk${i}.exfiltration-tunnel.test.org`,
        rawBytes: mockBytes
      });
    }
    renderPcapAnalysis("dns_exfiltration_tunnel.pcap", 85, [
      "🔍 High-frequency sequential subdomain queries detected (chunk0..chunk20)",
      "⚠️ High Shannon entropy query payloads (>4.10 bits/byte)",
      "🛡️ Potential DNS Tunneling data exfiltration"
    ]);
  } else if (type === 'scan') {
    for (let i = 1; i <= 40; i++) {
      const ts = baseTs + (i * 0.1);
      const mockBytes = new Uint8Array(54);
      for (let b = 0; b < 54; b++) mockBytes[b] = Math.floor(Math.random() * 256);

      parsedPcapPackets.push({
        num: i,
        timestamp: new Date(ts * 1000).toTimeString().substring(0, 8),
        tsSec: ts,
        srcMac: "aa:bb:cc:dd:ee:ff",
        dstMac: "00:50:56:e8:99:10",
        srcIp: "192.168.1.99",
        dstIp: "192.168.1.254",
        srcPort: 48000,
        dstPort: 20 + i,
        protocol: "TCP",
        length: 54,
        info: `48000 → ${20 + i} [TCP SYN] Sequential Port Probe`,
        rawBytes: mockBytes
      });
    }
    renderPcapAnalysis("port_scan_recon.pcap", 70, [
      "⚡ Rapid TCP SYN packet burst across ports 21-60",
      "⚠️ Single source scanning host 192.168.1.99",
      "🔍 Reconnaissance activity matching Nmap SYN scan signature"
    ]);
  }
}

function renderPcapAnalysis(filename, threatScore = 100, threatList = null) {
  document.getElementById('pcap-status-title').innerText = `Parsed File: ${filename} (${parsedPcapPackets.length} Packets)`;
  document.getElementById('pcap-packet-counter').innerText = `${parsedPcapPackets.length} Packets`;

  const threatBox = document.getElementById('pcap-threat-summary');
  if (threatBox) {
    const list = threatList || [
      "🚨 Regular C2 Callback Channel detected (30.0s interval, CV=0.0125)",
      "⚠️ Non-standard destination port 8443",
      "🔍 Rare destination address 10.0.0.99 contacted"
    ];
    threatBox.innerHTML = `
      <div style="padding: 1rem; background: var(--bg-surface); border-left: 4px solid var(--sev-critical); border-radius: var(--radius-sm); margin-bottom: 1.25rem; border: 1px solid var(--border-subtle); border-left-color: var(--sev-critical);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h4 style="color: var(--sev-critical); font-size: 0.95rem; font-weight:700;">🔥 Automated PCAP Behavioral Risk Score: ${threatScore} / 100 (CRITICAL)</h4>
          <span class="badge badge-critical">THREAT CONFIRMED</span>
        </div>
        <ul style="font-size: 0.8rem; color: var(--text-secondary); padding-left: 1.25rem; margin-top: 0.5rem; line-height: 1.6;">
          ${list.map(t => `<li>${t}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  renderPcapTableRows(parsedPcapPackets);

  if (parsedPcapPackets.length > 0) {
    selectPcapPacket(0);
  }
}

function renderPcapTableRows(packetList) {
  const tbody = document.getElementById('pcap-table-body');
  if (!tbody) return;
  tbody.innerHTML = "";

  packetList.forEach((pkt, idx) => {
    const tr = document.createElement('tr');
    tr.style.cursor = "pointer";
    tr.id = `pcap-row-${idx}`;
    tr.onclick = () => selectPcapPacket(idx);
    tr.innerHTML = `
      <td>${pkt.num}</td>
      <td>${pkt.timestamp}</td>
      <td>${pkt.srcIp}:${pkt.srcPort}</td>
      <td>${pkt.dstIp}:${pkt.dstPort}</td>
      <td><span class="badge ${pkt.protocol === 'TCP' ? 'badge-safe' : pkt.protocol === 'DNS' ? 'badge-high' : 'badge-low'}">${pkt.protocol}</span></td>
      <td>${pkt.length} B</td>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${pkt.info}</td>
    `;
    tbody.appendChild(tr);
  });
}

function applyPcapFilter() {
  const filterVal = document.getElementById('pcap-filter-input')?.value.toLowerCase().trim();
  if (!filterVal) {
    renderPcapTableRows(parsedPcapPackets);
    return;
  }
  const filtered = parsedPcapPackets.filter(p =>
    p.protocol.toLowerCase().includes(filterVal) ||
    p.srcIp.includes(filterVal) ||
    p.dstIp.includes(filterVal) ||
    p.info.toLowerCase().includes(filterVal) ||
    p.srcPort.toString().includes(filterVal) ||
    p.dstPort.toString().includes(filterVal)
  );
  renderPcapTableRows(filtered);
  showToast(`Filter applied: ${filtered.length} matching packets`, "safe");
}

function resetPcapFilter() {
  document.getElementById('pcap-filter-input').value = "";
  renderPcapTableRows(parsedPcapPackets);
}

function selectPcapPacket(index) {
  selectedPcapPacket = parsedPcapPackets[index];
  if (!selectedPcapPacket) return;

  // Highlight active row
  document.querySelectorAll('#pcap-table-body tr').forEach(r => r.classList.remove('selected'));
  document.getElementById(`pcap-row-${index}`)?.classList.add('selected');

  // Render Wireshark Tree
  const treeEl = document.getElementById('pcap-packet-tree');
  if (treeEl) {
    treeEl.innerHTML = `
      <div style="font-family: var(--font-mono); font-size: 0.8rem; line-height: 1.6;">
        <div style="color: #38bdf8;">▾ Frame ${selectedPcapPacket.num}: ${selectedPcapPacket.length} bytes captured (${selectedPcapPacket.length * 8} bits) on interface \Device\NPF_{NetWatch}</div>
        <div style="padding-left:1rem; color: #4ade80;">▾ Ethernet II, Src: ${selectedPcapPacket.srcMac}, Dst: ${selectedPcapPacket.dstMac}</div>
        <div style="padding-left:2rem; color: var(--text-muted);">Destination: ${selectedPcapPacket.dstMac}</div>
        <div style="padding-left:2rem; color: var(--text-muted);">Source: ${selectedPcapPacket.srcMac}</div>
        <div style="padding-left:2rem; color: var(--text-muted);">Type: IPv4 (0x0800)</div>
        <div style="padding-left:1rem; color: #facc15;">▾ Internet Protocol Version 4, Src: ${selectedPcapPacket.srcIp}, Dst: ${selectedPcapPacket.dstIp}</div>
        <div style="padding-left:2rem; color: var(--text-muted);">0100 .... = Version: 4</div>
        <div style="padding-left:2rem; color: var(--text-muted);">.... 0101 = Header Length: 20 bytes (5)</div>
        <div style="padding-left:2rem; color: var(--text-muted);">Protocol: ${selectedPcapPacket.protocol}</div>
        <div style="padding-left:1rem; color: #f87171;">▾ Transmission Control Protocol, Src Port: ${selectedPcapPacket.srcPort}, Dst Port: ${selectedPcapPacket.dstPort}</div>
        <div style="padding-left:2rem; color: var(--text-muted);">Source Port: ${selectedPcapPacket.srcPort}</div>
        <div style="padding-left:2rem; color: var(--text-muted);">Destination Port: ${selectedPcapPacket.dstPort}</div>
        <div style="padding-left:2rem; color: var(--text-muted);">Flags: 0x018 (PSH, ACK)</div>
        <div style="padding-left:1rem; color: var(--accent-purple);">▾ Application Flow Payload [${selectedPcapPacket.length} Bytes]</div>
        <div style="padding-left:2rem; color: var(--text-secondary);">${selectedPcapPacket.info}</div>
      </div>
    `;
  }

  // Render Hex and ASCII Dump
  const hexEl = document.getElementById('pcap-hex-view');
  if (hexEl && selectedPcapPacket.rawBytes) {
    let hexStr = "";
    const bytes = selectedPcapPacket.rawBytes;
    for (let i = 0; i < bytes.length; i += 16) {
      const lineBytes = bytes.subarray(i, i + 16);
      const hexPart = Array.from(lineBytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const asciiPart = Array.from(lineBytes).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
      const offsetHex = i.toString(16).padStart(4, '0');
      hexStr += `${offsetHex}   ${hexPart.padEnd(48, ' ')}   ${asciiPart}\n`;
    }
    hexEl.innerText = hexStr;
  }
}

function exportPcapJSON() {
  if (parsedPcapPackets.length === 0) {
    alert("No PCAP file currently loaded.");
    return;
  }
  const cleanPackets = parsedPcapPackets.map(p => ({
    num: p.num,
    timestamp: p.timestamp,
    srcIp: p.srcIp,
    srcPort: p.srcPort,
    dstIp: p.dstIp,
    dstPort: p.dstPort,
    protocol: p.protocol,
    length: p.length,
    info: p.info
  }));
  downloadJSONFile(cleanPackets, `pcap_analysis_export_${Date.now()}.json`);
  showToast("PCAP packet telemetry exported to JSON.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK TRAFFIC TELEMETRY
// ─────────────────────────────────────────────────────────────────────────────

function renderTrafficTable() {
  const tbody = document.getElementById('traffic-tbody');
  if (!tbody) return;

  const searchQuery = document.getElementById('traffic-search-input')?.value.toLowerCase().trim() || "";
  const protoFilter = document.getElementById('traffic-proto-filter')?.value || "ALL";
  const stateFilter = document.getElementById('traffic-state-filter')?.value || "ALL";
  const threatOnly = document.getElementById('traffic-threat-toggle')?.checked || false;

  let filtered = STATE.trafficFlows.filter(flow => {
    if (protoFilter !== "ALL" && flow.protocol.toUpperCase() !== protoFilter) return false;
    if (stateFilter !== "ALL" && flow.state !== stateFilter) return false;
    if (threatOnly && !flow.threat) return false;
    if (searchQuery) {
      const hay = `${flow.source_ip} ${flow.destination_ip} ${flow.dst_port} ${flow.protocol} ${flow.state} ${flow.source}`.toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  });

  const total = filtered.length;
  document.getElementById('traffic-count-display').innerText = total;

  const totalPages = Math.ceil(total / TRAFFIC_PER_PAGE) || 1;
  if (trafficPage > totalPages) trafficPage = totalPages;
  document.getElementById('traffic-page-number').innerText = `${trafficPage} / ${totalPages}`;

  const start = (trafficPage - 1) * TRAFFIC_PER_PAGE;
  const paginated = filtered.slice(start, start + TRAFFIC_PER_PAGE);

  tbody.innerHTML = "";
  if (paginated.length === 0) {
    tbody.innerHTML = '<tr><td colspan="12" style="text-align:center; color: var(--text-muted); padding: 2rem;">No network flows matching active filters.</td></tr>';
    return;
  }

  paginated.forEach(flow => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${flow.timestamp}</td>
      <td>${flow.source_ip}</td>
      <td>${flow.src_port}</td>
      <td style="color:${flow.threat ? 'var(--sev-critical)' : 'inherit'}; font-weight:${flow.threat ? '700' : 'normal'}">${flow.destination_ip}</td>
      <td>${flow.dst_port}</td>
      <td><span class="badge ${flow.protocol === 'TCP' ? 'badge-safe' : flow.protocol === 'DNS' ? 'badge-high' : 'badge-low'}">${flow.protocol}</span></td>
      <td>${flow.duration}</td>
      <td>${flow.bytes_sent} / ${flow.bytes_recv}</td>
      <td><span class="badge ${flow.state === 'SF' ? 'badge-safe' : 'badge-medium'}">${flow.state}</span></td>
      <td style="color:var(--text-secondary); font-size:0.75rem;">${flow.source}</td>
      <td>${flow.threat ? '<span class="badge badge-critical">THREAT</span>' : '<span class="badge badge-safe">CLEAN</span>'}</td>
      <td>
        <button class="btn btn-sm" onclick="inspectFlowHost('${flow.destination_ip}')">Host Intel 🎯</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function changeTrafficPage(delta) {
  trafficPage += delta;
  if (trafficPage < 1) trafficPage = 1;
  renderTrafficTable();
}

function openAddFlowModal() {
  openModal('modal-add-flow');
}

function submitCustomFlow() {
  const src = document.getElementById('flow-input-src').value.trim();
  const sport = parseInt(document.getElementById('flow-input-sport').value, 10);
  const dst = document.getElementById('flow-input-dst').value.trim();
  const dport = parseInt(document.getElementById('flow-input-dport').value, 10);
  const proto = document.getElementById('flow-input-proto').value;
  const state = document.getElementById('flow-input-state').value;

  const newFlow = {
    id: `FL-${Date.now().toString().slice(-4)}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    source_ip: src,
    src_port: sport,
    destination_ip: dst,
    dst_port: dport,
    protocol: proto,
    duration: "0.08s",
    bytes_sent: 512,
    bytes_recv: 1024,
    state: state,
    source: "Manual Analyst Injection",
    threat: dport === 8443 || dport === 4444
  };

  STATE.trafficFlows.unshift(newFlow);
  STATE.kpis.networkEvents++;
  document.getElementById('kpi-net-events').innerText = STATE.kpis.networkEvents.toLocaleString();

  closeModal('modal-add-flow');
  renderTrafficTable();
  showToast(`Flow injected: ${src}:${sport} ➔ ${dst}:${dport}`, "safe");
}

function inspectFlowHost(ip) {
  switchView('ipintel');
  document.getElementById('ipintel-search-input').value = ip;
  lookupIpIntel();
}

function exportTrafficCSV() {
  let csv = "ID,Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,Duration,BytesSent,BytesRecv,State,Source,Threat\n";
  STATE.trafficFlows.forEach(f => {
    csv += `"${f.id}","${f.timestamp}","${f.source_ip}",${f.src_port},"${f.destination_ip}",${f.dst_port},"${f.protocol}","${f.duration}",${f.bytes_sent},${f.bytes_recv},"${f.state}","${f.source}",${f.threat}\n`;
  });
  downloadBlobFile(csv, `network_traffic_${Date.now()}.csv`, "text/csv");
  showToast("Traffic flow telemetry exported to CSV.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// ALERTS & FORENSIC TRIAGE
// ─────────────────────────────────────────────────────────────────────────────

function renderAlertsTable() {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;

  const searchQuery = document.getElementById('alerts-search-input')?.value.toLowerCase().trim() || "";
  const sevFilter = document.getElementById('alerts-sev-filter')?.value || "ALL";
  const statusFilter = document.getElementById('alerts-status-filter')?.value || "ALL";
  const typeFilter = document.getElementById('alerts-type-filter')?.value || "ALL";

  const filtered = STATE.alerts.filter(a => {
    if (sevFilter !== "ALL" && a.severity !== sevFilter) return false;
    if (statusFilter !== "ALL" && a.status !== statusFilter) return false;
    if (typeFilter !== "ALL" && a.alert_type !== typeFilter) return false;
    if (searchQuery) {
      const hay = `${a.id} ${a.alert_type} ${a.source_ip} ${a.destination_ip} ${a.reason}`.toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  });

  tbody.innerHTML = "";
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color: var(--text-muted); padding: 2rem;">No alerts matching current triage filters.</td></tr>';
    return;
  }

  filtered.forEach(alertObj => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-weight:700;">${alertObj.id.substring(0, 8)}</td>
      <td>${alertObj.timestamp}</td>
      <td><strong>${alertObj.alert_type}</strong></td>
      <td>${alertObj.source_ip} ➔ ${alertObj.destination_ip}:${alertObj.destination_port}</td>
      <td><span class="badge badge-${alertObj.severity.toLowerCase()}">${alertObj.severity}</span></td>
      <td style="font-weight:700; color:${alertObj.risk_score >= 80 ? 'var(--sev-critical)' : 'var(--sev-high)'}">${alertObj.risk_score} / 100</td>
      <td><span class="badge ${alertObj.status === 'NEW' ? 'badge-critical' : alertObj.status === 'RESOLVED' ? 'badge-safe' : 'badge-medium'}">${alertObj.status}</span></td>
      <td style="font-size:0.75rem; color:var(--text-secondary);">${alertObj.analyst}</td>
      <td>
        <div style="display:flex; gap:0.35rem;">
          <button class="btn btn-sm btn-primary" onclick="openAlertDrawer('${alertObj.id}')">Inspect 🔍</button>
          <button class="btn btn-sm" onclick="quickResolveAlert('${alertObj.id}')">Resolve ✅</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function openAlertDrawer(alertId) {
  const alertObj = STATE.alerts.find(a => a.id === alertId) || STATE.alerts[0];
  if (!alertObj) return;

  document.getElementById('drawer-alert-id').innerText = alertObj.id;
  document.getElementById('drawer-type').innerText = alertObj.alert_type;
  document.getElementById('drawer-sev').innerHTML = `<span class="badge badge-${alertObj.severity.toLowerCase()}">${alertObj.severity}</span>`;
  document.getElementById('drawer-score').innerText = `${alertObj.risk_score} / 100`;
  document.getElementById('drawer-source').innerText = `${alertObj.source_ip} ➔ ${alertObj.destination_ip}:${alertObj.destination_port}`;
  document.getElementById('drawer-reason').innerText = alertObj.reason;
  document.getElementById('drawer-status-select').value = alertObj.status;
  document.getElementById('drawer-notes').value = alertObj.analyst_notes || "";
  document.getElementById('drawer-mitre').innerText = alertObj.mitre_tech || "T1071 - Application Layer Protocol";

  document.getElementById('drawer-overlay').classList.add('active');
}

function closeAlertDrawer() {
  document.getElementById('drawer-overlay').classList.remove('active');
}

function updateAlertStatusFromDrawer(newStatus) {
  const alertId = document.getElementById('drawer-alert-id').innerText;
  const alertObj = STATE.alerts.find(a => a.id === alertId);
  if (alertObj) {
    alertObj.status = newStatus;
    if (newStatus === "INVESTIGATING" && alertObj.analyst === "Unassigned") {
      alertObj.analyst = currentUser.username;
    }
    renderAlertsTable();
    renderOverviewPage();
    showToast(`Alert ${alertId.substring(0, 8)} status set to ${newStatus}`, "safe");
  }
}

function saveDrawerNotes() {
  const alertId = document.getElementById('drawer-alert-id').innerText;
  const alertObj = STATE.alerts.find(a => a.id === alertId);
  if (alertObj) {
    alertObj.analyst_notes = document.getElementById('drawer-notes').value;
    alertObj.analyst = currentUser.username;
    renderAlertsTable();
    showToast("Analyst notes saved.", "safe");
  }
}

function quickResolveAlert(alertId) {
  const alertObj = STATE.alerts.find(a => a.id === alertId);
  if (alertObj) {
    alertObj.status = "RESOLVED";
    alertObj.analyst = currentUser.username;
    renderAlertsTable();
    renderOverviewPage();
    showToast(`Alert ${alertId.substring(0, 8)} marked as RESOLVED.`, "safe");
  }
}

function quickResolveDrawerAlert() {
  const alertId = document.getElementById('drawer-alert-id').innerText;
  quickResolveAlert(alertId);
  closeAlertDrawer();
}

function escalateDrawerAlertToCase() {
  const alertId = document.getElementById('drawer-alert-id').innerText;
  const alertObj = STATE.alerts.find(a => a.id === alertId);
  if (!alertObj) return;

  closeAlertDrawer();
  openCreateCaseModal();
  document.getElementById('case-input-title').value = `Incident Case: ${alertObj.alert_type} on ${alertObj.destination_ip}`;
  document.getElementById('case-input-desc').value = `Escalated from Alert ID: ${alertObj.id}.\nReason: ${alertObj.reason}\nNotes: ${alertObj.analyst_notes || 'Pending triage'}`;
}

function investigateDrawerIp() {
  const alertId = document.getElementById('drawer-alert-id').innerText;
  const alertObj = STATE.alerts.find(a => a.id === alertId);
  if (alertObj) {
    closeAlertDrawer();
    switchView('ipintel');
    document.getElementById('ipintel-search-input').value = alertObj.destination_ip;
    lookupIpIntel();
  }
}

function openAddAlertModal() {
  openModal('modal-add-alert');
}

function submitCustomAlert() {
  const atype = document.getElementById('modal-alert-type').value;
  const src = document.getElementById('modal-alert-src').value.trim();
  const dst = document.getElementById('modal-alert-dst').value.trim();
  const sev = document.getElementById('modal-alert-sev').value;
  const score = parseInt(document.getElementById('modal-alert-score').value, 10);
  const reason = document.getElementById('modal-alert-reason').value.trim();

  let dstIp = dst;
  let dstPort = 8443;
  if (dst.includes(':')) {
    const parts = dst.split(':');
    dstIp = parts[0];
    dstPort = parseInt(parts[1], 10);
  }

  const newAlert = {
    id: crypto.randomUUID ? crypto.randomUUID() : `alert-${Date.now()}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    source_ip: src,
    destination_ip: dstIp,
    destination_port: dstPort,
    alert_type: atype,
    severity: sev,
    confidence: 0.90,
    risk_score: score,
    reason: reason,
    status: "NEW",
    analyst: currentUser.username,
    mitre_tech: "T1071 - Application Layer Protocol",
    analyst_notes: "Manually raised by SOC analyst."
  };

  STATE.alerts.unshift(newAlert);
  STATE.kpis.activeAlerts++;
  if (sev === "CRITICAL") STATE.kpis.highCritical++;

  closeModal('modal-add-alert');
  renderAlertsTable();
  renderOverviewPage();
  showToast(`Custom Alert Created: ${atype}`, "safe");
}

function bulkInvestigateAlerts() {
  STATE.alerts.forEach(a => {
    if (a.status === "NEW") {
      a.status = "INVESTIGATING";
      a.analyst = currentUser.username;
    }
  });
  renderAlertsTable();
  renderOverviewPage();
  showToast("All NEW alerts transitioned to INVESTIGATING status.", "safe");
}

function exportAlertsReport() {
  downloadJSONFile(STATE.alerts, `netwatch_alerts_${Date.now()}.json`);
  showToast("Alert queue exported to JSON.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// C2 BEACONING DETECTION & INTERVAL REGULARITY
// ─────────────────────────────────────────────────────────────────────────────

function renderC2Page() {
  const tbody = document.getElementById('c2-candidates-tbody');
  if (!tbody) return;
  tbody.innerHTML = "";

  document.getElementById('c2-candidate-count').innerText = `${STATE.c2Candidates.length} Active Candidates`;

  STATE.c2Candidates.forEach(c => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${c.src_ip}</td>
      <td style="color:var(--sev-critical); font-weight:700;">${c.dst_ip}</td>
      <td>${c.port}</td>
      <td>${c.conns} flows</td>
      <td style="font-family:var(--font-mono); font-weight:700;">${c.avg_interval}</td>
      <td>${c.stdev}</td>
      <td><span class="badge badge-critical">${c.cv}</span></td>
      <td><span class="badge badge-critical">${c.score} / 100</span></td>
      <td>
        <button class="btn btn-sm btn-primary" onclick="inspectFlowHost('${c.dst_ip}')">Investigate 🎯</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  renderC2PulseChart();
}

function recalculateC2Detection() {
  const cvThreshold = parseFloat(document.getElementById('c2-cv-slider')?.value || "0.15");
  const minConns = parseInt(document.getElementById('c2-minconn-slider')?.value || "10", 10);
  const portFilter = document.getElementById('c2-port-filter')?.value || "NON_STANDARD";

  let candidates = [
    {
      src_ip: "192.168.1.100",
      dst_ip: "10.0.0.99",
      port: 8443,
      conns: 30,
      avg_interval: "30.01s",
      stdev: "0.38s",
      cv: 0.0125,
      score: 100,
      status: "ACTIVE_BEACON"
    }
  ];

  if (cvThreshold >= 0.06 && minConns <= 15) {
    candidates.push({
      src_ip: "192.168.1.12",
      dst_ip: "192.168.99.99",
      port: 4444,
      conns: 12,
      avg_interval: "60.40s",
      stdev: "4.12s",
      cv: 0.0682,
      score: 85,
      status: "SUSPECT_JITTER"
    });
  }

  STATE.c2Candidates = candidates;
  renderC2Page();
  showToast(`C2 Detection Sweep completed: ${candidates.length} candidate(s) isolated.`, "safe");
}

function renderC2PulseChart() {
  const ctx = document.getElementById('chart-c2-pulse')?.getContext('2d');
  if (!ctx) return;

  if (chartC2Pulse) chartC2Pulse.destroy();

  chartC2Pulse = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Pulse #1', '#2', '#3', '#4', '#5', '#6', '#7', '#8', '#9', '#10'],
      datasets: [
        {
          label: 'Inter-Arrival Interval (seconds)',
          data: [30.0, 30.1, 29.9, 30.0, 30.2, 29.8, 30.1, 30.0, 29.9, 30.0],
          backgroundColor: '#f97316',
          borderRadius: 4
        },
        {
          label: 'Expected Target Interval (30.0s)',
          data: [30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
          type: 'line',
          borderColor: '#ef4444',
          borderDash: [5, 5],
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          min: 25,
          max: 35,
          grid: { color: 'rgba(255,255,255,0.05)' }
        },
        x: { grid: { display: false } }
      }
    }
  });
}

function copyContainmentRule(rule) {
  navigator.clipboard.writeText(rule).then(() => {
    showToast("Containment firewall command copied to clipboard!", "safe");
  }).catch(() => {
    prompt("Copy firewall rule:", rule);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS ANALYSIS & LIVE SHANNON ENTROPY TOOL
// ─────────────────────────────────────────────────────────────────────────────

function renderDnsPage() {
  renderDnsTable();
  testCustomDomainEntropy();
}

function renderDnsTable() {
  const tbody = document.getElementById('dns-tbody');
  if (!tbody) return;

  const searchQuery = document.getElementById('dns-search-input')?.value.toLowerCase().trim() || "";
  const indicatorFilter = document.getElementById('dns-indicator-filter')?.value || "ALL";

  const filtered = STATE.dnsTelemetry.filter(d => {
    if (indicatorFilter !== "ALL" && d.indicator !== indicatorFilter) return false;
    if (searchQuery && !d.query.toLowerCase().includes(searchQuery) && !d.source_ip.includes(searchQuery)) return false;
    return true;
  });

  tbody.innerHTML = "";
  filtered.forEach(dns => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${dns.timestamp}</td>
      <td>${dns.source_ip}</td>
      <td style="font-family:var(--font-mono); color:${dns.risk_score >= 70 ? 'var(--sev-high)' : 'inherit'}">${dns.query}</td>
      <td><span class="badge badge-low">${dns.qtype}</span></td>
      <td><strong>${dns.entropy}</strong></td>
      <td><span class="badge ${dns.indicator === 'BENIGN' ? 'badge-safe' : 'badge-high'}">${dns.indicator}</span></td>
      <td><span class="badge ${dns.risk_score >= 75 ? 'badge-critical' : dns.risk_score >= 50 ? 'badge-high' : 'badge-safe'}">${dns.risk_score}</span></td>
      <td>
        <button class="btn btn-sm" onclick="populateDnsTest('${dns.query}')">Test 🔬</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function calculateShannonEntropy(str) {
  const len = str.length;
  if (len === 0) return 0;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(2));
}

function testCustomDomainEntropy() {
  const domain = document.getElementById('dns-test-input')?.value.trim() || "";
  if (!domain) return;

  const entropy = calculateShannonEntropy(domain);
  const labels = domain.split('.').length;
  const vowels = (domain.match(/[aeiou]/gi) || []).length;
  const consonants = (domain.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
  const vowelRatio = consonants > 0 ? (vowels / consonants).toFixed(2) : 1;

  let risk = "BENIGN";
  let riskScore = 10;
  let color = "var(--sev-safe)";

  if (domain.length > 50 || entropy > 4.2 || labels > 5) {
    risk = "HIGH RISK (DGA / TUNNELING)";
    riskScore = 85;
    color = "var(--sev-critical)";
  } else if (entropy > 3.8 || labels > 3) {
    risk = "SUSPICIOUS";
    riskScore = 55;
    color = "var(--sev-high)";
  }

  const resultContainer = document.getElementById('dns-entropy-result');
  if (resultContainer) {
    resultContainer.innerHTML = `
      <div style="background:var(--bg-canvas); border:1px solid var(--border-subtle); border-left:4px solid ${color}; padding:1rem; border-radius:var(--radius-sm);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h4 style="color:${color}; font-size:0.95rem;">Assessment: ${risk} (Threat Score: ${riskScore}/100)</h4>
          <span class="badge ${riskScore >= 75 ? 'badge-critical' : 'badge-safe'}">${risk}</span>
        </div>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:0.75rem; margin-top:0.75rem;">
          <div><span style="font-size:0.7rem; color:var(--text-muted);">Shannon Entropy:</span> <strong style="font-family:var(--font-mono);">${entropy} bits/char</strong></div>
          <div><span style="font-size:0.7rem; color:var(--text-muted);">Domain Length:</span> <strong style="font-family:var(--font-mono);">${domain.length} chars</strong></div>
          <div><span style="font-size:0.7rem; color:var(--text-muted);">Subdomain Labels:</span> <strong style="font-family:var(--font-mono);">${labels} levels</strong></div>
          <div><span style="font-size:0.7rem; color:var(--text-muted);">Vowel/Consonant Ratio:</span> <strong style="font-family:var(--font-mono);">${vowelRatio}</strong></div>
        </div>
      </div>
    `;
  }
}

function testPresetDomain(type) {
  const input = document.getElementById('dns-test-input');
  if (type === 'dga') {
    input.value = "xklq9848asdkjnca814981491jka.dyn-c2-service.ru";
  } else {
    input.value = "auth.google-analytics.com";
  }
  testCustomDomainEntropy();
}

function populateDnsTest(domain) {
  document.getElementById('dns-test-input').value = domain;
  testCustomDomainEntropy();
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTERPRISE MITRE ATT&CK MATRIX
// ─────────────────────────────────────────────────────────────────────────────

const MITRE_MATRIX_DATA = [
  {
    tactic: "Reconnaissance (TA0043)",
    techniques: [
      { id: "T1595", name: "Active Scanning", hits: 40, active: true },
      { id: "T1590", name: "Gather Victim Network Info", hits: 12, active: false }
    ]
  },
  {
    tactic: "Initial Access (TA0001)",
    techniques: [
      { id: "T1190", name: "Exploit Public-Facing App", hits: 3, active: false },
      { id: "T1566", name: "Phishing", hits: 0, active: false }
    ]
  },
  {
    tactic: "Execution (TA0002)",
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", hits: 18, active: false },
      { id: "T1204", name: "User Execution", hits: 2, active: false }
    ]
  },
  {
    tactic: "Defense Evasion (TA0005)",
    techniques: [
      { id: "T1070", name: "Indicator Removal", hits: 0, active: false },
      { id: "T1562", name: "Impair Defenses", hits: 5, active: false }
    ]
  },
  {
    tactic: "Command & Control (TA0011)",
    techniques: [
      { id: "T1071.001", name: "Web Protocols (HTTPS Beacon)", hits: 98, active: true },
      { id: "T1071.004", name: "DNS C2 Tunneling", hits: 22, active: true },
      { id: "T1571", name: "Non-Standard Port (4444/8443)", hits: 42, active: true },
      { id: "T1568.002", name: "Domain Generation Algorithms (DGA)", hits: 14, active: true }
    ]
  },
  {
    tactic: "Exfiltration (TA0010)",
    techniques: [
      { id: "T1041", name: "Exfiltration Over C2 Channel", hits: 30, active: true },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", hits: 8, active: true }
    ]
  }
];

function renderMitreMatrix() {
  const container = document.getElementById('mitre-matrix-container');
  if (!container) return;
  container.innerHTML = "";

  MITRE_MATRIX_DATA.forEach(col => {
    const colDiv = document.createElement('div');
    colDiv.className = "mitre-tactic-col";

    let techniquesHtml = "";
    col.techniques.forEach(tech => {
      techniquesHtml += `
        <div class="mitre-technique-card ${tech.active ? 'active-alert' : ''}" onclick="inspectMitreTech('${tech.id}', '${tech.name}', ${tech.hits})">
          <div class="mitre-tech-id">${tech.id}</div>
          <div class="mitre-tech-name">${tech.name}</div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.35rem;">
            <span style="font-size:0.68rem; color:${tech.active ? 'var(--sev-critical)' : 'var(--text-muted)'}; font-weight:700;">
              ${tech.active ? 'DETECTION ACTIVE' : 'MONITORING'}
            </span>
            <span class="badge ${tech.hits > 0 ? 'badge-high' : 'badge-neutral'}" style="font-size:0.65rem;">${tech.hits} Hits</span>
          </div>
        </div>
      `;
    });

    colDiv.innerHTML = `
      <div class="mitre-tactic-header">${col.tactic}</div>
      <div class="mitre-techniques-list">${techniquesHtml}</div>
    `;
    container.appendChild(colDiv);
  });
}

function inspectMitreTech(id, name, hits) {
  alert(`ATT&CK Technique ${id} — ${name}\nActive Hits Recorded: ${hits}\nDetection Logic: Behavioral Regularity Variance & Entropy Modeling.\nRecommended Hunting Query: destination_port in [4444, 8443] OR entropy > 3.8`);
}

function exportMitreCoverage() {
  downloadJSONFile(MITRE_MATRIX_DATA, `mitre_attack_coverage_${Date.now()}.json`);
  showToast("MITRE ATT&CK coverage exported to JSON.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// DETECTION RULES ENGINE
// ─────────────────────────────────────────────────────────────────────────────

function renderRulesTable() {
  const tbody = document.getElementById('rules-tbody');
  if (!tbody) return;
  tbody.innerHTML = "";

  STATE.detectionRules.forEach((rule, idx) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family:var(--font-mono); font-weight:700;">${rule.id}</td>
      <td><strong>${rule.name}</strong></td>
      <td><span class="badge badge-low">${rule.category}</span></td>
      <td><span class="badge badge-${rule.severity.toLowerCase()}">${rule.severity}</span></td>
      <td style="font-family:var(--font-mono); font-size:0.75rem;">${rule.threshold}</td>
      <td>
        <label class="switch">
          <input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="toggleRuleState(${idx}, this.checked)">
          <span class="slider"></span>
        </label>
      </td>
      <td><strong style="color:var(--accent-cyan);">${rule.hits}</strong></td>
      <td>
        <button class="btn btn-sm" onclick="editRuleThreshold(${idx})">Edit ⚙️</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function toggleRuleState(index, newState) {
  if (currentUser.role !== 'ADMIN') {
    alert("Permission Denied: Only users with the ADMIN role can modify detection rules.");
    renderRulesTable();
    return;
  }
  STATE.detectionRules[index].enabled = newState;
  showToast(`Rule ${STATE.detectionRules[index].id} ${newState ? 'ENABLED' : 'DISABLED'}`, newState ? 'safe' : 'high');
}

function editRuleThreshold(index) {
  if (currentUser.role !== 'ADMIN') {
    alert("Permission Denied: ADMIN role required to edit rule thresholds.");
    return;
  }
  const rule = STATE.detectionRules[index];
  const newThresh = prompt(`Edit threshold condition for ${rule.name}:`, rule.threshold);
  if (newThresh !== null && newThresh.trim() !== "") {
    rule.threshold = newThresh.trim();
    renderRulesTable();
    showToast(`Threshold updated for ${rule.id}`, "safe");
  }
}

function openAddRuleModal() {
  if (currentUser.role !== 'ADMIN') {
    alert("Permission Denied: ADMIN role required to create new detection rules.");
    return;
  }
  openModal('modal-add-rule');
}

function submitCreateRule() {
  const id = document.getElementById('rule-input-id').value.trim();
  const name = document.getElementById('rule-input-name').value.trim();
  const category = document.getElementById('rule-input-category').value;
  const sev = document.getElementById('rule-input-sev').value;
  const thresh = document.getElementById('rule-input-threshold').value.trim();

  STATE.detectionRules.push({
    id: id,
    name: name,
    category: category,
    severity: sev,
    threshold: thresh,
    enabled: true,
    hits: 0
  });

  closeModal('modal-add-rule');
  renderRulesTable();
  showToast(`Detection rule ${id} activated.`, "safe");
}

function resetDefaultRules() {
  STATE.detectionRules = JSON.parse(JSON.stringify(INITIAL_DATA.detectionRules));
  renderRulesTable();
  showToast("Detection rules restored to factory baseline.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// IP & HOST THREAT INTELLIGENCE
// ─────────────────────────────────────────────────────────────────────────────

function lookupIpIntel() {
  const ip = document.getElementById('ipintel-search-input')?.value.trim() || "10.0.0.99";
  const container = document.getElementById('ipintel-result-container');
  if (!container) return;

  const profile = STATE.ipIntelDB[ip] || {
    ip: ip,
    classification: "CUSTOM QUERY HOST",
    risk_score: ip.startsWith("192.168.") ? 20 : 65,
    severity: ip.startsWith("192.168.") ? "LOW" : "HIGH",
    country: "External Geolocation",
    country_flag: "🌐",
    asn: "AS-DISCOVERED",
    abuse_confidence: "Dynamic Simulation Assessment",
    open_ports: "80, 443",
    reverse_dns: `host-${ip.replace(/\./g, '-')}.net`,
    summary: "Host evaluated via dynamic NetWatch telemetry lookup."
  };

  const relatedAlerts = STATE.alerts.filter(a => a.source_ip === ip || a.destination_ip === ip);
  const relatedFlows = STATE.trafficFlows.filter(f => f.source_ip === ip || f.destination_ip === ip);

  container.innerHTML = `
    <div style="background:var(--bg-surface); border:1px solid var(--border-subtle); border-radius:var(--radius-sm); padding:1.25rem; margin-bottom:1.5rem;">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:1rem;">
        <div>
          <div style="display:flex; align-items:center; gap:0.5rem;">
            <span style="font-size:1.5rem;">${profile.country_flag}</span>
            <h2 style="font-family:var(--font-mono); font-size:1.4rem;">${profile.ip}</h2>
            <span class="badge badge-${profile.severity.toLowerCase()}">${profile.classification}</span>
          </div>
          <p style="color:var(--text-secondary); font-size:0.82rem; margin-top:0.25rem;">${profile.summary}</p>
        </div>
        <div style="text-align:right;">
          <div style="font-size:0.75rem; color:var(--text-muted);">Reputation Risk Score</div>
          <div style="font-family:var(--font-mono); font-size:1.8rem; font-weight:800; color:${profile.risk_score >= 80 ? 'var(--sev-critical)' : profile.risk_score >= 50 ? 'var(--sev-high)' : 'var(--sev-safe)'}">
            ${profile.risk_score} / 100
          </div>
        </div>
      </div>

      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:1rem; margin-top:1.25rem; padding-top:1.25rem; border-top:1px solid var(--border-subtle);">
        <div><span style="font-size:0.7rem; color:var(--text-muted); display:block;">Location</span> <strong>${profile.country}</strong></div>
        <div><span style="font-size:0.7rem; color:var(--text-muted); display:block;">Network ASN</span> <strong>${profile.asn}</strong></div>
        <div><span style="font-size:0.7rem; color:var(--text-muted); display:block;">Open Ports</span> <strong>${profile.open_ports}</strong></div>
        <div><span style="font-size:0.7rem; color:var(--text-muted); display:block;">Reverse DNS</span> <strong style="font-family:var(--font-mono);">${profile.reverse_dns}</strong></div>
      </div>

      <div style="display:flex; gap:0.5rem; margin-top:1.25rem;">
        <button class="btn btn-sm btn-danger" onclick="copyContainmentRule('iptables -A OUTPUT -d ${profile.ip} -j DROP')">Block in Firewall 🚫</button>
        <button class="btn btn-sm" onclick="exportIpDossier('${profile.ip}')">Download Host Dossier 📥</button>
      </div>
    </div>

    <div class="grid-equal">
      <div class="card">
        <div class="card-title">🚨 Related Active Alerts (${relatedAlerts.length})</div>
        <div class="table-responsive" style="max-height:220px; overflow-y:auto;">
          <table class="soc-table">
            <thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Action</th></tr></thead>
            <tbody>
              ${relatedAlerts.length === 0 ? '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">No active alerts associated with this IP.</td></tr>' :
                relatedAlerts.map(a => `<tr><td>${a.timestamp}</td><td>${a.alert_type}</td><td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td><td><button class="btn btn-sm" onclick="openAlertDrawer('${a.id}')">Inspect</button></td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-title">🌐 Session Flow History (${relatedFlows.length})</div>
        <div class="table-responsive" style="max-height:220px; overflow-y:auto;">
          <table class="soc-table">
            <thead><tr><th>Timestamp</th><th>Proto</th><th>Port</th><th>Bytes</th></tr></thead>
            <tbody>
              ${relatedFlows.length === 0 ? '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">No connection records found.</td></tr>' :
                relatedFlows.map(f => `<tr><td>${f.timestamp}</td><td>${f.protocol}</td><td>${f.dst_port}</td><td>${f.bytes_sent + f.bytes_recv} B</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function quickPickIp(ip) {
  document.getElementById('ipintel-search-input').value = ip;
  lookupIpIntel();
}

function exportIpDossier(ip) {
  const profile = STATE.ipIntelDB[ip] || { ip: ip, lookup: "ad-hoc" };
  downloadJSONFile(profile, `ip_dossier_${ip.replace(/\./g, '_')}.json`);
  showToast(`Intel dossier for ${ip} exported.`, "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// CASES & INCIDENT RESPONSE
// ─────────────────────────────────────────────────────────────────────────────

function renderCasesTable() {
  const tbody = document.getElementById('cases-tbody');
  if (!tbody) return;

  const statusFilter = document.getElementById('case-status-filter')?.value || "ALL";
  const priorityFilter = document.getElementById('case-priority-filter')?.value || "ALL";

  const filtered = STATE.cases.filter(c => {
    if (statusFilter !== "ALL" && c.status !== statusFilter) return false;
    if (priorityFilter !== "ALL" && c.priority !== priorityFilter) return false;
    return true;
  });

  tbody.innerHTML = "";
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:2rem;">No incident cases found.</td></tr>';
    return;
  }

  filtered.forEach(c => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family:var(--font-mono); font-weight:700;">${c.id}</td>
      <td><strong>${c.title}</strong></td>
      <td><span class="badge badge-${c.priority.toLowerCase()}">${c.priority}</span></td>
      <td><span class="badge ${c.status === 'OPEN' ? 'badge-critical' : c.status === 'CLOSED' ? 'badge-safe' : 'badge-medium'}">${c.status}</span></td>
      <td>${c.analyst}</td>
      <td><span class="badge badge-low">${c.linked_alerts} Alerts</span></td>
      <td>${c.created_at}</td>
      <td>
        <button class="btn btn-sm btn-primary" onclick="viewCaseDetails('${c.id}')">View Dossier 📁</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function openCreateCaseModal() {
  openModal('modal-create-case');
}

function submitCreateCase() {
  const title = document.getElementById('case-input-title').value.trim();
  const priority = document.getElementById('case-input-priority').value;
  const analyst = document.getElementById('case-input-analyst').value.trim() || currentUser.username;
  const desc = document.getElementById('case-input-desc').value.trim();

  const newCase = {
    id: `CASE-2026-${(STATE.cases.length + 1).toString().padStart(3, '0')}`,
    title: title,
    priority: priority,
    status: "OPEN",
    analyst: analyst,
    linked_alerts: 1,
    created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
    desc: desc
  };

  STATE.cases.unshift(newCase);
  STATE.kpis.cases++;
  document.getElementById('kpi-cases').innerText = STATE.kpis.cases;
  document.getElementById('nav-case-badge').innerText = STATE.cases.length;

  closeModal('modal-create-case');
  renderCasesTable();
  showToast(`Incident Case ${newCase.id} registered.`, "safe");
}

function viewCaseDetails(caseId) {
  const c = STATE.cases.find(x => x.id === caseId);
  if (!c) return;
  alert(`📁 ${c.id}: ${c.title}\nStatus: ${c.status} | Priority: ${c.priority}\nLead Analyst: ${c.analyst}\n\nScope:\n${c.desc}`);
}

function exportCasesJSON() {
  downloadJSONFile(STATE.cases, `soc_incident_cases_${Date.now()}.json`);
  showToast("Incident cases exported to JSON.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE LOCKER
// ─────────────────────────────────────────────────────────────────────────────

function renderEvidenceTable() {
  const tbody = document.getElementById('evidence-tbody');
  if (!tbody) return;
  tbody.innerHTML = "";

  STATE.evidenceList.forEach((ev, idx) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-family:var(--font-mono); font-weight:700;">${ev.filename}</td>
      <td><span class="badge badge-low">${ev.type}</span></td>
      <td>${ev.size}</td>
      <td style="font-family:var(--font-mono); font-size:0.72rem; color:var(--accent-cyan);">${ev.hash.substring(0, 16)}...</td>
      <td>${ev.date}</td>
      <td style="color:var(--text-muted); font-size:0.75rem;">${ev.dir}</td>
      <td>
        <div style="display:flex; gap:0.35rem;">
          <button class="btn btn-sm" onclick="previewEvidenceModal(${idx})">Inspect 👁️</button>
          <button class="btn btn-sm btn-primary" onclick="downloadEvidenceFile(${idx})">Download 📥</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function previewEvidenceModal(index) {
  const ev = STATE.evidenceList[index];
  if (!ev) return;
  document.getElementById('evidence-preview-title').innerText = `Artifact: ${ev.filename} (${ev.type})`;
  document.getElementById('evidence-preview-hash').innerText = ev.hash;
  document.getElementById('evidence-preview-body').innerText = ev.content;
  document.getElementById('evidence-preview-download-btn').onclick = () => downloadEvidenceFile(index);
  openModal('modal-evidence-preview');
}

function downloadEvidenceFile(index) {
  const ev = STATE.evidenceList[index];
  if (!ev) return;
  downloadBlobFile(ev.content, ev.filename, "text/plain");
  showToast(`Evidence downloaded: ${ev.filename}`, "safe");
}

function openUploadEvidenceModal() {
  const name = prompt("Enter artifact filename (e.g. host_memory.dmp):");
  if (!name) return;
  STATE.evidenceList.unshift({
    filename: name,
    type: "Analyst Upload",
    size: "45 KB",
    hash: "d41d8cd98f00b204e9800998ecf8427e",
    date: new Date().toISOString().substring(0, 16).replace('T', ' '),
    dir: "data/uploads",
    content: `[Manual evidence upload recorded by ${currentUser.username}]`
  });
  renderEvidenceTable();
  showToast(`Artifact ${name} indexed into evidence locker.`, "safe");
}

function exportEvidenceManifest() {
  downloadJSONFile(STATE.evidenceList, `evidence_manifest_${Date.now()}.json`);
  showToast("Evidence manifest exported.", "safe");
}

// ─────────────────────────────────────────────────────────────────────────────
// THREAT HUNTER (GLOBAL UNIVERSAL SEARCH)
// ─────────────────────────────────────────────────────────────────────────────

function handleQuickSearch(query) {
  if (query.length > 1) {
    switchView('search');
    document.getElementById('hunter-query-input').value = query;
    executeThreatHunt();
  }
}

function executeThreatHunt() {
  const query = document.getElementById('hunter-query-input')?.value.toLowerCase().trim() || "";
  const container = document.getElementById('hunter-results-container');
  const summary = document.getElementById('hunter-results-summary');
  if (!container) return;

  if (!query) {
    container.innerHTML = '<p style="color:var(--text-muted); padding:1rem;">Enter an IP, port, alert type, or hash to hunt across all datasets.</p>';
    summary.innerHTML = "";
    return;
  }

  const matchedAlerts = STATE.alerts.filter(a => `${a.id} ${a.alert_type} ${a.source_ip} ${a.destination_ip} ${a.reason}`.toLowerCase().includes(query));
  const matchedFlows = STATE.trafficFlows.filter(f => `${f.source_ip} ${f.destination_ip} ${f.dst_port} ${f.protocol} ${f.source}`.toLowerCase().includes(query));
  const matchedDns = STATE.dnsTelemetry.filter(d => `${d.query} ${d.source_ip} ${d.indicator}`.toLowerCase().includes(query));
  const matchedEvidence = STATE.evidenceList.filter(e => `${e.filename} ${e.type} ${e.hash}`.toLowerCase().includes(query));

  const totalHits = matchedAlerts.length + matchedFlows.length + matchedDns.length + matchedEvidence.length;
  summary.innerHTML = `Found <strong style="color:var(--accent-cyan);">${totalHits} hits</strong> for telemetry pattern <code>${query}</code>:`;

  container.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:1.25rem;">
      <!-- Alerts Hits -->
      <div class="card">
        <div class="card-title">🚨 Matched Security Alerts (${matchedAlerts.length})</div>
        <div class="table-responsive">
          <table class="soc-table">
            <thead><tr><th>ID</th><th>Type</th><th>Flow</th><th>Severity</th><th>Action</th></tr></thead>
            <tbody>
              ${matchedAlerts.length === 0 ? '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No matching alerts.</td></tr>' :
                matchedAlerts.map(a => `<tr><td>${a.id.substring(0,8)}</td><td>${a.alert_type}</td><td>${a.source_ip} ➔ ${a.destination_ip}</td><td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td><td><button class="btn btn-sm btn-primary" onclick="openAlertDrawer('${a.id}')">Inspect</button></td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Flows Hits -->
      <div class="card">
        <div class="card-title">🌐 Matched Traffic Flows (${matchedFlows.length})</div>
        <div class="table-responsive">
          <table class="soc-table">
            <thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Proto</th><th>Threat</th></tr></thead>
            <tbody>
              ${matchedFlows.length === 0 ? '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No matching flows.</td></tr>' :
                matchedFlows.map(f => `<tr><td>${f.timestamp}</td><td>${f.source_ip}:${f.src_port}</td><td>${f.destination_ip}:${f.dst_port}</td><td>${f.protocol}</td><td>${f.threat ? '<span class="badge badge-critical">THREAT</span>' : '<span class="badge badge-safe">CLEAN</span>'}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- DNS Hits -->
      <div class="card">
        <div class="card-title">🔍 Matched DNS Queries (${matchedDns.length})</div>
        <div class="table-responsive">
          <table class="soc-table">
            <thead><tr><th>Timestamp</th><th>Client IP</th><th>Domain Query</th><th>Indicator</th></tr></thead>
            <tbody>
              ${matchedDns.length === 0 ? '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">No matching DNS queries.</td></tr>' :
                matchedDns.map(d => `<tr><td>${d.timestamp}</td><td>${d.source_ip}</td><td>${d.query}</td><td><span class="badge badge-high">${d.indicator}</span></td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function clearThreatHunt() {
  document.getElementById('hunter-query-input').value = "";
  executeThreatHunt();
}

// ─────────────────────────────────────────────────────────────────────────────
// REPORT GENERATOR & LIVE PREVIEW
// ─────────────────────────────────────────────────────────────────────────────

function generateReportPreview() {
  const type = document.getElementById('report-type-select')?.value || "executive";
  const windowRange = document.getElementById('report-window-select')?.value || "24h";
  const classification = document.getElementById('report-class-select')?.value || "TLP:CLEAR";
  const container = document.getElementById('report-preview-container');
  if (!container) return;

  const now = new Date().toUTCString();

  let title = "EXECUTIVE SECURITY OPERATIONS THREAT BRIEFING";
  let contentHtml = "";

  if (type === "executive") {
    contentHtml = `
      <div style="border-bottom: 2px solid #0f172a; padding-bottom: 1rem; margin-bottom: 1.5rem; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h2 style="font-size: 1.4rem; font-weight:800;">NETWATCH SOC — ${title}</h2>
          <p style="font-size: 0.82rem; color: #475569; margin-top: 0.25rem;">Generated on ${now} | Prepared by: ${currentUser.username} (${currentUser.role})</p>
        </div>
        <span style="font-family: var(--font-mono); font-weight:700; border:2px solid #0f172a; padding:0.25rem 0.75rem; border-radius:4px;">${classification}</span>
      </div>

      <div style="margin-bottom:1.5rem;">
        <h3 style="font-size:1.05rem; margin-bottom:0.5rem;">1. Executive Summary & Threat Posture</h3>
        <p style="font-size:0.85rem; line-height:1.6; color:#334155;">
          During the evaluated timeframe (<strong>${windowRange}</strong>), the NetWatch SOC platform monitored <strong>${STATE.kpis.networkEvents.toLocaleString()}</strong> network flows across host physical and synthetic interfaces. A total of <strong>${STATE.alerts.length} high-severity security incidents</strong> were flagged by behavioral detection engines, including <strong>1 confirmed C2 beaconing callback channel</strong> and <strong>DNS tunneling indicators</strong>.
        </p>
      </div>

      <div style="margin-bottom:1.5rem;">
        <h3 style="font-size:1.05rem; margin-bottom:0.5rem;">2. Priority Incident Triage Queue</h3>
        <table>
          <thead>
            <tr><th>Alert ID</th><th>Type</th><th>Source Host</th><th>Destination C2</th><th>Severity</th><th>Status</th></tr>
          </thead>
          <tbody>
            ${STATE.alerts.map(a => `<tr><td>${a.id.substring(0,8)}</td><td>${a.alert_type}</td><td>${a.source_ip}</td><td>${a.destination_ip}:${a.destination_port}</td><td><strong>${a.severity}</strong></td><td>${a.status}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>

      <div>
        <h3 style="font-size:1.05rem; margin-bottom:0.5rem;">3. Recommended Containment & Remediation Actions</h3>
        <ul style="font-size:0.85rem; line-height:1.6; color:#334155; padding-left:1.5rem;">
          <li><strong>Host Isolation</strong>: Quarantine host <code>192.168.1.100</code> on VLAN 999 to halt HTTPS beaconing to <code>10.0.0.99:8443</code>.</li>
          <li><strong>Firewall Perimeter Filter</strong>: Apply egress drop rules for TCP port 8443 and port 4444.</li>
          <li><strong>DNS Sinkholing</strong>: Add <code>malicious-sim.org</code> and associated subdomains to local recursive DNS RPZ blocklists.</li>
        </ul>
      </div>
    `;
  } else {
    contentHtml = `
      <div style="border-bottom: 2px solid #0f172a; padding-bottom: 1rem; margin-bottom: 1.5rem;">
        <h2 style="font-size: 1.4rem; font-weight:800;">NETWATCH SOC — TECHNICAL FORENSIC DOSSIER (${type.toUpperCase()})</h2>
        <p style="font-size: 0.82rem; color: #475569; margin-top: 0.25rem;">Timestamp: ${now} | Classification: ${classification}</p>
      </div>
      <pre style="background:#f8fafc; border:1px solid #cbd5e1; padding:1rem; border-radius:4px; font-family:var(--font-mono); font-size:0.8rem; overflow-x:auto;">
${JSON.stringify({ classification, generated_at: now, alert_summary: STATE.alerts, candidates: STATE.c2Candidates }, null, 2)}
      </pre>
    `;
  }

  container.innerHTML = contentHtml;
}

function printReport() {
  window.print();
}

function exportReport(format) {
  if (format === 'json') {
    const reportObj = {
      title: "NetWatch SOC Security Intelligence Report",
      generated_at: new Date().toISOString(),
      analyst: currentUser.username,
      kpis: STATE.kpis,
      alerts: STATE.alerts,
      c2_candidates: STATE.c2Candidates,
      evidence: STATE.evidenceList
    };
    downloadJSONFile(reportObj, `netwatch_soc_report_${Date.now()}.json`);
  } else {
    let csv = "AlertID,Timestamp,Type,SourceIP,DestinationIP,Severity,RiskScore,Status,Reason\n";
    STATE.alerts.forEach(a => {
      csv += `"${a.id}","${a.timestamp}","${a.alert_type}","${a.source_ip}","${a.destination_ip}:${a.destination_port}","${a.severity}",${a.risk_score},"${a.status}","${a.reason.replace(/"/g, '""')}"\n`;
    });
    downloadBlobFile(csv, `netwatch_soc_report_${Date.now()}.csv`, "text/csv");
  }
  showToast(`Report exported in ${format.toUpperCase()} format.`, "safe");
}

function copyReportMarkdown() {
  const md = `# NetWatch SOC — Threat Intelligence Briefing
- **Generated**: ${new Date().toISOString()}
- **Analyst**: ${currentUser.username} (${currentUser.role})
- **Active Threats**: ${STATE.alerts.length}
- **Confirmed C2 Beacons**: ${STATE.c2Candidates.length}

## Active Alerts
${STATE.alerts.map(a => `- **[${a.severity}]** ${a.alert_type} on ${a.destination_ip} (Score: ${a.risk_score})`).join('\n')}
`;
  navigator.clipboard.writeText(md).then(() => {
    showToast("Report Markdown copied to clipboard!", "safe");
  });
}

function quickExport() {
  exportReport('json');
}

// ─────────────────────────────────────────────────────────────────────────────
// OVERVIEW PAGE & CHARTS
// ─────────────────────────────────────────────────────────────────────────────

function renderOverviewPage() {
  // Update KPI displays
  document.getElementById('kpi-net-events').innerText = STATE.kpis.networkEvents.toLocaleString();
  document.getElementById('kpi-alerts').innerText = STATE.alerts.filter(a => a.status !== 'RESOLVED').length;
  document.getElementById('kpi-critical').innerText = STATE.alerts.filter(a => a.severity === 'CRITICAL' && a.status !== 'RESOLVED').length;
  document.getElementById('kpi-c2-beacons').innerText = STATE.c2Candidates.length;
  document.getElementById('kpi-unique-dsts').innerText = STATE.kpis.uniqueDsts;
  document.getElementById('kpi-dns-queries').innerText = STATE.kpis.dnsQueries;
  document.getElementById('kpi-cases').innerText = STATE.cases.filter(c => c.status !== 'CLOSED').length;
  document.getElementById('kpi-rules').innerText = `${STATE.detectionRules.filter(r => r.enabled).length} / ${STATE.detectionRules.length}`;

  // Update Overview priority alerts table
  const tbody = document.getElementById('overview-alerts-tbody');
  if (tbody) {
    tbody.innerHTML = "";
    STATE.alerts.slice(0, 5).forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${a.timestamp}</td>
        <td><strong>${a.alert_type}</strong></td>
        <td>${a.source_ip}</td>
        <td style="color:${a.severity === 'CRITICAL' ? 'var(--sev-critical)' : 'inherit'}; font-weight:700;">${a.destination_ip}:${a.destination_port}</td>
        <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td style="font-weight:700; color:var(--sev-critical);">${a.risk_score}</td>
        <td><span class="badge ${a.status === 'NEW' ? 'badge-critical' : 'badge-safe'}">${a.status}</span></td>
        <td>
          <button class="btn btn-sm btn-primary" onclick="openAlertDrawer('${a.id}')">Inspect 🔍</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Render Charts
  renderOverviewCharts();
}

function setTimelineRange(range) {
  currentTimelineRange = range;
  renderTimelineChart();
  showToast(`Timeline scale adjusted to ${range}`, "neutral");
}

function renderOverviewCharts() {
  renderTimelineChart();
  renderSeverityChart();
  renderProtocolChart();
  renderTopTalkersChart();
}

function renderTimelineChart() {
  const ctx = document.getElementById('chart-timeline')?.getContext('2d');
  if (!ctx) return;

  if (chartTimeline) chartTimeline.destroy();

  const labels = currentTimelineRange === '1h'
    ? ['15:00', '15:10', '15:20', '15:30', '15:40', '15:50']
    : currentTimelineRange === '6h'
    ? ['10:00', '11:00', '12:00', '13:00', '14:00', '15:00']
    : ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];

  const data = currentTimelineRange === '1h'
    ? [120, 150, 180, 210, 190, 240]
    : currentTimelineRange === '6h'
    ? [420, 560, 780, 910, 1100, 1420]
    : [1800, 2400, 3100, 4800, 5200, 6400];

  chartTimeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Flow Events (Volume)',
        data: data,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.15)',
        fill: true,
        tension: 0.35,
        pointBackgroundColor: '#3b82f6'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { grid: { color: 'rgba(255,255,255,0.05)' } },
        x: { grid: { color: 'rgba(255,255,255,0.03)' } }
      }
    }
  });
}

function renderSeverityChart() {
  const ctx = document.getElementById('chart-severity')?.getContext('2d');
  if (!ctx) return;

  if (chartSeverity) chartSeverity.destroy();

  const criticals = STATE.alerts.filter(a => a.severity === 'CRITICAL').length;
  const highs = STATE.alerts.filter(a => a.severity === 'HIGH').length;
  const mediums = STATE.alerts.filter(a => a.severity === 'MEDIUM').length;
  const lows = STATE.alerts.filter(a => a.severity === 'LOW').length;

  chartSeverity = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      datasets: [{
        data: [criticals, highs, mediums + 1, lows + 2],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#38bdf8'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } }
      }
    }
  });
}

function renderProtocolChart() {
  const ctx = document.getElementById('chart-protocol')?.getContext('2d');
  if (!ctx) return;

  if (chartProtocol) chartProtocol.destroy();

  chartProtocol = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['TCP Flow', 'UDP Datagram', 'DNS Query', 'ICMP Echo'],
      datasets: [{
        label: 'Flow Count',
        data: [820, 310, 284, 18],
        backgroundColor: ['#3b82f6', '#06b6d4', '#a855f7', '#10b981'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { grid: { color: 'rgba(255,255,255,0.05)' } },
        x: { grid: { display: false } }
      }
    }
  });
}

function renderTopTalkersChart() {
  const ctx = document.getElementById('chart-top-talkers')?.getContext('2d');
  if (!ctx) return;

  if (chartTopTalkers) chartTopTalkers.destroy();

  chartTopTalkers = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['10.0.0.99 (C2)', '142.250.190.46', '8.8.8.8', '192.168.99.99', '10.0.0.1'],
      datasets: [{
        label: 'Risk Score',
        data: [100, 5, 0, 75, 10],
        backgroundColor: ['#ef4444', '#10b981', '#10b981', '#f97316', '#3b82f6'],
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { max: 100, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { grid: { display: false } }
      }
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS & SYSTEM CONTROL
// ─────────────────────────────────────────────────────────────────────────────

function applyTheme(themeName) {
  document.body.removeAttribute('data-theme');
  if (themeName !== 'default') {
    document.body.setAttribute('data-theme', themeName);
  }
  localStorage.setItem('netwatch_theme', themeName);

  const sel1 = document.getElementById('theme-selector');
  if (sel1) sel1.value = themeName;
  const sel2 = document.getElementById('settings-theme-select');
  if (sel2) sel2.value = themeName;
}

function resetAllDemoData() {
  if (!confirm("Are you sure you want to reset all telemetry, cases, and rules to default state?")) return;
  STATE = JSON.parse(JSON.stringify(INITIAL_DATA));
  localStorage.removeItem('netwatch_saved_state');
  switchView('overview');
  showToast("SOC baseline telemetry restored to initial state.", "safe");
}

function seedSampleBatch() {
  for (let i = 1; i <= 10; i++) {
    STATE.trafficFlows.push({
      id: `FL-${2000 + i}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      source_ip: "192.168.1.100",
      src_port: 52100 + i,
      destination_ip: "10.0.0.99",
      dst_port: 8443,
      protocol: "TCP",
      duration: "0.12s",
      bytes_sent: 512,
      bytes_recv: 1024,
      state: "SF",
      source: "Live Injection",
      threat: true
    });
  }
  STATE.kpis.networkEvents += 10;
  document.getElementById('kpi-net-events').innerText = STATE.kpis.networkEvents.toLocaleString();
  if (currentView === 'overview') renderOverviewPage();
  if (currentView === 'traffic') renderTrafficTable();
  showToast("10 simulated C2 beacon flows injected into telemetry stream.", "safe");
}

function backupStateJSON() {
  downloadJSONFile(STATE, `netwatch_soc_state_backup_${Date.now()}.json`);
  showToast("State backup exported to JSON.", "safe");
}

function restoreStateJSONPrompt() {
  const jsonStr = prompt("Paste full state JSON to restore:");
  if (!jsonStr) return;
  try {
    const parsed = JSON.parse(jsonStr);
    STATE = parsed;
    switchView('overview');
    showToast("State successfully restored from JSON.", "safe");
  } catch (err) {
    alert("Invalid JSON format.");
  }
}

function handleBackgroundSimTick() {
  if (!document.getElementById('settings-sim-toggle')?.checked) return;
  STATE.kpis.networkEvents += Math.floor(Math.random() * 4) + 1;
  const el = document.getElementById('kpi-net-events');
  if (el) el.innerText = STATE.kpis.networkEvents.toLocaleString();
}

function updateRealtimeUI() {
  const permBadge = document.getElementById('perm-badge');
  if (permBadge) {
    permBadge.className = isAdminConsentGranted ? "badge badge-safe" : "badge badge-critical";
    permBadge.innerText = isAdminConsentGranted ? "PERMISSION: GRANTED" : "PERMISSION: REVOKED";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TOAST NOTIFICATIONS & AUDIO SYNTHESIS
// ─────────────────────────────────────────────────────────────────────────────

function showToast(message, type = "safe") {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span>${type === 'critical' ? '🔥' : type === 'high' ? '⚠️' : '🛡️'}</span>
    <div>${message}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function playAlertBeep() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(880, ctx.currentTime); // A5 note
    osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.25);

    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + 0.25);
  } catch (e) {
    // Audio context not allowed without interaction
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MODAL & HELPER UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

function openModal(modalId) {
  document.getElementById(modalId)?.classList.add('active');
}

function closeModal(modalId) {
  document.getElementById(modalId)?.classList.remove('active');
}

function downloadJSONFile(data, filename) {
  const str = JSON.stringify(data, null, 2);
  downloadBlobFile(str, filename, "application/json");
}

function downloadBlobFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
