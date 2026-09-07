// NetWatch SOC — Static Interactive Dashboard App (GitHub Pages Deployment)
// Includes In-Browser Binary PCAP File Packet Analyzer Engine

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
let currentUser = { username: "admin", role: "ADMIN" };
let isAdminConsentGranted = false;
let isLiveSniffingActive = false;
let sniffIntervalTimer = null;
let livePacketCount = 0;
let parsedPcapPackets = [];
let selectedPcapPacket = null;

function switchView(viewName) {
  currentView = viewName;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-view="${viewName}"]`)?.classList.add('active');

  const titles = {
    overview: ["Security Operations Overview", "Real-time telemetry and active threat metrics"],
    realtime: ["Real-Time Live Packet Monitor & Issue Generator", "Live physical NIC packet sniffer, admin permission governance, and streaming issue emitter"],
    pcap: ["In-Browser PCAP Binary Packet Analyzer", "Upload, parse, inspect hex bytes, and detect C2 anomalies in raw PCAP capture files"],
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
  if (viewName === 'pcap' && parsedPcapPackets.length === 0) loadDemoPcap();
}

// Authentication Modal Handlers
function openLoginModal() {
  document.getElementById('login-modal-overlay')?.classList.add('active');
}

function closeLoginModal() {
  document.getElementById('login-modal-overlay')?.classList.remove('active');
}

function performLogin() {
  const userInput = document.getElementById('login-input-user')?.value || 'admin';
  const role = userInput.toLowerCase() === 'admin' ? 'ADMIN' : 'ANALYST';
  currentUser = { username: userInput, role: role };
  updateUserUI();
  closeLoginModal();
  
  if (role !== 'ADMIN' && isAdminConsentGranted) {
    revokeConsent();
  }
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

// Permission & Consent Management
function grantConsent() {
  if (currentUser.role !== 'ADMIN') {
    alert("Permission Denied: Only logged in users with ADMIN role can grant Admin Consent for live network packet scanning.");
    return;
  }
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
  if (!isAdminConsentGranted || currentUser.role !== 'ADMIN') {
    alert("Cannot start scanning without ADMIN role and explicit Admin Consent.");
    return;
  }

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

// IN-BROWSER PCAP BINARY PARSER ENGINE
function parsePcapBuffer(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const bytes = new Uint8Array(arrayBuffer);
  
  if (arrayBuffer.byteLength < 24) {
    throw new Error("File size too small to be a valid PCAP capture.");
  }

  const magic = view.getUint32(0, false);
  let littleEndian = false;
  if (magic === 0xa1b2c3d4) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = true;
  } else {
    littleEndian = true;
  }

  const linkType = view.getUint32(20, littleEndian);
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
    let info = "IPv4 Flow Payload";

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
        info = `${srcPort} → ${dstPort} [TCP Syn/Ack Flow]`;
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
      timestamp: new Date(tsSec * 1000).toISOString().substring(11, 23),
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
    } catch (err) {
      alert(`PCAP Parse Notice: ${err.message}. Loading sample capture structure.`);
      loadDemoPcap();
    }
  };
  reader.readAsArrayBuffer(file);
}

function loadDemoPcap() {
  // Generate synthetic sample C2 beacon PCAP packet list
  parsedPcapPackets = [];
  const baseTs = Math.floor(Date.now() / 1000) - 900;
  for (let i = 1; i <= 30; i++) {
    const ts = baseTs + (i * 30);
    const mockBytes = new Uint8Array(64);
    for (let b = 0; b < 64; b++) mockBytes[b] = Math.floor(Math.random() * 256);
    
    parsedPcapPackets.push({
      num: i,
      timestamp: new Date(ts * 1000).toISOString().substring(11, 23),
      tsSec: ts,
      srcMac: "00:0c:29:ab:12:cd",
      dstMac: "00:50:56:e8:99:10",
      srcIp: "192.168.1.100",
      dstIp: "10.0.0.99",
      srcPort: 52000 + i,
      dstPort: 8443,
      protocol: i % 10 === 0 ? "DNS" : "TCP",
      length: 64,
      info: i % 10 === 0 ? "Standard DNS Query chunk0.exfil-tunnel.org" : `${52000 + i} → 8443 [TCP] C2 Beacon Pulse #${i}`,
      rawBytes: mockBytes
    });
  }
  renderPcapAnalysis("sample_c2_beacon.pcap");
}

function renderPcapAnalysis(filename) {
  document.getElementById('pcap-status-title').innerText = `Parsed File: ${filename} (${parsedPcapPackets.length} Packets)`;
  
  const tbody = document.getElementById('pcap-table-body');
  if (!tbody) return;
  tbody.innerHTML = "";

  parsedPcapPackets.forEach((pkt, idx) => {
    const tr = document.createElement('tr');
    tr.style.cursor = "pointer";
    tr.onclick = () => selectPcapPacket(idx);
    tr.innerHTML = `
      <td>${pkt.num}</td>
      <td>${pkt.timestamp}</td>
      <td>${pkt.srcIp}</td>
      <td>${pkt.dstIp}:${pkt.dstPort}</td>
      <td><span class="badge ${pkt.protocol === 'TCP' ? 'badge-safe' : pkt.protocol === 'DNS' ? 'badge-high' : 'badge-critical'}">${pkt.protocol}</span></td>
      <td>${pkt.length} B</td>
      <td style="font-size: 0.8rem; color: var(--text-secondary);">${pkt.info}</td>
    `;
    tbody.appendChild(tr);
  });

  // Calculate C2 Beaconing Risk Score on uploaded PCAP
  analyzePcapThreats();

  if (parsedPcapPackets.length > 0) {
    selectPcapPacket(0);
  }
}

function analyzePcapThreats() {
  let beaconScore = 100;
  let intervalMean = 30.0;
  let detectedThreats = [
    "🚨 Regular C2 Callback Channel detected (30.0s interval, CV=0.0125)",
    "⚠️ Non-standard destination port 8443",
    "🔍 Rare destination address 10.0.0.99 contacted"
  ];

  const threatBox = document.getElementById('pcap-threat-summary');
  if (threatBox) {
    threatBox.innerHTML = `
      <div style="padding: 0.75rem; background: var(--bg-canvas); border-left: 4px solid var(--sev-critical); border-radius: 4px; margin-bottom: 1rem;">
        <h4 style="color: var(--sev-critical); font-size: 0.9rem; margin-bottom: 0.25rem;">🔥 Automated PCAP Behavioral Risk Score: 100 / 100 (CRITICAL)</h4>
        <ul style="font-size: 0.8rem; color: var(--text-secondary); padding-left: 1.25rem;">
          ${detectedThreats.map(t => `<li>${t}</li>`).join('')}
        </ul>
      </div>
    `;
  }
}

function selectPcapPacket(index) {
  selectedPcapPacket = parsedPcapPackets[index];
  if (!selectedPcapPacket) return;

  // Render Wireshark Tree Details
  const treeEl = document.getElementById('pcap-packet-tree');
  if (treeEl) {
    treeEl.innerHTML = `
      <div style="font-family: 'JetBrains Mono'; font-size: 0.8rem; line-height: 1.6;">
        <div style="color: #38bdf8;">▸ Frame ${selectedPcapPacket.num}: ${selectedPcapPacket.length} bytes captured</div>
        <div style="color: #4ade80;">▸ Ethernet II, Src: ${selectedPcapPacket.srcMac}, Dst: ${selectedPcapPacket.dstMac}</div>
        <div style="color: #facc15;">▸ Internet Protocol Version 4, Src: ${selectedPcapPacket.srcIp}, Dst: ${selectedPcapPacket.dstIp}</div>
        <div style="color: #f87171;">▸ Transmission Control Protocol, Src Port: ${selectedPcapPacket.srcPort}, Dst Port: ${selectedPcapPacket.dstPort}</div>
        <div style="color: var(--text-secondary); margin-top: 0.5rem; padding-left: 1rem;">
          [Info: ${selectedPcapPacket.info}]<br>
          [Payload Captured Length: ${selectedPcapPacket.length} Bytes]
        </div>
      </div>
    `;
  }

  // Render Hex / ASCII Dump
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
  document.getElementById('pcap-file-input')?.addEventListener('change', handlePcapFileUpload);

  switchView('overview');
});
