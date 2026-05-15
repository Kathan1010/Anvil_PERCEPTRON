// KAVACH SOC Agent Engine - Real Backend Connection

const SCENARIO_MAPPING = {
  malware: 'malware_hash',
  suspicious_ip: 'suspicious_ip',
  phishing: 'phishing_email',
  cve: 'cve_exploit'
};

const SCENARIO_TITLES = {
  malware_hash: { title: 'Malware Hash Detected', severity: 'critical' },
  suspicious_ip: { title: 'Suspicious IP Login Detected', severity: 'high' },
  phishing_email: { title: 'Phishing Email IOC', severity: 'high' },
  cve_exploit: { title: 'CVE Exploitation Attempt', severity: 'critical' }
};

let isRunning = false;
let currentWs = null;

function now() { return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }); }

function addStreamMsg(agent, text, type = '') {
  const stream = document.getElementById('agent-stream');
  if (!stream) return;
  const idle = stream.querySelector('.stream-idle');
  if (idle) idle.remove();
  const div = document.createElement('div');
  div.className = `stream-msg ${agent} ${type}`;
  div.innerHTML = `<span class="agent-name">${agent.toUpperCase()}</span><span class="msg-text">${text}</span>`;
  stream.appendChild(div);
  stream.scrollTop = stream.scrollHeight;
}

function addTimelineStep(title, status = 'active') {
  const body = document.getElementById('timeline-body');
  if (!body) return;
  const empty = body.querySelector('.timeline-empty');
  if (empty) empty.remove();
  const div = document.createElement('div');
  div.className = 'tl-step';
  div.innerHTML = `<div class="tl-dot ${status}"></div><div class="tl-info"><div class="tl-title">${title}</div><div class="tl-time">${now()}</div></div>`;
  body.appendChild(div);
  return div;
}

function completeTimelineStep(stepEl) {
  if (!stepEl) return;
  const dot = stepEl.querySelector('.tl-dot');
  if (dot) { dot.classList.remove('active'); dot.classList.add('done'); }
}

function setConfidence(value) {
  const fill = document.getElementById('conf-fill');
  const display = document.getElementById('conf-value');
  if (!fill || !display) return;
  const circumference = 2 * Math.PI * 52;
  const dashLen = (value / 100) * circumference;
  fill.setAttribute('stroke-dasharray', `${dashLen} ${circumference}`);
  if (value >= 90) fill.setAttribute('stroke', '#22c55e');
  else if (value >= 70) fill.setAttribute('stroke', '#f59e0b');
  else fill.setAttribute('stroke', '#ef4444');
  display.textContent = `${value}%`;
}

function addEvidence(source, text) {
  const list = document.getElementById('evidence-list');
  if (!list) return;
  const empty = list.querySelector('.evidence-empty');
  if (empty) empty.remove();
  const div = document.createElement('div');
  div.className = 'evidence-item';
  div.innerHTML = `<span class="evidence-source">${source}</span><span class="evidence-text">${text}</span>`;
  list.appendChild(div);
}

function activateMitre(tactics) {
  tactics.forEach(t => {
    const el = document.querySelector(`.mitre-tactic[data-tactic="${t}"]`);
    if (el) el.classList.add('active');
  });
}

function addAlert(scenarioKey) {
  const list = document.getElementById('alert-list');
  const counter = document.getElementById('alert-count');
  if (!list) return;
  const empty = list.querySelector('.alert-empty');
  if (empty) empty.remove();
  const meta = SCENARIO_TITLES[scenarioKey] || { title: 'Unknown Alert', severity: 'high' };
  const div = document.createElement('div');
  div.className = 'alert-item';
  div.innerHTML = `<div class="alert-severity ${meta.severity}"></div><div class="alert-text">${meta.title}</div><div class="alert-time">${now()}</div>`;
  list.prepend(div);
  if (counter) counter.textContent = list.children.length;
}

function updateMetrics(data) {
  const mttr = document.getElementById('metric-mttr');
  const inc = document.getElementById('metric-incidents');
  const threat = document.getElementById('metric-threat');
  const auto = document.getElementById('metric-auto');
  if (mttr && data.mttr) mttr.textContent = data.mttr;
  if (inc && data.incidents !== undefined) inc.textContent = data.incidents;
  if (threat && data.threat) { threat.textContent = data.threat; threat.className = `metric-value threat-level ${data.threat.toLowerCase()}`; }
  if (auto && data.auto) auto.textContent = data.auto;
}

function setStreamStatus(text, active = true) {
  const el = document.getElementById('stream-status');
  if (!el) return;
  el.textContent = text;
  el.className = `stream-status${active ? ' active' : ''}`;
}

function showApproval(reason) {
  return new Promise(resolve => {
    const panel = document.getElementById('approval-panel');
    const reasonEl = document.getElementById('approval-reason');
    const btnApprove = document.getElementById('btn-approve');
    const btnReject = document.getElementById('btn-reject');
    if (!panel) { resolve(true); return; }

    panel.classList.remove('hidden');
    if (reasonEl) reasonEl.textContent = reason;

    const cleanup = (result) => {
      panel.classList.add('hidden');
      btnApprove.removeEventListener('click', onApprove);
      btnReject.removeEventListener('click', onReject);
      resolve(result);
    };
    const onApprove = () => cleanup(true);
    const onReject = () => cleanup(false);
    btnApprove.addEventListener('click', onApprove);
    btnReject.addEventListener('click', onReject);
  });
}

// ===== MAIN PIPELINE =====
export async function runPipeline(scenarioBtnKey) {
  if (isRunning) return;
  isRunning = true;
  resetUI();
  
  const backendScenario = SCENARIO_MAPPING[scenarioBtnKey] || 'malware_hash';
  addAlert(backendScenario);
  setStreamStatus('Connecting...', true);

  try {
    // 1. Trigger Backend
    const res = await fetch("http://localhost:8000/api/demo/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: backendScenario })
    });
    const data = await res.json();
    if (!data.incident_id) {
      addStreamMsg('system', 'Error triggering pipeline: No incident ID returned', 'error');
      isRunning = false;
      return;
    }
    const incidentId = data.incident_id;

    // 2. Connect WebSocket
    if (currentWs) currentWs.close();
    currentWs = new WebSocket("ws://localhost:8000/ws");
    
    let currentStepEl = null;
    let startTime = Date.now();

    currentWs.onopen = () => {
      setStreamStatus('Processing', true);
      currentWs.send(JSON.stringify({ type: "subscribe", incident_id: incidentId }));
      currentStepEl = addTimelineStep('Pipeline Started');
    };

    currentWs.onmessage = async (event) => {
      const msg = JSON.parse(event.data);
      
      if (msg.type === "agent_update") {
        let textType = '';
        if (msg.message && msg.message.includes("✅")) textType = 'success';
        else if (msg.message && msg.message.includes("❌")) textType = 'error';
        else textType = 'tool';
        
        addStreamMsg(msg.agent || 'system', msg.message || JSON.stringify(msg.data), textType);

        // Update UI based on agent progress
        if (msg.agent === 'investigation' && msg.data) {
          if (msg.data.confidence !== undefined) setConfidence(Math.round(msg.data.confidence * 100));
          if (msg.data.mitre_techniques) activateMitre(msg.data.mitre_techniques.map(t => t.toLowerCase()));
          if (msg.data.findings) addEvidence('Investigation', msg.data.findings.substring(0, 100) + '...');
        }
        if (msg.agent === 'enrichment' && msg.data && msg.data.summary) {
          addEvidence('Enrichment', msg.data.summary);
        }
      } 
      else if (msg.type === "status_change") {
        if (currentStepEl) completeTimelineStep(currentStepEl);
        
        const status = msg.data ? msg.data.status : msg.status;
        const statusMap = {
          new: "Incident Created",
          triage: "Triage & Classification",
          enriched: "Parallel Enrichment",
          enrichment: "Parallel Enrichment",
          investigation: "Deep Investigation",
          awaiting_approval: "Human Approval Required",
          remediation: "Containment & Remediation",
          reporting: "Incident Reporting",
          monitoring: "Continuous Monitoring",
          monitor: "Monitor-Only Mode",
          resolved: "Incident Resolved"
        };
        
        const stepName = statusMap[status] || (status || 'UNKNOWN').toUpperCase();
        currentStepEl = addTimelineStep(stepName);
        
        if (status === "awaiting_approval") {
          addStreamMsg('decision', '⚠️ Human approval required for containment actions.');
          const approved = await showApproval("The system requires human approval before executing containment actions.");
          
          if (approved) {
            addStreamMsg('decision', '✅ Analyst approved', 'success');
            fetch(`http://localhost:8000/api/incidents/${incidentId}/approve`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ approved: true, analyst_notes: "Approved via dashboard" })
            });
          } else {
            addStreamMsg('decision', '❌ Analyst rejected', 'error');
            fetch(`http://localhost:8000/api/incidents/${incidentId}/approve`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ approved: false, analyst_notes: "Rejected via dashboard" })
            });
          }
        }
        
        if (msg.data && (msg.data.status === "resolved" || msg.data.status === "monitoring" || msg.data.status === "monitor")) {
          setStreamStatus('Complete', false);
          completeTimelineStep(currentStepEl);
          const duration = Math.round((Date.now() - startTime) / 1000);
          updateMetrics({ mttr: `${duration}s`, incidents: '1', auto: msg.data.status === 'resolved' ? '100%' : '0%' });
          currentWs.close();
          isRunning = false;
        }
      }
    };
    
    currentWs.onerror = () => {
      addStreamMsg('system', 'WebSocket connection error. Is the backend running?', 'error');
      isRunning = false;
    };
    
    currentWs.onclose = () => {
      isRunning = false;
    };

  } catch (err) {
    addStreamMsg('system', 'Failed to reach backend API.', 'error');
    isRunning = false;
  }
}

export function resetUI() {
  const stream = document.getElementById('agent-stream');
  if (stream) stream.innerHTML = '<div class="stream-idle"><div class="idle-bot"><div class="idle-bot-face"><div class="idle-eye l"></div><div class="idle-eye r"></div></div></div><p>Awaiting incoming alerts...</p><p class="stream-hint">Click a threat scenario above to begin</p></div>';

  const tl = document.getElementById('timeline-body');
  if (tl) tl.innerHTML = '<div class="timeline-empty">No active incident</div>';

  const ev = document.getElementById('evidence-list');
  if (ev) ev.innerHTML = '<div class="evidence-empty">No evidence collected yet</div>';

  const fill = document.getElementById('conf-fill');
  const val = document.getElementById('conf-value');
  if (fill) fill.setAttribute('stroke-dasharray', '0 327');
  if (val) val.textContent = '—';

  document.querySelectorAll('.mitre-tactic').forEach(el => el.classList.remove('active'));

  const ap = document.getElementById('approval-panel');
  if (ap) ap.classList.add('hidden');

  setStreamStatus('Idle', false);
  updateMetrics({ mttr: '—', incidents: '0', threat: 'LOW', auto: '0%' });
}

export function initPreviewStream() {
  const container = document.getElementById('preview-stream');
  if (!container) return;

  const lines = [
    { agent: 'TRIAGE', msg: 'Alert received — Malware hash detected', color: 'var(--color-neon-cyan)' },
    { agent: 'ENRICHMENT', msg: 'Querying VirusTotal... 47/72 detections', color: 'var(--color-neon-purple)' },
    { agent: 'ENRICHMENT', msg: 'AbuseIPDB: 92% abuse confidence', color: 'var(--color-neon-purple)' },
    { agent: 'INVESTIGATE', msg: 'MITRE: T1566.001 Spearphishing', color: 'var(--color-neon-amber)' },
    { agent: 'DECISION', msg: '✅ Confidence 94% — Auto-remediating', color: '#3b82f6' },
    { agent: 'REMEDIATE', msg: '🔒 IP blocked, Slack notified', color: 'var(--color-neon-red)' },
    { agent: 'REPORT', msg: '📋 Incident report generated', color: 'var(--color-neon-green)' },
  ];

  let i = 0;
  function addLine() {
    if (i >= lines.length) { i = 0; container.innerHTML = ''; }
    const line = lines[i];
    const div = document.createElement('div');
    div.className = 'preview-line';
    div.innerHTML = `<span class="preview-agent" style="color:${line.color}">[${line.agent}]</span><span class="preview-msg">${line.msg}</span>`;
    container.appendChild(div);
    if (container.children.length > 7) container.removeChild(container.firstChild);
    i++;
  }
  setInterval(addLine, 2000);
  addLine();
}
