// SOC Agent Pipeline Simulation Engine
// Simulates the full multi-agent autonomous incident response workflow

const SCENARIOS = {
  malware: {
    alert: { type: 'malware_hash', severity: 'critical', title: 'Malware Hash Detected', ioc: 'e99a18c428cb38d5f260853678922e03', source: 'EDR Agent' },
    enrichment: {
      vt: { positives: 47, total: 72, malware_family: 'Emotet', first_seen: '2024-03-15' },
      abuse: { confidence: 92, reports: 340, country: 'RU', isp: 'Bulletproof Hosting Ltd' },
      cve: null,
      intel: { references: 3, summary: 'Known Emotet dropper variant, linked to ransomware campaigns' }
    },
    mitre: ['initial-access', 'execution', 'persistence', 'c2'],
    techniques: ['T1566.001 Spearphishing', 'T1059.001 PowerShell', 'T1547.001 Registry Run Keys', 'T1071.001 Web Protocols'],
    confidence: 0.94,
    decision: 'auto_remediate',
    actions: ['block_ip', 'slack_alert', 'create_ticket']
  },
  suspicious_ip: {
    alert: { type: 'suspicious_ip', severity: 'high', title: 'Suspicious IP Login Detected', ioc: '45.33.32.156', source: 'SIEM' },
    enrichment: {
      vt: { reputation: -15, malicious_count: 23, country: 'CN', as_owner: 'AS4134 ChinaNet' },
      abuse: { confidence: 78, reports: 156, country: 'CN', isp: 'ChinaNet' },
      cve: null,
      intel: { references: 5, summary: 'IP associated with brute-force campaigns and credential stuffing' }
    },
    mitre: ['initial-access', 'credential-access', 'lateral-movement', 'discovery'],
    techniques: ['T1110.001 Password Guessing', 'T1078 Valid Accounts', 'T1021 Remote Services'],
    confidence: 0.82,
    decision: 'request_approval',
    actions: ['block_ip', 'slack_alert']
  },
  phishing: {
    alert: { type: 'phishing', severity: 'high', title: 'Phishing Email IOC', ioc: 'login-secure-update.com', source: 'Email Gateway' },
    enrichment: {
      vt: { reputation: -20, categories: ['phishing', 'malware'], last_analysis: '12/72 malicious' },
      abuse: { confidence: 65, reports: 42, country: 'US', isp: 'Cloudflare' },
      cve: null,
      intel: { references: 2, summary: 'Domain registered 3 days ago, mimicking corporate login portal' }
    },
    mitre: ['initial-access', 'credential-access', 'collection'],
    techniques: ['T1566.002 Spearphishing Link', 'T1056.001 Keylogging', 'T1114 Email Collection'],
    confidence: 0.73,
    decision: 'request_approval',
    actions: ['slack_alert', 'create_ticket']
  },
  cve: {
    alert: { type: 'cve_exploit', severity: 'critical', title: 'CVE Exploitation Attempt', ioc: 'CVE-2024-3400', source: 'IDS' },
    enrichment: {
      vt: null,
      abuse: { confidence: 88, reports: 520, country: 'KP', isp: 'Unknown' },
      cve: { id: 'CVE-2024-3400', cvss: 10.0, severity: 'CRITICAL', description: 'PAN-OS GlobalProtect command injection' },
      intel: { references: 8, summary: 'Actively exploited in the wild. Patch available from Palo Alto Networks.' }
    },
    mitre: ['initial-access', 'execution', 'priv-escalation', 'defense-evasion', 'c2'],
    techniques: ['T1190 Exploit Public App', 'T1059.004 Unix Shell', 'T1068 Exploitation for Privilege Escalation'],
    confidence: 0.97,
    decision: 'auto_remediate',
    actions: ['block_ip', 'slack_alert', 'create_ticket']
  }
};

let isRunning = false;
let currentIncident = null;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function now() { return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }); }

function addStreamMsg(agent, text, type = '') {
  const stream = document.getElementById('agent-stream');
  if (!stream) return;
  // Remove idle state
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

function addAlert(scenario) {
  const list = document.getElementById('alert-list');
  const counter = document.getElementById('alert-count');
  if (!list) return;
  const empty = list.querySelector('.alert-empty');
  if (empty) empty.remove();
  const div = document.createElement('div');
  div.className = 'alert-item';
  div.innerHTML = `<div class="alert-severity ${scenario.alert.severity}"></div><div class="alert-text">${scenario.alert.title}</div><div class="alert-time">${now()}</div>`;
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
export async function runPipeline(scenarioKey) {
  if (isRunning) return;
  isRunning = true;
  const scenario = SCENARIOS[scenarioKey];
  if (!scenario) { isRunning = false; return; }

  resetUI();
  setStreamStatus('Processing', true);
  updateMetrics({ threat: scenario.alert.severity === 'critical' ? 'HIGH' : 'MEDIUM' });
  addAlert(scenario);

  // === PHASE 1: TRIAGE ===
  const step1 = addTimelineStep('Triage — Alert Classification');
  addStreamMsg('triage', `🛡️ Alert received: ${scenario.alert.title}`);
  await sleep(800);
  addStreamMsg('triage', `Classifying severity... Source: ${scenario.alert.source}`);
  await sleep(600);
  addStreamMsg('triage', `IOC identified: ${scenario.alert.ioc}`, 'tool');
  await sleep(500);
  addStreamMsg('triage', `⚡ Severity: ${scenario.alert.severity.toUpperCase()} — Dispatching enrichment agents`);
  completeTimelineStep(step1);

  // === PHASE 2: PARALLEL ENRICHMENT ===
  const step2 = addTimelineStep('Enrichment — Parallel Intelligence');
  addStreamMsg('enrichment', '🔬 Launching parallel enrichment agents...');
  await sleep(400);

  // Simulate parallel execution with staggered display
  const enrichPromises = [];
  if (scenario.enrichment.vt) {
    enrichPromises.push((async () => {
      await sleep(300);
      addStreamMsg('enrichment', `Querying VirusTotal for ${scenario.alert.ioc}...`, 'tool');
      await sleep(900);
      const vt = scenario.enrichment.vt;
      if (vt.positives !== undefined) {
        addStreamMsg('enrichment', `✅ VT: ${vt.positives}/${vt.total} detections — ${vt.malware_family || 'Unknown family'}`, 'success');
        addEvidence('VT', `${vt.positives}/${vt.total} detections — ${vt.malware_family || 'Malicious'}`);
      } else {
        addStreamMsg('enrichment', `✅ VT: Reputation ${vt.reputation}, ${vt.malicious_count} malicious flags`, 'success');
        addEvidence('VT', `Reputation: ${vt.reputation}, ${vt.malicious_count} engines flagged`);
      }
    })());
  }
  if (scenario.enrichment.abuse) {
    enrichPromises.push((async () => {
      await sleep(500);
      addStreamMsg('enrichment', `Querying AbuseIPDB...`, 'tool');
      await sleep(700);
      const a = scenario.enrichment.abuse;
      addStreamMsg('enrichment', `✅ AbuseIPDB: ${a.confidence}% confidence, ${a.reports} reports (${a.country})`, 'success');
      addEvidence('Abuse', `${a.confidence}% abuse confidence, ${a.reports} reports, ISP: ${a.isp}`);
    })());
  }
  if (scenario.enrichment.cve) {
    enrichPromises.push((async () => {
      await sleep(600);
      addStreamMsg('enrichment', `Querying NVD for ${scenario.alert.ioc}...`, 'tool');
      await sleep(800);
      const c = scenario.enrichment.cve;
      addStreamMsg('enrichment', `✅ CVE: ${c.id} — CVSS ${c.cvss} ${c.severity}`, 'success');
      addEvidence('NVD', `${c.id}: CVSS ${c.cvss} — ${c.description}`);
    })());
  }
  if (scenario.enrichment.intel) {
    enrichPromises.push((async () => {
      await sleep(400);
      addStreamMsg('enrichment', `Searching threat intelligence feeds...`, 'tool');
      await sleep(1000);
      const ti = scenario.enrichment.intel;
      addStreamMsg('enrichment', `✅ Intel: ${ti.references} references found — ${ti.summary}`, 'success');
      addEvidence('Intel', ti.summary);
    })());
  }
  await Promise.all(enrichPromises);
  completeTimelineStep(step2);

  // === PHASE 3: INVESTIGATION ===
  const step3 = addTimelineStep('Investigation — Deep Analysis');
  addStreamMsg('investigation', '🔍 Correlating enrichment evidence...');
  await sleep(800);
  addStreamMsg('investigation', 'Mapping MITRE ATT&CK techniques...', 'tool');
  await sleep(600);
  activateMitre(scenario.mitre);
  scenario.techniques.forEach(t => addEvidence('MITRE', t));
  addStreamMsg('investigation', `Techniques: ${scenario.techniques.join(', ')}`, 'success');
  await sleep(500);
  addStreamMsg('investigation', 'Computing confidence score...');
  await sleep(400);
  setConfidence(Math.round(scenario.confidence * 100));
  addStreamMsg('investigation', `🧠 Confidence: ${Math.round(scenario.confidence * 100)}% — Root cause analysis complete`);
  await sleep(300);
  addStreamMsg('investigation', 'Checking IOC history in incident memory...');
  await sleep(500);
  addStreamMsg('investigation', '📊 IOC appeared in 0 prior incidents (novel threat)');
  completeTimelineStep(step3);

  // === PHASE 4: DECISION ===
  const step4 = addTimelineStep('Decision — Action Selection');
  addStreamMsg('decision', '⚖️ Evaluating confidence thresholds...');
  await sleep(600);

  let approved = true;
  if (scenario.decision === 'auto_remediate') {
    addStreamMsg('decision', `✅ Confidence ≥ 95% — AUTO-REMEDIATION authorized`, 'success');
  } else if (scenario.decision === 'request_approval') {
    addStreamMsg('decision', `⚠️ Confidence ${Math.round(scenario.confidence * 100)}% — Requesting analyst approval`);
    await sleep(300);
    approved = await showApproval(
      `Confidence: ${Math.round(scenario.confidence * 100)}%. Recommended: ${scenario.actions.join(', ')}. The system requires human approval before executing containment actions.`
    );
    if (approved) {
      addStreamMsg('decision', '✅ Analyst approved containment actions', 'success');
    } else {
      addStreamMsg('decision', '❌ Analyst rejected — switching to monitor-only mode');
    }
  }
  completeTimelineStep(step4);

  // === PHASE 5: REMEDIATION ===
  const step5 = addTimelineStep('Remediation — Executing Actions');
  if (approved) {
    for (const action of scenario.actions) {
      if (action === 'block_ip') {
        addStreamMsg('remediation', `🔒 Blocking IOC: ${scenario.alert.ioc}...`, 'tool');
        await sleep(800);
        addStreamMsg('remediation', `✅ Firewall rule applied — ${scenario.alert.ioc} blocked`, 'success');
      } else if (action === 'slack_alert') {
        addStreamMsg('remediation', '📢 Sending Slack notification...', 'tool');
        await sleep(600);
        addStreamMsg('remediation', '✅ Slack alert sent to #soc-incidents', 'success');
      } else if (action === 'create_ticket') {
        addStreamMsg('remediation', '🎫 Creating Jira ticket...', 'tool');
        await sleep(700);
        addStreamMsg('remediation', '✅ Jira SOC-1042 created — assigned to Tier-2', 'success');
      }
    }
  } else {
    addStreamMsg('remediation', '👁️ Monitor-only mode — no active containment');
  }
  completeTimelineStep(step5);

  // === PHASE 6: REPORTING ===
  const step6 = addTimelineStep('Reporting — Incident Documentation');
  addStreamMsg('reporting', '📋 Generating incident report...');
  await sleep(800);
  addStreamMsg('reporting', 'Writing executive summary and timeline...', 'tool');
  await sleep(600);
  addStreamMsg('reporting', '✅ Incident report generated — PDF available for download', 'success');
  await sleep(400);
  addStreamMsg('reporting', '💾 Updating incident memory graph...');
  await sleep(500);
  addStreamMsg('reporting', '✅ IOC correlation saved. System will recognize this threat faster next time.', 'success');
  completeTimelineStep(step6);

  // Final
  setStreamStatus('Complete', true);
  updateMetrics({ mttr: '12s', incidents: '1', auto: approved ? '100%' : '0%' });
  addStreamMsg('reporting', `🛡️ Incident resolved in ${Math.round(12 + Math.random() * 5)}s. All agents standing down.`, 'success');

  isRunning = false;
}

export function resetUI() {
  // Clear stream
  const stream = document.getElementById('agent-stream');
  if (stream) stream.innerHTML = '<div class="stream-idle"><div class="idle-bot"><div class="idle-bot-face"><div class="idle-eye l"></div><div class="idle-eye r"></div></div></div><p>Awaiting incoming alerts...</p><p class="stream-hint">Click a threat scenario above to begin</p></div>';

  // Clear timeline
  const tl = document.getElementById('timeline-body');
  if (tl) tl.innerHTML = '<div class="timeline-empty">No active incident</div>';

  // Clear evidence
  const ev = document.getElementById('evidence-list');
  if (ev) ev.innerHTML = '<div class="evidence-empty">No evidence collected yet</div>';

  // Reset confidence
  const fill = document.getElementById('conf-fill');
  const val = document.getElementById('conf-value');
  if (fill) fill.setAttribute('stroke-dasharray', '0 327');
  if (val) val.textContent = '—';

  // Reset MITRE
  document.querySelectorAll('.mitre-tactic').forEach(el => el.classList.remove('active'));

  // Hide approval
  const ap = document.getElementById('approval-panel');
  if (ap) ap.classList.add('hidden');

  // Reset status
  setStreamStatus('Idle', false);
  updateMetrics({ mttr: '—', incidents: '0', threat: 'LOW', auto: '0%' });
}

// Hero preview animation
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
