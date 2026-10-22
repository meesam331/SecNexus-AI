const state = {
  type: 'url',
  count: 0,
  requestId: 0,
  currentResult: null,
  currentVerdicts: [],
  chatHistory: [],
  viewMode: 'simple' // 'simple' or 'soc'
};

// DOM Elements
const input = document.querySelector('#indicator');
const file = document.querySelector('#file');
const dropzone = document.querySelector('#dropzone');
const form = document.querySelector('#scan-form');
const button = document.querySelector('#scan-button');
const toast = document.querySelector('#toast');
const tabs = [...document.querySelectorAll('.tabs .tab')];
const subtabs = [...document.querySelectorAll('.subtabs .subtab')];
const sampleBtns = [...document.querySelectorAll('.sample-btn')];
const radarOverlay = document.querySelector('#scan-radar-overlay');
const radarStatusText = document.querySelector('#radar-status-text');
const radarSubtext = document.querySelector('#radar-subtext');

const placeholders = {
  url: 'https://example.com/malicious-payload',
  domain: 'evil-c2-domain.com',
  ip: '185.220.101.5',
  url: 'https://example.com/path',
  domain: 'example.com',
  ip: '8.8.8.8',
  hash: 'SHA-256, SHA-1, or MD5 (e.g. 44d88612fea8a8f36de82e1278abb02f)'
};

let toastTimer;
let radarInterval;

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
  checkBackendHealth();
  setupEventListeners();
});

async function checkBackendHealth() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.status === 'ok') {
      const vtBadge = document.querySelector('#badge-vt');
      const groqBadge = document.querySelector('#badge-groq');
      if (data.providers) {
        if (data.providers.virustotal === 'configured') {
          vtBadge.className = 'status-badge live';
          vtBadge.innerHTML = '<i></i> VIRUSTOTAL CONFIGURED';
        } else {
          vtBadge.className = 'status-badge';
          vtBadge.innerHTML = '<i></i> VT DEMO MODE';
        }

        if (data.providers.groq_ai === 'active') {
          groqBadge.className = 'status-badge groq';
          const modelName = data.providers.groq_model ? data.providers.groq_model.split('/').pop().toUpperCase() : 'AI';
          groqBadge.innerHTML = `<i></i> GROQ ${modelName} READY`;
        } else {
          groqBadge.className = 'status-badge';
          groqBadge.innerHTML = '<i></i> AI UNAVAILABLE';
        }
      }
    }
  } catch (e) {
    console.warn('Health check failed:', e);
  }
}

function setupEventListeners() {
  // Main Indicator Tabs
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => selectType(tab));
    tab.addEventListener('keydown', event => {
      if (!['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1) + tabs.length) % tabs.length;
      tabs[next].focus();
      selectType(tabs[next]);
    });
  });

  // Results Subtabs
  subtabs.forEach(subtab => {
    subtab.addEventListener('click', () => switchSubtab(subtab.dataset.subtab));
  });

  // View Mode Toggles (Simple vs SOC)
  document.querySelector('#btn-mode-simple').addEventListener('click', () => switchViewMode('simple'));
  document.querySelector('#btn-mode-soc').addEventListener('click', () => switchViewMode('soc'));

  // Sample Buttons
  sampleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetType = btn.dataset.type;
      const targetVal = btn.dataset.val;
      const matchingTab = tabs.find(t => t.dataset.type === targetType);
      if (matchingTab) selectType(matchingTab);
      input.value = targetVal;
      runValue(targetVal);
    });
  });

  // File Upload
  document.querySelector('#browse').addEventListener('click', () => file.click());
  file.addEventListener('change', () => file.files[0] && runFile(file.files[0]));

  dropzone.addEventListener('dragover', event => {
    event.preventDefault();
    dropzone.classList.add('dragging');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragging'));
  dropzone.addEventListener('drop', event => {
    event.preventDefault();
    dropzone.classList.remove('dragging');
    const selected = event.dataTransfer.files[0];
    selected && runFile(selected);
  });

  // Form Submit
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (input.value.trim()) runValue(input.value.trim());
  });

  // Copy Script Buttons
  document.querySelector('#copy-win-script').addEventListener('click', () => {
    const code = document.querySelector('#windows-script-code').textContent;
    copyToClipboard(code, 'Windows PowerShell script copied to clipboard!');
  });
  document.querySelector('#copy-nix-script').addEventListener('click', () => {
    const code = document.querySelector('#nix-script-code').textContent;
    copyToClipboard(code, 'Linux / macOS command copied to clipboard!');
  });

  // Engine Search & Filter
  document.querySelector('#engine-search').addEventListener('input', e => filterEngines());
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterEngines();
    });
  });

  // Chat Form
  document.querySelector('#chat-form').addEventListener('submit', e => {
    e.preventDefault();
    handleChatSubmit();
  });

  // Quick Prompt Chips
  document.querySelectorAll('.chat-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelector('#chat-input').value = chip.textContent;
      handleChatSubmit();
    });
  });

  // Export Buttons
  document.querySelector('#btn-copy-md').addEventListener('click', () => {
    if (!state.currentResult) return;
    const md = generateMarkdownReport(state.currentResult);
    copyToClipboard(md, 'Markdown Incident Report copied!');
  });
  document.querySelector('#btn-download-json').addEventListener('click', () => {
    if (!state.currentResult) return;
    downloadJSON(state.currentResult);
  });
}

function selectType(tab) {
  tabs.forEach(item => {
    const selected = item === tab;
    item.classList.toggle('active', selected);
    item.setAttribute('aria-selected', selected);
    item.tabIndex = selected ? 0 : -1;
  });
  state.type = tab.dataset.type;
  input.value = '';
  file.value = '';
  const isFile = state.type === 'file';
  form.classList.toggle('hidden', isFile);
  dropzone.classList.toggle('hidden', !isFile);
  input.placeholder = placeholders[state.type] || '';
  if (!isFile) input.focus();
}

function switchViewMode(mode) {
  state.viewMode = mode;
  document.querySelector('#btn-mode-simple').classList.toggle('active', mode === 'simple');
  document.querySelector('#btn-mode-soc').classList.toggle('active', mode === 'soc');

  document.querySelector('#simple-view-container').classList.toggle('hidden', mode !== 'simple');
  document.querySelector('#soc-view-container').classList.toggle('hidden', mode !== 'soc');
  document.querySelector('#result').classList.toggle('simple-mode', mode === 'simple');
}

function switchSubtab(subtabId) {
  subtabs.forEach(tab => {
    const isActive = tab.dataset.subtab === subtabId;
    tab.classList.toggle('active', isActive);
  });

  document.querySelectorAll('.subtab-content').forEach(content => {
    content.classList.toggle('hidden', content.id !== `subtab-${subtabId}`);
  });
}

// --- SCAN EXECUTION ---
// --- SCAN EXECUTION & RADAR ANIMATION ---

function startRadarAnimation() {
  radarOverlay.classList.remove('hidden');
  const steps = [
    { text: 'Querying VirusTotal Threat Feeds...', sub: 'Connecting to 70+ Antivirus vendor scanning engines...' },
    { text: 'Running Groq AI (120B) Behavioral Dissection...', sub: 'Analyzing execution flows, MITRE tactics & payload heuristics...' },
    { text: 'Synthesizing Device Protection & Playbooks...', sub: 'Formulating immediate containment and host disinfection scripts...' }
  ];
  let stepIdx = 0;
  radarStatusText.textContent = steps[0].text;
  radarSubtext.textContent = steps[0].sub;

  clearInterval(radarInterval);
  radarInterval = setInterval(() => {
    stepIdx = (stepIdx + 1) % steps.length;
    radarStatusText.textContent = steps[stepIdx].text;
    radarSubtext.textContent = steps[stepIdx].sub;
  }, 1800);
}

function stopRadarAnimation() {
  clearInterval(radarInterval);
  radarOverlay.classList.add('hidden');
}

async function runValue(value) {
  const urls = {
    url: '/api/scan/url',
    domain: '/api/intelligence/domain',
    ip: '/api/intelligence/ip',
    hash: '/api/scan/hash'
  };
  let options = { method: 'GET' };
  let endpoint = urls[state.type];
  if (state.type === 'url') {
    options = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: value })
    };
  } else {
    endpoint += `?value=${encodeURIComponent(value)}`;
  }
  await request(endpoint, options);
}

async function runFile(selected) {
  const body = new FormData();
  body.append('file', selected);
  await request('/api/scan/file', { method: 'POST', body });
}

async function request(endpoint, options) {
  const requestId = ++state.requestId;
  button.disabled = true;
  button.querySelector('.btn-text').textContent = 'Analyzing...';
  startRadarAnimation();

  try {
    const response = await fetch(endpoint, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Scan request failed. Please try again.');
    if (requestId === state.requestId) render(data);
  } catch (error) {
    if (requestId === state.requestId) showError(error.message);
  } finally {
    if (requestId === state.requestId) {
      stopRadarAnimation();
      button.disabled = false;
      button.querySelector('.btn-text').textContent = 'Analyze with AI';
    }
  }
}

function showError(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add('show');
  toastTimer = setTimeout(() => toast.classList.remove('show'), 4000);
}

function showToast(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add('show');
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3000);
}

// --- RENDERING RESULTS ---

function render(data) {
  const result = data.result;
  state.currentResult = result;
  state.currentVerdicts = result.vendorVerdicts || [];
  state.chatHistory = [];

  const isDemo = result.isDemo === true;
  const isTestArtifact = result.isTestArtifact === true;
  const score = Number.isFinite(result.score?.score) ? result.score.score : null;
  const isUnscored = isDemo || isTestArtifact || score === null;
  const hasDetections = Number(result.detections?.malicious) > 0 || Number(result.detections?.suspicious) > 0;
  const safetyStatus = isTestArtifact
    ? 'test-artifact'
    : result.safetyStatus === 'NOT_SAFE' || hasDetections
      ? 'not-safe'
      : result.safetyStatus === 'NO_THREATS_FOUND'
        ? 'no-threats-found'
        : 'not-verified';
  const safetyLabel = safetyStatus === 'not-safe' ? 'NOT SAFE' : safetyStatus === 'test-artifact' ? 'TEST ARTIFACT' : safetyStatus === 'no-threats-found' ? 'NO THREATS FOUND' : 'NOT VERIFIED';
  const risk = safetyLabel;
  const ai = result.aiIntelligence || {};
  const overview = ai.threat_overview || {};
  const howWorks = ai.how_it_works || {};
  const protection = ai.device_protection || {};

  state.count++;
  document.querySelector('#scan-count').textContent = state.count;
  document.querySelector('#last-score').textContent = isUnscored ? 'N/A' : `${score}/100`;
  document.querySelector('#last-severity').textContent = risk;
  document.querySelector('.stats').classList.add('hidden');

  const resultPanel = document.querySelector('#result');
  resultPanel.classList.remove('hidden');

  // Header & Tags
  const sevBadge = document.querySelector('#severity-badge');
  sevBadge.className = `severity-badge ${safetyStatus}`;
  sevBadge.textContent = safetyLabel;

  const aiTag = document.querySelector('#ai-model-tag');
  aiTag.textContent = `🤖 ${ai.ai_model || 'Groq AI Analysis'}`;

  document.querySelector('#result-title').textContent = result.indicatorValue;
  document.querySelector('#result-meta').textContent = `${result.indicatorType.toUpperCase()} · Scanned at ${new Date(result.scannedAt).toLocaleTimeString()}`;
  document.querySelector('#score').textContent = isUnscored ? 'N/A' : score;

  // Animated Score Counter
  if (!isUnscored) animateScore(score);

  // Animated Circular SVG Gauge
  const gaugeCircle = document.querySelector('#gauge-fill-circle');
  const circumference = 2 * Math.PI * 42; // ~263.89
  const offset = isUnscored ? circumference : circumference - (score / 100) * circumference;
  gaugeCircle.style.strokeDashoffset = offset;

  // Set gauge color based on score
  if (isUnscored) {
    gaugeCircle.style.stroke = 'var(--muted)';
  } else if (score >= 75) {
    gaugeCircle.style.stroke = 'var(--red)';
  } else if (score >= 25) {
    gaugeCircle.style.stroke = 'var(--orange)';
  } else {
    gaugeCircle.style.stroke = 'var(--teal)';
  }

  document.querySelector('#score-bar').style.width = isUnscored ? '0%' : `${score}%`;

  // Details
  document.querySelector('#ratio').textContent = isTestArtifact ? data.detectionRatioLabel : isDemo ? 'No live engine results' : data.detectionRatioLabel || `${result.detections.malicious}/${result.detections.totalEngines}`;
  document.querySelector('#threat-classification').textContent = isTestArtifact ? 'Antivirus test artifact' : isDemo ? 'Unverified' : overview.classification || (result.detections.malicious > 0 ? 'Malicious' : 'No detections; unknown');
  document.querySelector('#source').textContent = result.source.toUpperCase();

  // 1. AI Threat Intel Tab
  // --- 1. RENDER SIMPLE VIEW (FOR NORMAL USERS) ---
  const simpleBanner = document.querySelector('#simple-verdict-banner');
  simpleBanner.className = `simple-verdict-banner ${safetyStatus}`;
  document.querySelector('#simple-headline').textContent = safetyLabel;

  // --- 2. RENDER ADVANCED SOC INTEL TAB ---
  document.querySelector('#ai-summary').textContent = overview.summary || 'Threat analysis compiled.';
  document.querySelector('#ai-attack-vector').textContent = howWorks.attack_vector || 'Unavailable from the supplied scan telemetry.';
  document.querySelector('#ai-execution').textContent = howWorks.execution_mechanism || 'No behavioral telemetry was supplied.';
  document.querySelector('#ai-damage').textContent = howWorks.potential_damage || 'Unknown from the supplied scan telemetry.';

  // MITRE ATT&CK Mapping
  const mitreContainer = document.querySelector('#mitre-container');
  mitreContainer.replaceChildren(...(howWorks.mitre_attack || []).map(m => {
    const card = document.createElement('div');
    card.className = 'mitre-tag';
    const id = document.createElement('span');
    id.className = 'mitre-id';
    id.textContent = `${m.id || ''} · ${m.tactic || ''}`;
    const technique = document.createElement('div');
    technique.className = 'mitre-name';
    technique.textContent = m.technique || '';
    const description = document.createElement('p');
    description.className = 'mitre-desc';
    description.textContent = m.description || '';
    card.append(id, technique, description);
    return card;
  }));

  // Risk Factors
  const factorsEl = document.querySelector('#factors');
  factorsEl.replaceChildren(...(result.score.factors || []).map(f => {
    const item = document.createElement('div');
    item.className = 'factor';
    const detail = document.createElement('span');
    const label = document.createElement('b');
    label.textContent = f.label;
    detail.append(label, document.createElement('br'), f.detail);
    if (f.source) {
      const source = document.createElement('small');
      source.textContent = `Evidence: ${f.source}`;
      detail.append(document.createElement('br'), source);
    }
    const weight = document.createElement('strong');
    weight.textContent = f.weight > 0 ? `+${f.weight}` : '0';
    item.append(detail, weight);
    return item;
  }));

  // 2. Device Protection Tab
  // --- 3. RENDER DEVICE PROTECTION TAB ---
  renderChecklist('#containment-list', protection.immediate_containment || []);
  renderChecklist('#remediation-list', protection.host_remediation || []);
  renderChecklist('#hardening-list', protection.hardening_and_prevention || []);

  const cmds = protection.platform_commands || {};
  document.querySelector('#windows-script-code').textContent = cmds.windows || '# No specific Windows containment script generated.';
  document.querySelector('#nix-script-code').textContent = cmds.linux_mac || '# No specific Linux command generated.';

  // 3. Antivirus Engines Tab
  // --- 4. RENDER ANTIVIRUS ENGINES TAB ---
  document.querySelector('#engine-count').textContent = result.vendorVerdicts ? result.vendorVerdicts.length : 0;
  renderEngineTable(state.currentVerdicts);

  // 4. Reset Chat Assistant
  // --- 5. RESET CHAT ASSISTANT ---
  const chatMessages = document.querySelector('#chat-messages');
  const welcomeBubble = document.createElement('div');
  welcomeBubble.className = 'chat-bubble ai';
  const welcomeLabel = document.createElement('strong');
  welcomeLabel.textContent = `ThreatLens AI (${ai.ai_model || 'SOC Assistant'}):`;
  const welcomeText = document.createElement('p');
  welcomeText.textContent = isDemo
    ? 'This is demo data, not a live verdict. Do not treat it as evidence about the indicator.'
    : `Analysis loaded for ${result.indicatorValue} (Severity: ${overview.severity || risk}). Ask about the scan evidence.`;
  welcomeBubble.append(welcomeLabel, welcomeText);
  chatMessages.replaceChildren(welcomeBubble);

  // 5. Export Preview
  // --- 6. EXPORT PREVIEW ---
  document.querySelector('#export-preview-code').textContent = generateMarkdownReport(result);

  // 6. Session Log History Row
  // --- 7. SESSION LOG HISTORY ROW ---
  const row = document.createElement('tr');
  const values = [
    result.indicatorValue,
    result.indicatorType.toUpperCase(),
    safetyLabel,
    new Date(result.scannedAt).toLocaleTimeString()
  ];
  values.forEach((val, idx) => {
    const cell = document.createElement('td');
    cell.textContent = val;
    if (idx === 0) cell.title = result.indicatorValue;
    if (idx === 2) cell.className = `severity-badge ${safetyStatus}`;
    row.append(cell);
  });
  const historyBody = document.querySelector('#history');
  const priorRow = [...historyBody.rows].find(historyRow =>
    historyRow.cells[0]?.textContent === String(result.indicatorValue) &&
    historyRow.cells[1]?.textContent === result.indicatorType.toUpperCase()
  );
  if (priorRow) priorRow.replaceWith(row);
  else historyBody.prepend(row);
  document.querySelector('#empty-history').classList.add('hidden');
  document.querySelector('#history-count').textContent = `${historyBody.rows.length} ${historyBody.rows.length === 1 ? 'unique indicator' : 'unique indicators'}`;

  // Default to AI Intel subtab
  // Default to Simple View or keep user selected mode
  switchViewMode(state.viewMode);
  switchSubtab('ai-intel');
  resultPanel.focus({ preventScroll: false });
  resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function animateScore(targetScore) {
  const el = document.querySelector('#score');
  let current = 0;
  const duration = 1000;
  const startTime = performance.now();

  function update(time) {
    const elapsed = time - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeOut = 1 - Math.pow(1 - progress, 3);
    current = Math.round(easeOut * targetScore);
    el.textContent = current;
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      el.textContent = targetScore;
    }
  }
  requestAnimationFrame(update);
}

function renderChecklist(selector, items) {
  const container = document.querySelector(selector);
  container.replaceChildren(...items.map(item => {
    const li = document.createElement('li');
    li.textContent = item;
    return li;
  }));
}

function renderEngineTable(verdicts) {
  const tbody = document.querySelector('#engine-table-body');
  if (!verdicts || verdicts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty">No engine verdicts recorded.</td></tr>';
    return;
  }

  tbody.replaceChildren(...verdicts.map(v => {
    const tr = document.createElement('tr');
    const vendorCell = document.createElement('td');
    const vendor = document.createElement('strong');
    vendor.textContent = v.vendor || 'Unknown engine';
    vendorCell.append(vendor);
    const categoryCell = document.createElement('td');
    const categoryBadge = document.createElement('span');
    categoryBadge.className = v.category === 'malicious' ? 'badge-malicious' : v.category === 'suspicious' ? 'badge-suspicious' : 'badge-clean';
    categoryBadge.textContent = (v.category || 'unknown').toUpperCase();
    categoryCell.append(categoryBadge);
    const resultCell = document.createElement('td');
    resultCell.textContent = v.result || 'Undetected';
    tr.append(vendorCell, categoryCell, resultCell);
    return tr;
  }));
}

function filterEngines() {
  const query = document.querySelector('#engine-search').value.toLowerCase().trim();
  const activeFilter = document.querySelector('.filter-btn.active').dataset.filter;

  const filtered = state.currentVerdicts.filter(v => {
    const matchesQuery = v.vendor.toLowerCase().includes(query) || (v.result && v.result.toLowerCase().includes(query));
    if (!matchesQuery) return false;
    if (activeFilter === 'all') return true;
    if (activeFilter === 'malicious') return v.category === 'malicious';
    if (activeFilter === 'suspicious') return v.category === 'suspicious';
    if (activeFilter === 'clean') return v.category === 'undetected' || v.category === 'harmless';
    return true;
  });

  renderEngineTable(filtered);
}

// --- AI CHAT ASSISTANT ---

async function handleChatSubmit() {
  const inputField = document.querySelector('#chat-input');
  const message = inputField.value.trim();
  if (!message || !state.currentResult) return;

  inputField.value = '';
  const chatMessages = document.querySelector('#chat-messages');

  // Append User message
  const userBubble = document.createElement('div');
  userBubble.className = 'chat-bubble user';
  const userText = document.createElement('p');
  userText.textContent = message;
  userBubble.append(userText);
  chatMessages.append(userBubble);

  // Append AI loading bubble
  const aiBubble = document.createElement('div');
  aiBubble.className = 'chat-bubble ai';
  const loadingLabel = document.createElement('strong');
  loadingLabel.textContent = 'ThreatLens AI:';
  const loadingText = document.createElement('p');
  loadingText.textContent = 'Analyzing the available scan evidence...';
  aiBubble.append(loadingLabel, loadingText);
  chatMessages.append(aiBubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;

  state.chatHistory.push({ role: 'user', content: message });

  try {
    const res = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        indicator: state.currentResult.indicatorValue,
        type: state.currentResult.indicatorType,
        ai_report: state.currentResult.aiIntelligence,
        history: state.chatHistory.slice(0, -1)
      })
    });

    const data = await res.json();
    if (res.ok && data.response) {
      const responseLabel = document.createElement('strong');
      responseLabel.textContent = `ThreatLens AI (${data.model ? data.model.split('/').pop() : 'AI'}):`;
      aiBubble.replaceChildren(responseLabel);
      aiBubble.insertAdjacentHTML('beforeend', formatMarkdown(data.response));
      state.chatHistory.push({ role: 'assistant', content: data.response });
    } else {
      const errorText = document.createElement('p');
      errorText.className = 'error';
      errorText.textContent = data.error || 'Failed to generate response.';
      aiBubble.replaceChildren(loadingLabel, errorText);
    }
  } catch (err) {
    const errorText = document.createElement('p');
    errorText.className = 'error';
    errorText.textContent = 'Network error. Please try again.';
    aiBubble.replaceChildren(loadingLabel, errorText);
  }

  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// --- EXPORT & UTILITIES ---

function generateMarkdownReport(result) {
  const ai = result.aiIntelligence || {};
  const simple = ai.simple_guide || {};
  const overview = ai.threat_overview || {};
  const how = ai.how_it_works || {};
  const prot = ai.device_protection || {};

  return `# ThreatLens Security Incident Report
**Generated:** ${new Date(result.scannedAt).toUTCString()}
**Target Indicator:** ${result.indicatorValue}
**Indicator Type:** ${result.indicatorType.toUpperCase()}
**Threat Severity:** ${overview.severity || result.score.riskLevel.toUpperCase()}
**Threat Score:** ${Number.isFinite(result.score.score) ? `${result.score.score}/100` : 'N/A'}
**Detection Ratio:** ${result.detections.malicious}/${result.detections.totalEngines} engines flagged

---

## 1. Executive Threat Summary
${overview.summary || 'N/A'}
## 1. Executive Summary & Plain Language Guide
- **Verdict:** ${result.verdict || result.safetyStatus || 'NOT VERIFIED'}
- **What is this:** ${simple.what_is_it || overview.summary || 'N/A'}
- **Safe to open:** ${simple.is_it_safe_to_open || 'N/A'}

- **Classification:** ${overview.classification || 'N/A'}
- **Identified Threat Name:** ${overview.threat_name || 'N/A'}

---

## 2. Threat Behavior ("How this Virus Works")
- **Infection & Attack Vector:** ${how.attack_vector || 'N/A'}
- **Execution Mechanism:** ${how.execution_mechanism || 'N/A'}
- **Potential Blast Radius:** ${how.potential_damage || 'N/A'}

### MITRE ATT&CK Matrix Mapping
${(how.mitre_attack || []).map(m => `- **[${m.id}] ${m.technique}** (${m.tactic}): ${m.description}`).join('\n')}

---

## 3. Device Protection & Incident Response Playbook

### Phase 1: Immediate Containment
${(prot.immediate_containment || []).map(step => `- [ ] ${step}`).join('\n')}

### Phase 2: Host Disinfection & Cleanup
${(prot.host_remediation || []).map(step => `- [ ] ${step}`).join('\n')}

### Phase 3: Hardening & Prevention
${(prot.hardening_and_prevention || []).map(step => `- [ ] ${step}`).join('\n')}

### Platform Containment Scripts
**Windows PowerShell:**
\`\`\`powershell
${(prot.platform_commands || {}).windows || '# N/A'}
\`\`\`

**Linux / macOS:**
\`\`\`bash
${(prot.platform_commands || {}).linux_mac || '# N/A'}
\`\`\`
`;
}

function downloadJSON(result) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `threatlens-report-${result.indicatorType}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('JSON report downloaded successfully!');
}

function copyToClipboard(text, successMsg) {
  navigator.clipboard.writeText(text).then(() => {
    showToast(successMsg);
  }).catch(() => {
    showError('Failed to copy to clipboard.');
  });
}

function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}

function formatMarkdown(text) {
  let html = escapeHTML(text);
  // Code blocks ```...```
  html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  // Inline code `...`
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Bold **...**
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Bullet lists
  html = html.replace(/^- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/gim, '<ul>$1</ul>');
  // Line breaks
  html = html.replace(/\n/g, '<br>');
  return `<p>${html}</p>`;
}