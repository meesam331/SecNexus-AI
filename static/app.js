const state = {
  type: 'file-hash',
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
  'file-hash': 'SHA-256, SHA-1, or MD5 hash (e.g. 44d88612fea8a8f36de82e1278abb02f)',
  url: 'https://suspicious-domain.pk/payload',
  apk: 'Upload APK file via File tab or browse button below',
  'ip-address': '185.220.101.5',
  whatsapp: 'https://wa.me/923001234567',
  'qr-code': 'Upload QR code image or paste URL',
  deepfake: 'Upload MP4 video for deepfake analysis'
};

let toastTimer;
let radarInterval;

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
  checkBackendHealth();
  setupEventListeners();
  // Set initial tab state
  const initialTab = tabs.find(t => t.dataset.type === state.type) || tabs[0];
  if (initialTab) selectType(initialTab);
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
          vtBadge.innerHTML = '<i></i> VIRUSTOTAL INTEL FEED';
        } else {
          vtBadge.className = 'status-badge';
          vtBadge.innerHTML = '<i></i> VT DEMO MODE';
        }

        if (data.providers.groq_ai === 'active') {
          groqBadge.className = 'status-badge groq';
          const modelName = data.providers.groq_model ? data.providers.groq_model.split('/').pop().toUpperCase() : 'AI';
          groqBadge.innerHTML = `<i></i> GROQ ${modelName} ENGINE`;
        } else {
          groqBadge.className = 'status-badge';
          groqBadge.innerHTML = '<i></i> AI OFFLINE';
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

  // View Mode Toggles (Officer Summary vs Forensic Detail)
  document.querySelector('#btn-mode-simple').addEventListener('click', () => switchViewMode('simple'));
  document.querySelector('#btn-mode-soc').addEventListener('click', () => switchViewMode('soc'));

  // Forensic Sample Buttons
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
  document.querySelector('#copy-win-script')?.addEventListener('click', () => {
    const code = document.querySelector('#windows-script-code').textContent;
    copyToClipboard(code, 'Windows PowerShell script copied to clipboard!');
  });
  document.querySelector('#copy-nix-script')?.addEventListener('click', () => {
    const code = document.querySelector('#nix-script-code').textContent;
    copyToClipboard(code, 'Linux / Android containment command copied to clipboard!');
  });

  // Copy Forensic Report Button for FIR
  document.querySelector('#copy-forensic-report')?.addEventListener('click', () => {
    const text = document.querySelector('#forensic-report-text')?.textContent || '';
    copyToClipboard(text, 'Forensic report copied for court challan / FIR!');
  });

  // Engine Search & Filter
  document.querySelector('#engine-search')?.addEventListener('input', () => filterEngines());
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterEngines();
    });
  });

  // Chat Form
  document.querySelector('#chat-form')?.addEventListener('submit', e => {
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
  document.querySelector('#btn-copy-md')?.addEventListener('click', () => {
    if (!state.currentResult) return;
    const md = generateMarkdownReport(state.currentResult);
    copyToClipboard(md, 'SecNexus FIR Markdown Report copied!');
  });
  document.querySelector('#btn-download-json')?.addEventListener('click', () => {
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

  const showDropzone = ['apk', 'deepfake', 'qr-code', 'file-hash'].includes(state.type);
  const isFileOnly = ['apk', 'deepfake'].includes(state.type);

  form.classList.toggle('hidden', isFileOnly);
  dropzone.classList.toggle('hidden', !showDropzone);

  const hintEl = document.querySelector('#dropzone-hint');
  if (hintEl) {
    if (state.type === 'apk') hintEl.textContent = 'Upload Android APK file for permission & reverse engineering analysis. Maximum 32 MB.';
    else if (state.type === 'deepfake') hintEl.textContent = 'Upload MP4 video for frame, audio & deepfake artifact analysis. Maximum 32 MB.';
    else if (state.type === 'qr-code') hintEl.textContent = 'Upload QR code image (PNG, JPG) or enter URL above. Maximum 32 MB.';
    else if (state.type === 'file-hash') hintEl.textContent = 'Drop any suspicious file here to auto-calculate hashes, or enter hash above.';
    else hintEl.textContent = 'Maximum file size: 32 MB. Processed on-premise on Pakistan Sovereign Secure Node.';
  }

  input.placeholder = placeholders[state.type] || 'Enter evidence indicator...';
  if (!isFileOnly) input.focus();
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

// --- SCAN EXECUTION & RADAR ANIMATION ---

function startRadarAnimation() {
  radarOverlay.classList.remove('hidden');
  const steps = [
    { text: 'Querying VirusTotal Intelligence Feeds...', sub: 'Cross-referencing 70+ global threat databases...' },
    { text: 'Running Cuckoo Sandbox Behavioral Analysis...', sub: 'Simulating execution — checking C2, persistence, exfiltration...' },
    { text: 'Performing APK Hunter / PECA Mapping...', sub: 'Analyzing permissions, hardcoded secrets, legal violation mapping...' },
    { text: 'Generating Sovereign Forensic Report...', sub: 'Synthesizing court-admissible FIR documentation under PECA 2016...' }
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
  let endpoint = '';
  let options = { method: 'GET' };

  if (state.type === 'url' || state.type === 'whatsapp') {
    endpoint = '/api/scan/url';
    options = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: value })
    };
  } else if (state.type === 'qr-code') {
    endpoint = '/api/scan/url';
    options = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: value })
    };
  } else if (state.type === 'ip-address') {
    endpoint = `/api/intelligence/ip?value=${encodeURIComponent(value)}`;
  } else if (state.type === 'file-hash') {
    endpoint = `/api/scan/hash?value=${encodeURIComponent(value)}`;
  } else {
    // Dynamic fallback
    if (value.startsWith('http://') || value.startsWith('https://')) {
      endpoint = '/api/scan/url';
      options = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value })
      };
    } else if (/^[a-fA-F0-9]{32,64}$/.test(value)) {
      endpoint = `/api/scan/hash?value=${encodeURIComponent(value)}`;
    } else {
      endpoint = `/api/intelligence/ip?value=${encodeURIComponent(value)}`;
    }
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
  button.querySelector('.btn-text').textContent = 'Run Forensic Analysis...';
  startRadarAnimation();

  try {
    const response = await fetch(endpoint, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Forensic analysis failed. Please verify indicator format.');
    if (requestId === state.requestId) render(data);
  } catch (error) {
    if (requestId === state.requestId) showError(error.message);
  } finally {
    if (requestId === state.requestId) {
      stopRadarAnimation();
      button.disabled = false;
      button.querySelector('.btn-text').textContent = 'FORENSIC SCAN';
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

  const safetyLabel = safetyStatus === 'not-safe'
    ? 'MALICIOUS THREAT'
    : safetyStatus === 'test-artifact'
      ? 'TEST ARTIFACT'
      : safetyStatus === 'no-threats-found'
        ? 'NO THREATS FOUND'
        : 'NOT VERIFIED';

  const risk = safetyLabel;
  const ai = result.aiIntelligence || {};
  const overview = ai.threat_overview || {};
  const howWorks = ai.how_it_works || {};
  const protection = ai.device_protection || {};

  state.count++;
  document.querySelector('#scan-count').textContent = state.count;
  document.querySelector('#last-score').textContent = isUnscored ? 'N/A' : `${score}/100`;
  document.querySelector('#last-severity').textContent = risk;
  document.querySelector('.stats').classList.remove('hidden');

  const resultPanel = document.querySelector('#result');
  resultPanel.classList.remove('hidden');

  // Header & Tags
  const sevBadge = document.querySelector('#severity-badge');
  sevBadge.className = `severity-badge ${safetyStatus}`;
  sevBadge.textContent = safetyLabel;

  const aiTag = document.querySelector('#ai-model-tag');
  aiTag.textContent = `🔬 ${ai.ai_model || 'SecNexus AI Forensic Engine'}`;

  document.querySelector('#result-title').textContent = result.indicatorValue;
  document.querySelector('#result-meta').textContent = `${(result.caseReport?.input_type || result.indicatorType).toUpperCase()} · Processed at ${new Date(result.scannedAt).toLocaleTimeString()} (Pakistan Sovereign Secure Node)`;
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
  } else if (score >= 70) {
    gaugeCircle.style.stroke = 'var(--red)';
  } else if (score >= 25) {
    gaugeCircle.style.stroke = 'var(--gold)';
  } else {
    gaugeCircle.style.stroke = 'var(--matrix)';
  }

  document.querySelector('#score-bar').style.width = isUnscored ? '0%' : `${score}%`;

  // Details
  document.querySelector('#ratio').textContent = isTestArtifact ? data.detectionRatioLabel : isDemo ? 'No live engine results' : data.detectionRatioLabel || `${result.detections.malicious}/${result.detections.totalEngines}`;
  document.querySelector('#threat-classification').textContent = isTestArtifact ? 'Antivirus test artifact' : isDemo ? 'Unverified' : overview.classification || (result.detections.malicious > 0 ? 'Malicious' : 'No detections; unclassified');
  document.querySelector('#source').textContent = result.source.toUpperCase();

  // Simple Officer Summary View
  const simpleBanner = document.querySelector('#simple-verdict-banner');
  simpleBanner.className = `simple-verdict-banner ${safetyStatus}`;
  document.querySelector('#simple-headline').textContent = safetyLabel;

  // Forensic Analysis Subtab
  document.querySelector('#ai-summary').textContent = overview.summary || 'Forensic analysis compiled.';
  document.querySelector('#ai-attack-vector').textContent = howWorks.attack_vector || 'Unavailable from static indicators alone.';
  document.querySelector('#ai-execution').textContent = howWorks.execution_mechanism || 'No sandbox behavioral execution observed.';
  document.querySelector('#ai-damage').textContent = howWorks.potential_damage || 'Unknown impact without deep reverse engineering.';

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

  // Render PECA Tab
  renderPecaTab(result);

  // Device Containment Tab
  renderChecklist('#containment-list', protection.immediate_containment || []);
  renderChecklist('#remediation-list', protection.host_remediation || []);
  renderChecklist('#hardening-list', protection.hardening_and_prevention || []);

  const cmds = protection.platform_commands || {};
  document.querySelector('#windows-script-code').textContent = cmds.windows || '# No specific Windows containment command generated.';
  document.querySelector('#nix-script-code').textContent = cmds.linux_mac || '# No specific Linux command generated.';

  // Antivirus Engines Tab
  document.querySelector('#engine-count').textContent = result.vendorVerdicts ? result.vendorVerdicts.length : 0;
  renderEngineTable(state.currentVerdicts);

  // Reset Chat Assistant
  const chatMessages = document.querySelector('#chat-messages');
  const welcomeBubble = document.createElement('div');
  welcomeBubble.className = 'chat-bubble ai';
  const welcomeLabel = document.createElement('strong');
  welcomeLabel.textContent = `SecNexus AI (${ai.ai_model || 'Forensic Assistant'}):`;
  const welcomeText = document.createElement('p');
  welcomeText.textContent = isDemo
    ? 'Offline demo mode. Data analyzed on-premise, Pakistan Sovereign Secure Node.'
    : `Forensic dossier loaded for ${result.indicatorValue} (Verdict: ${overview.severity || risk}). Ask any legal or technical question.`;
  welcomeBubble.append(welcomeLabel, welcomeText);
  chatMessages.replaceChildren(welcomeBubble);

  // Export Preview
  document.querySelector('#export-preview-code').textContent = generateMarkdownReport(result);

  // Session Case Log History Row (5 columns: EVIDENCE, TYPE, VERDICT, PECA, TIME)
  const caseReport = result.caseReport || {};
  const pecaBadge = (caseReport.peca_sections_violated && caseReport.peca_sections_violated.length > 0)
    ? caseReport.peca_sections_violated[0].split('—')[0].trim()
    : '--';

  const row = document.createElement('tr');
  const values = [
    result.indicatorValue,
    caseReport.input_type || result.indicatorType.toUpperCase(),
    safetyLabel,
    pecaBadge,
    new Date(result.scannedAt).toLocaleTimeString()
  ];
  values.forEach((val, idx) => {
    const cell = document.createElement('td');
    cell.textContent = val;
    if (idx === 0) cell.title = result.indicatorValue;
    if (idx === 2) cell.className = `severity-badge ${safetyStatus}`;
    if (idx === 3) cell.className = 'peca-cell';
    row.append(cell);
  });

  const historyBody = document.querySelector('#history');
  const priorRow = [...historyBody.rows].find(historyRow =>
    historyRow.cells[0]?.textContent === String(result.indicatorValue) &&
    historyRow.cells[1]?.textContent === (caseReport.input_type || result.indicatorType.toUpperCase())
  );
  if (priorRow) priorRow.replaceWith(row);
  else historyBody.prepend(row);
  document.querySelector('#empty-history').classList.add('hidden');
  document.querySelector('#history-count').textContent = `${historyBody.rows.length} ${historyBody.rows.length === 1 ? 'case logged' : 'cases logged'}`;

  // Preserve user mode and default subtab
  switchViewMode(state.viewMode);
  switchSubtab('ai-intel');
  resultPanel.focus({ preventScroll: false });
  resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderPecaTab(result) {
  const report = result.caseReport || {};
  const pecaList = document.querySelector('#peca-violations-list');
  const violations = report.peca_sections_violated || [];
  if (pecaList) {
    if (violations.length === 0) {
      pecaList.innerHTML = '<p class="muted">No PECA violations automatically identified. Legal review required by authorized officer.</p>';
    } else {
      pecaList.replaceChildren(...violations.map(v => {
        const div = document.createElement('div');
        div.className = 'peca-violation';
        div.textContent = v;
        return div;
      }));
    }
  }
  const urduEl = document.querySelector('#urdu-summary-text');
  if (urduEl) urduEl.textContent = report.executive_summary_urdu || result.aiIntelligence?.executive_summary_urdu || 'تجزیہ جاری ہے۔';
  const recEl = document.querySelector('#analyst-recommendation-text');
  if (recEl) recEl.textContent = report.recommended_action_for_officer || 'Preserve evidence and refer for specialist examination.';
  const forensicEl = document.querySelector('#forensic-report-text');
  if (forensicEl) forensicEl.textContent = report.forensic_report_pdf_text || 'Forensic report unavailable.';
}

function animateScore(targetScore) {
  const el = document.querySelector('#score');
  let current = 0;
  const duration = 900;
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
  if (!container) return;
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

// --- SECNEXUS AI FORENSIC CHAT ASSISTANT ---

async function handleChatSubmit() {
  const inputField = document.querySelector('#chat-input');
  const message = inputField.value.trim();
  if (!message || !state.currentResult) return;

  inputField.value = '';
  const chatMessages = document.querySelector('#chat-messages');

  // User message bubble
  const userBubble = document.createElement('div');
  userBubble.className = 'chat-bubble user';
  const userText = document.createElement('p');
  userText.textContent = message;
  userBubble.append(userText);
  chatMessages.append(userBubble);

  // AI loading bubble
  const aiBubble = document.createElement('div');
  aiBubble.className = 'chat-bubble ai';
  const loadingLabel = document.createElement('strong');
  loadingLabel.textContent = 'SecNexus AI:';
  const loadingText = document.createElement('p');
  loadingText.textContent = 'Analyzing evidence under PECA 2016 framework...';
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
        type: state.currentResult.caseReport?.input_type || state.currentResult.indicatorType,
        ai_report: state.currentResult.aiIntelligence,
        history: state.chatHistory.slice(0, -1)
      })
    });

    const data = await res.json();
    if (res.ok && data.response) {
      const responseLabel = document.createElement('strong');
      responseLabel.textContent = `SecNexus AI (${data.model ? data.model.split('/').pop() : 'Forensic Engine'}):`;
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
    errorText.textContent = 'Network error contacting sovereign analysis engine.';
    aiBubble.replaceChildren(loadingLabel, errorText);
  }

  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// --- EXPORT & UTILITIES ---

function generateMarkdownReport(result) {
  const rep = result.caseReport || {};
  const ai = result.aiIntelligence || {};
  const simple = ai.simple_guide || {};
  const overview = ai.threat_overview || {};
  const how = ai.how_it_works || {};
  const prot = ai.device_protection || {};

  return `# SecNexus AI v2.0 — Pakistan Sovereign Cyber Threat Intelligence & Forensic Report
**Case Identifier:** ${rep.case_id || 'PK-CTI-EVIDENCE'}
**Classification:** SOVEREIGN CYBER DEFENSE // PECA 2016
**Jurisdiction:** Pakistan National Cyber Crime Legal Framework (PECA 2016)
**Generated:** ${new Date(result.scannedAt).toUTCString()}
**Target Evidence:** \`${result.indicatorValue}\`
**Evidence Input Type:** ${rep.input_type || result.indicatorType.toUpperCase()}
**Forensic Threat Score:** ${Number.isFinite(result.score.score) ? `${result.score.score}/100` : 'UNVERIFIED'}
**Verdict:** ${rep.verdict || result.verdict || 'NOT VERIFIED'}
**Detection Ratio:** ${result.detections.malicious}/${result.detections.totalEngines} security engines flagged

---

## 1. PECA 2016 Statutory Mapping & Violations
${(rep.peca_sections_violated || []).length > 0
  ? rep.peca_sections_violated.map(s => `- **${s}**`).join('\n')
  : '- No direct automated statutory violation identified. Full legal review recommended.'}

### Recommended Action for Investigating Officer / Forensic Analyst
${rep.recommended_action_for_officer || 'Preserve evidence and refer for specialist examination.'}

### ملزم / متاثرہ شخص کے لیے خلاصہ (Urdu Summary for Victim)
> ${rep.executive_summary_urdu || simple.what_is_it || 'کوئی خلاصہ دستیاب نہیں۔'}

---

## 2. Forensic Threat Overview & Behavioral Dissection
- **Classification:** ${overview.classification || 'N/A'}
- **Identified Threat Family:** ${overview.threat_name || 'N/A'}
- **Summary:** ${overview.summary || 'N/A'}
- **Attack Vector:** ${how.attack_vector || 'N/A'}
- **Execution Mechanism:** ${how.execution_mechanism || 'N/A'}
- **Potential Impact:** ${how.potential_damage || 'N/A'}

### MITRE ATT&CK Matrix Mapping
${(how.mitre_attack || []).map(m => `- **[${m.id}] ${m.technique}** (${m.tactic}): ${m.description}`).join('\n')}

---

## 3. Device Containment Playbook (Sovereign Incident Response)
### Phase 1: Immediate Containment
${(prot.immediate_containment || []).map(step => `- [ ] ${step}`).join('\n')}

### Phase 2: Host Disinfection & Forensics
${(prot.host_remediation || []).map(step => `- [ ] ${step}`).join('\n')}

### Phase 3: Hardening & Prevention
${(prot.hardening_and_prevention || []).map(step => `- [ ] ${step}`).join('\n')}

### Platform Containment Commands
**Windows PowerShell:**
\`\`\`powershell
${(prot.platform_commands || {}).windows || '# N/A'}
\`\`\`

**Linux / Android Terminal:**
\`\`\`bash
${(prot.platform_commands || {}).linux_mac || '# N/A'}
\`\`\`

---

## 4. Court Challan Documentation (Forensic Paragraph)
${rep.forensic_report_pdf_text || 'Forensic report paragraph unavailable.'}
`;
}

function downloadJSON(result) {
  const report = result.caseReport || result;
  const id = report.case_id || Date.now();
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `secnexus-forensic-case-${id}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Sovereign JSON case packet downloaded successfully!');
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
  html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/^- (.*$)/gim, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/gim, '<ul>$1</ul>');
  html = html.replace(/\n/g, '<br>');
  return `<p>${html}</p>`;
}

}