const API_BASE = 'http://localhost:8000';

const currentUrlEl = document.getElementById('currentUrl');
const manualUrlEl = document.getElementById('manualUrl');
const scanActiveBtn = document.getElementById('scanActiveBtn');
const scanManualBtn = document.getElementById('scanManualBtn');
const loadingBox = document.getElementById('loadingBox');
const errorBox = document.getElementById('errorBox');
const resultCard = document.getElementById('resultCard');

const verdictBanner = document.getElementById('verdictBanner');
const verdictIcon = document.getElementById('verdictIcon');
const verdictTitle = document.getElementById('verdictTitle');
const verdictRisk = document.getElementById('verdictRisk');

const statPhishing = document.getElementById('statPhishing');
const statLegitimate = document.getElementById('statLegitimate');
const statRisk = document.getElementById('statRisk');

const shapList = document.getElementById('shapList');
const recommendationText = document.getElementById('recommendationText');
const backendStatus = document.getElementById('backendStatus');

let activeTabUrl = '';

// Check backend connectivity
async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/model-info`);
    if (res.ok) {
      backendStatus.textContent = 'Online (RF + SHAP)';
      backendStatus.style.color = '#34d399';
    } else {
      backendStatus.textContent = 'Error';
      backendStatus.style.color = '#f87171';
    }
  } catch (err) {
    backendStatus.textContent = 'Offline (Start FastAPI)';
    backendStatus.style.color = '#f87171';
  }
}

// Detect current active tab URL
function detectActiveTab() {
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        activeTabUrl = tabs[0].url;
        currentUrlEl.textContent = activeTabUrl;
      } else {
        currentUrlEl.textContent = 'No active tab URL detected';
      }
    });
  } else {
    // Fallback for direct browser testing outside extension runner
    activeTabUrl = 'https://www.google.com';
    currentUrlEl.textContent = activeTabUrl + ' (Demo Mode)';
  }
}

async function analyzeUrl(targetUrl) {
  if (!targetUrl) return;

  errorBox.classList.add('hidden');
  resultCard.classList.add('hidden');
  loadingBox.classList.remove('hidden');

  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || 'Analysis request failed.');
    }

    const data = await res.json();
    displayResult(data);
  } catch (err) {
    errorBox.textContent = err.message || 'Failed to reach PhishNet Sentinel backend.';
    errorBox.classList.remove('hidden');
  } finally {
    loadingBox.classList.add('hidden');
  }
}

function displayResult(data) {
  const isPhish = data.prediction === 'phishing';

  verdictBanner.className = 'verdict-banner ' + (isPhish ? 'phish' : 'safe');
  verdictIcon.textContent = isPhish ? '??' : '???';
  verdictTitle.textContent = isPhish ? 'PHISHING DETECTED' : 'LIKELY LEGITIMATE';
  verdictRisk.textContent = `Risk Level: ${data.risk_level}`;

  statPhishing.textContent = `${data.phishing_probability}%`;
  statLegitimate.textContent = `${data.legitimate_probability}%`;
  statRisk.textContent = `${data.risk_score}/100`;

  // Render top 4 SHAP local features
  shapList.innerHTML = '';
  if (data.explanation && Array.isArray(data.explanation)) {
    data.explanation.slice(0, 4).forEach((item) => {
      const row = document.createElement('div');
      row.className = 'shap-item';
      const isRisk = item.shap_value > 0;
      row.innerHTML = `
        <span class="name">${item.feature_name}</span>
        <span class="impact ${isRisk ? 'impact-phish' : 'impact-legit'}">
          ${isRisk ? '+' : ''}${item.shap_value}
        </span>
      `;
      shapList.appendChild(row);
    });
  }

  recommendationText.textContent = data.recommendation;
  resultCard.classList.remove('hidden');
}

scanActiveBtn.addEventListener('click', () => {
  if (activeTabUrl && !activeTabUrl.startsWith('chrome://') && !activeTabUrl.startsWith('edge://')) {
    analyzeUrl(activeTabUrl);
  } else {
    errorBox.textContent = 'Cannot scan internal browser pages. Enter a web URL below.';
    errorBox.classList.remove('hidden');
  }
});

scanManualBtn.addEventListener('click', () => {
  const val = manualUrlEl.value.trim();
  if (val) {
    analyzeUrl(val);
  }
});

manualUrlEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    scanManualBtn.click();
  }
});

// Init
detectActiveTab();
checkHealth();
