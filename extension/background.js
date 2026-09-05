// PhishNet Sentinel - Student Safety Interceptor
const API_BASE = 'http://localhost:8000';

// Instant local heuristics for immediate blocking before full ML check
const BLOCKED_DOMAINS = [
  '1xbet', 'bet365', 'betway', 'parimatch', 'melbet', '22bet',
  'dafabet', 'mostbet', 'linebet', 'lotus365', 'fairplay', 'stake.com',
  'pornhub', 'xvideos', 'xnxx', 'xhamster', 'redtube', 'youporn',
  'chaturbate', 'stripchat', 'livejasmin', 'onlyfans'
];

function isBlockedLocally(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    for (const b of BLOCKED_DOMAINS) {
      if (host.includes(b)) {
        return {
          blocked: true,
          category: b.includes('bet') || b.includes('stake') ? 'Betting & Gambling' : '18+ Adult Content',
          reason: `Domain matched blacklisted high-risk pattern '${b}' prohibited for students.`
        };
      }
    }
  } catch (e) {
    // Ignore invalid url parse
  }
  return { blocked: false };
}

// Intercept browser navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process main frame navigation (not sub-iframes)
  if (details.frameId !== 0) return;
  const targetUrl = details.url;

  if (!targetUrl || targetUrl.startsWith('chrome://') || targetUrl.startsWith('edge://') || targetUrl.startsWith('chrome-extension://')) {
    return;
  }

  // 1. Fast local check
  const localCheck = isBlockedLocally(targetUrl);
  if (localCheck.blocked) {
    const blockPageUrl = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(targetUrl)}&category=${encodeURIComponent(localCheck.category)}&reason=${encodeURIComponent(localCheck.reason)}`
    );
    chrome.tabs.update(details.tabId, { url: blockPageUrl });
    return;
  }

  // 2. Query backend for deeper student safety & AI phishing check
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200);

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      if (data.student_safety && data.student_safety.is_blocked) {
        const blockPageUrl = chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(targetUrl)}&category=${encodeURIComponent(data.student_safety.category_label)}&reason=${encodeURIComponent(data.student_safety.reason)}`
        );
        chrome.tabs.update(details.tabId, { url: blockPageUrl });
      }
    }
  } catch (err) {
    // Backend offline or timeout; allow non-blacklisted navigation to proceed
  }
});
