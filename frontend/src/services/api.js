export const analyzeUrl = async (url) => {
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Analysis failed');
  return data;
};

export const fetchStats = async () => {
  const res = await fetch('/api/stats');
  if (!res.ok) throw new Error('Failed to fetch statistics');
  return await res.json();
};

export const fetchHistory = async () => {
  const res = await fetch('/api/history');
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return await res.json();
};

export const fetchModelInfo = async () => {
  const res = await fetch('/api/model-info');
  if (!res.ok) throw new Error('Failed to fetch model info');
  return await res.json();
};

export const deleteHistory = async (id) => {
  const url = id ? `/api/history/${id}` : '/api/history';
  const res = await fetch(url, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete history');
  return await res.json();
};

export const reportPhishingUrl = async (url) => {
  const res = await fetch('/api/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Reporting failed');
  return data;
};

export const triggerModelRetrain = async () => {
  const res = await fetch('/api/retrain', { method: 'POST' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Retraining failed');
  return data;
};
