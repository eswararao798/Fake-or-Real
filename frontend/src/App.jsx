import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import ScannerView from './pages/ScannerView';
import DashboardView from './pages/DashboardView';
import HistoryView from './pages/HistoryView';
import AboutView from './pages/AboutView';
import { analyzeUrl, fetchStats, fetchModelInfo, fetchHistory, deleteHistory } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState('');
  
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [modelInfo, setModelInfo] = useState(null);
  const [historySearch, setHistorySearch] = useState('');
  const [historyFilter, setHistoryFilter] = useState('ALL');

  useEffect(() => {
    if (activeTab === 'dashboard') {
      fetchStats().then(setStats).catch(console.error);
      fetchModelInfo().then(setModelInfo).catch(console.error);
    } else if (activeTab === 'history') {
      loadHistory();
    }
  }, [activeTab]);

  const loadHistory = async () => {
    try {
      const data = await fetchHistory();
      setHistory(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!urlInput.trim()) return;

    setLoading(true);
    setScanError('');
    setScanResult(null);
    setScanStep(1);

    const t1 = setTimeout(() => setScanStep(2), 200);
    const t2 = setTimeout(() => setScanStep(3), 400);
    const t3 = setTimeout(() => setScanStep(4), 600);

    try {
      const data = await analyzeUrl(urlInput.trim());
      setScanStep(5);
      setTimeout(() => {
        setScanResult(data);
        setLoading(false);
      }, 250);
    } catch (err) {
      setScanError(err.message || 'Failed to analyze URL');
      setLoading(false);
    } finally {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    }
  };

  const deleteHistoryItem = async (id) => {
    try {
      await deleteHistory(id);
      loadHistory();
    } catch (e) {
      console.error(e);
    }
  };

  const clearAllHistory = async () => {
    if (!confirm('Clear all historical scans?')) return;
    try {
      await deleteHistory();
      setHistory([]);
    } catch (e) {
      console.error(e);
    }
  };

  const filteredHistory = history.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(historySearch.toLowerCase());
    const matchesFilter = historyFilter === 'ALL' || item.prediction.toUpperCase() === historyFilter;
    return matchesSearch && matchesFilter;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-white">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'scanner' && (
          <ScannerView
            urlInput={urlInput}
            setUrlInput={setUrlInput}
            handleScan={handleScan}
            loading={loading}
            scanStep={scanStep}
            scanError={scanError}
            scanResult={scanResult}
          />
        )}

        {activeTab === 'dashboard' && (
          <DashboardView stats={stats} modelInfo={modelInfo} />
        )}

        {activeTab === 'history' && (
          <HistoryView
            history={history}
            filteredHistory={filteredHistory}
            historySearch={historySearch}
            setHistorySearch={setHistorySearch}
            historyFilter={historyFilter}
            setHistoryFilter={setHistoryFilter}
            deleteHistoryItem={deleteHistoryItem}
            clearAllHistory={clearAllHistory}
            onLoadUrl={(url) => {
              setUrlInput(url);
              setActiveTab('scanner');
            }}
          />
        )}

        {activeTab === 'about' && <AboutView />}
      </main>

      <footer className="border-t border-slate-800/80 bg-slate-950/80 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <p>© 2026 PhishNet Sentinel. B.Tech Cybersecurity & AI Final-Year Project.</p>
          <p className="text-slate-400">FastAPI + Scikit-learn + SHAP + React</p>
        </div>
      </footer>
    </div>
  );
}
