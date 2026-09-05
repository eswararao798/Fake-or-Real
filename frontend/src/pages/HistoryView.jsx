import React from 'react';
import { Search, Trash2, History as HistoryIcon } from 'lucide-react';

export default function HistoryView({ 
  history, filteredHistory, historySearch, setHistorySearch, 
  historyFilter, setHistoryFilter, deleteHistoryItem, clearAllHistory, 
  onLoadUrl 
}) {
  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Scan Audit Log & History</h2>
          <p className="text-sm text-slate-400 mt-0.5">Historical verification logs stored in local database.</p>
        </div>
        <button
          onClick={clearAllHistory}
          disabled={history.length === 0}
          className="px-3.5 py-2 bg-red-950/40 border border-red-800/60 hover:bg-red-900/40 text-red-300 text-xs font-semibold rounded-xl flex items-center gap-2 transition-colors disabled:opacity-40 cursor-pointer"
        >
          <Trash2 className="w-4 h-4" />
          Clear All Logs
        </button>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3.5 pointer-events-none" />
          <input
            type="text"
            value={historySearch}
            onChange={(e) => setHistorySearch(e.target.value)}
            placeholder="Search scanned URLs..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>
        <div className="flex gap-1 bg-slate-900 p-1 border border-slate-800 rounded-xl">
          {['ALL', 'PHISHING', 'LEGITIMATE'].map(flt => (
            <button
              key={flt}
              onClick={() => setHistoryFilter(flt)}
              className={'px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ' +
                (historyFilter === flt ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-white')
              }
            >
              {flt}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        {filteredHistory.length === 0 ? (
          <div className="p-12 text-center text-slate-500 space-y-2">
            <HistoryIcon className="w-8 h-8 mx-auto text-slate-600" />
            <p className="text-sm">No scan records match your criteria.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Target URL</th>
                  <th className="py-3 px-4">Prediction</th>
                  <th className="py-3 px-4">Phish Prob</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredHistory.map(item => (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 font-mono font-medium max-w-xs truncate text-white" title={item.url}>
                      {item.url}
                    </td>
                    <td className="py-3 px-4">
                      <span className={'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide ' +
                        (item.prediction === 'phishing'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30')
                      }>
                        {item.prediction}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono">{item.phishing_probability}%</td>
                    <td className="py-3 px-4 font-mono font-bold">
                      {item.risk_score} / 100
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <button
                        onClick={() => onLoadUrl(item.url)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] transition-colors cursor-pointer"
                      >
                        Load
                      </button>
                      <button
                        onClick={() => deleteHistoryItem(item.id)}
                        className="p-1 text-slate-500 hover:text-red-400 transition-colors cursor-pointer"
                        title="Delete item"
                      >
                        <Trash2 className="w-3.5 h-3.5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
