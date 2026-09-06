import React from 'react';
import { Shield, Search, Activity, History, Info, AlertOctagon, CheckCircle2 } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, onOpenReportModal }) {
  const navItems = [
    { id: 'scanner', label: 'URL Scanner', icon: Search },
    { id: 'dashboard', label: 'Threat Dashboard', icon: Activity },
    { id: 'history', label: 'Scan Audit Log', icon: History },
    { id: 'about', label: 'Methodology & XAI', icon: Info },
  ];

  return (
    <header className="border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3.5 cursor-pointer" onClick={() => setActiveTab('scanner')}>
          <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-lg tracking-tight text-white font-sans">
                PhishNet<span className="text-cyan-400">Sentinel</span>
              </span>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
                Enterprise XAI
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-normal">Cyber Threat Intelligence Platform</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <nav className="flex space-x-1 sm:space-x-2">
            {navItems.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all duration-200 cursor-pointer ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-cyan-500/40 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span className="hidden md:inline">{tab.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="hidden lg:flex items-center gap-2 pl-3 border-l border-slate-800">
            <button
              onClick={onOpenReportModal}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900/60 border border-rose-700/50 text-rose-300 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
            >
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>Report Phishing</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
