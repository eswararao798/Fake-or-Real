import React from 'react';
import { Shield, Search, Activity, History, Info } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'scanner', label: 'Scanner', icon: Search },
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'history', label: 'History', icon: History },
    { id: 'about', label: 'About & XAI', icon: Info },
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3 cursor-pointer" onClick=
{() => setActiveTab('scanner')}>
          <div className="p-2 bg-gradient-to-tr from-cyan-600 to-blue-600 rounded-lg shadow-lg shadow-cyan-500/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <span className="font-bold text-xl tracking-tight text-white flex items-center gap-1.5">
              PhishNet <span className="text-cyan-400">Sentinel</span>
            </span>
            <p className="text-[11px] text-slate-400 font-medium tracking-wide">Detect. Explain. Protect.</p>
          </div>
        </div>

        <nav className="flex space-x-1 sm:space-x-2">
          {navItems.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-colors ${isActive ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'}`}
              >
                <Icon className="w-4 h-4" />
                <span className="hidden sm:inline">{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
