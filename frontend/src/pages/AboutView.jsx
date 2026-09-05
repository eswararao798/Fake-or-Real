import React from 'react';
import { BrainCircuit, Layers, Lock } from 'lucide-react';

export default function AboutView() {
  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      <div>
        <h2 className="text-3xl font-extrabold text-white tracking-tight">About PhishNet Sentinel</h2>
        <p className="text-slate-400 mt-1">Explainable AI (XAI) Cybersecurity Architecture for Real-Time Threat Analysis.</p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h3 className="text-lg font-bold text-cyan-400 flex items-center gap-2">
          <BrainCircuit className="w-5 h-5" />
          1. Core Problem & Methodology
        </h3>
        <p className="text-sm text-slate-300 leading-relaxed">
          Phishing attacks trick users into providing credentials and banking info. Traditional blacklists suffer from latency 
          on newly deployed domains. PhishNet Sentinel analyzes 24 lexical and structural features via a trained Random Forest 
          classifier paired with real-time SHAP explainability.
        </p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h3 className="text-lg font-bold text-cyan-400 flex items-center gap-2">
          <Layers className="w-5 h-5" />
          2. Explainable AI (SHAP) Integration
        </h3>
        <p className="text-sm text-slate-300 leading-relaxed">
          SHAP explicitly quantifies which URL features increase phishing probability (Positive SHAP) and which features 
          indicate legitimate patterns (Negative SHAP).
        </p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h3 className="text-lg font-bold text-cyan-400 flex items-center gap-2">
          <Lock className="w-5 h-5" />
          3. Transparent Risk Bands
        </h3>
        <p className="text-sm text-slate-300 leading-relaxed">
          Classifications are probabilistic risk assessments. PhishNet Sentinel defines 5 risk bands (LOW 0-20, MODERATE 21-40, 
          MEDIUM 41-60, HIGH 61-80, CRITICAL 81-100). Users should always verify certificates on unknown websites.
        </p>
      </div>
    </div>
  );
}
