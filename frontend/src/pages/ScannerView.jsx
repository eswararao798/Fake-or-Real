import React from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Search, ExternalLink, 
  RefreshCw, BarChart3, CheckCircle2, XCircle, Globe, FileText,
  GraduationCap, Ban, Lock
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function ScannerView({ 
  urlInput, setUrlInput, handleScan, loading, scanStep, scanError, scanResult 
}) {
  return (
    <div className="space-y-8">
      <div className="text-center max-w-3xl mx-auto space-y-4 pt-4 pb-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 text-xs font-semibold uppercase tracking-wider">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
          Explainable AI Phishing Defense
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
          Verify Website Authenticity <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500">
            With Interpretable Machine Learning
          </span>
        </h1>
        <p className="text-slate-400 text-sm sm:text-base">
          Analyze 24 lexical features, domain entropy, SSL indicators, and inspect full SHAP local feature contributions.
        </p>

        <form onSubmit={handleScan} className="mt-6 flex flex-col sm:flex-row gap-2 max-w-2xl mx-auto">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="e.g. https://example.com or http://secure-login-verify.xyz"
              className="w-full pl-11 pr-4 py-3.5 bg-slate-900/90 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm shadow-inner"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !urlInput.trim()}
            className="px-6 py-3.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-semibold rounded-xl transition-all shadow-lg shadow-cyan-500/25 flex items-center justify-center gap-2 text-sm cursor-pointer"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{loading ? 'Analyzing...' : 'Analyze Website'}</span>
          </button>
        </form>

        <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-xs text-slate-400">
          <span className="text-slate-500">Quick samples:</span>
          <button 
            type="button"
            onClick={() => setUrlInput('https://en.wikipedia.org/wiki/Computer_science')}
            className="px-2.5 py-1 rounded bg-slate-900 border border-cyan-800/40 hover:border-cyan-500 text-cyan-300 transition-colors cursor-pointer"
          >
            🎓 Wikipedia (Student Safe)
          </button>
          <button 
            type="button"
            onClick={() => setUrlInput('https://indian.1xbet.com/en?v=2')}
            className="px-2.5 py-1 rounded bg-slate-900 border border-rose-800/40 hover:border-rose-500 text-rose-300 transition-colors cursor-pointer"
          >
            🚫 1xBet (Illegal Betting)
          </button>
          <button 
            type="button"
            onClick={() => setUrlInput('http://secure-paypal-login-account-update.xyz/webscr?cmd=login')}
            className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 transition-colors cursor-pointer"
          >
            🔴 Fake Phishing Test
          </button>
        </div>
      </div>

      {loading && (
        <div className="max-w-xl mx-auto p-6 bg-slate-900/80 border border-slate-800 rounded-2xl shadow-xl space-y-4">
          <div className="flex items-center justify-between text-sm">
            <span className="font-medium text-cyan-400 flex items-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin" />
              Analyzing website security characteristics...
            </span>
            <span className="text-xs text-slate-400 font-mono">Step {scanStep} / 5</span>
          </div>
          <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
            <div 
              className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 transition-all duration-300"
              style={{ width: (scanStep / 5) * 100 + '%' }}
            ></div>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 pt-2">
            <span className={scanStep >= 1 ? 'text-cyan-400 font-medium' : ''}>✓ 1. Validating URL & SSRF</span>
            <span className={scanStep >= 2 ? 'text-cyan-400 font-medium' : ''}>✓ 2. Extracting 24 Features</span>
            <span className={scanStep >= 3 ? 'text-cyan-400 font-medium' : ''}>✓ 3. Evaluating Random Forest</span>
            <span className={scanStep >= 4 ? 'text-cyan-400 font-medium' : ''}>✓ 4. Computing SHAP Values</span>
            <span className={scanStep >= 5 ? 'text-cyan-400 font-medium' : ''}>✓ 5. Generating Security Review</span>
          </div>
        </div>
      )}

      {scanError && (
        <div className="max-w-2xl mx-auto p-4 bg-red-950/40 border border-red-800/60 rounded-xl text-red-300 text-sm flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-red-200">Analysis Error</h4>
            <p className="mt-0.5 text-xs text-red-300/90">{scanError}</p>
          </div>
        </div>
      )}

      {scanResult && !loading && (
        <div className="space-y-6">
          <div className={'p-6 rounded-2xl border shadow-2xl relative overflow-hidden ' +
            (scanResult.student_safety?.is_blocked || scanResult.prediction === 'phishing'
              ? 'bg-gradient-to-br from-red-950/40 via-slate-900 to-slate-950 border-red-800/60 shadow-red-950/20'
              : scanResult.student_safety?.category === 'EDUCATIONAL_RESOURCE'
                ? 'bg-gradient-to-br from-cyan-950/40 via-slate-900 to-slate-950 border-cyan-500/50 shadow-cyan-950/20'
                : 'bg-gradient-to-br from-emerald-950/30 via-slate-900 to-slate-950 border-emerald-800/50 shadow-emerald-950/20')
          }>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  {scanResult.student_safety?.category === 'BETTING_AND_GAMBLING' ? (
                    <span className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold uppercase tracking-wider bg-rose-950 text-rose-300 border border-rose-600 shadow-lg shadow-rose-950/80">
                      <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse" />
                      🔴 PHISHING / ILLEGAL BETTING APP DETECTED
                    </span>
                  ) : scanResult.student_safety?.category === 'DEVELOPER_PLATFORM' ? (
                    <span className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold uppercase tracking-wider bg-cyan-950 text-cyan-300 border border-cyan-500 shadow-lg shadow-cyan-950/80">
                      <GraduationCap className="w-4 h-4 text-cyan-400" />
                      💻 DEVELOPER PLATFORM (STUDENT APPROVED)
                    </span>
                  ) : scanResult.student_safety?.category === 'EDUCATIONAL_RESOURCE' ? (
                    <span className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold uppercase tracking-wider bg-emerald-950 text-emerald-300 border border-emerald-500 shadow-lg shadow-emerald-950/80">
                      <GraduationCap className="w-4 h-4 text-emerald-400" />
                      🎓 EDUCATIONAL RESOURCE (STUDENT APPROVED)
                    </span>
                  ) : scanResult.student_safety?.is_blocked ? (
                    <span className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold uppercase tracking-wider bg-rose-950 text-rose-300 border border-rose-600 shadow-lg shadow-rose-950/80">
                      <Ban className="w-4 h-4 text-rose-400" />
                      🚫 RESTRICTED / BLOCKED FOR STUDENTS
                    </span>
                  ) : (
                    <span className={'inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-extrabold uppercase tracking-wider ' +
                      (scanResult.prediction === 'phishing'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30')
                    }>
                      {scanResult.prediction === 'phishing' ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                      {scanResult.prediction === 'phishing' ? '🔴 PHISHING CLONE DETECTED' : '🟢 VERIFIED LEGITIMATE DOMAIN'}
                    </span>
                  )}

                  {scanResult.student_safety?.purpose && (
                    <span className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-900 text-slate-200 border border-slate-700">
                      Purpose: {scanResult.student_safety.purpose}
                    </span>
                  )}
                </div>

                <h2 className="text-xl sm:text-2xl font-bold text-white break-all flex items-center gap-2">
                  {scanResult.url}
                  {scanResult.student_safety?.is_blocked ? (
                    <span className="inline-flex items-center gap-1 text-xs text-rose-400 font-normal px-2 py-0.5 bg-rose-950/60 rounded border border-rose-800/60" title="Outbound link disabled for student protection">
                      <Lock className="w-3.5 h-3.5 inline" /> Restricted Access
                    </span>
                  ) : (
                    <a href={scanResult.url} target="_blank" rel="noreferrer" className="text-slate-400 hover:text-cyan-400" title="Open verified site in new tab">
                      <ExternalLink className="w-4 h-4 inline" />
                    </a>
                  )}
                </h2>
                
                <p className={'text-sm max-w-2xl font-medium ' + (scanResult.student_safety?.is_blocked ? 'text-rose-200' : 'text-slate-300')}>
                  {scanResult.recommendation}
                </p>
              </div>

              <div className="flex items-center gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800/80">
                <div className="text-center">
                  <div className="text-xs uppercase font-semibold tracking-wider text-red-400">
                    {scanResult.student_safety?.category === 'BETTING_AND_GAMBLING' ? 'Risk Level' : 'Phishing Prob'}
                  </div>
                  <div className="text-2xl sm:text-3xl font-extrabold text-red-400 font-mono">
                    {scanResult.phishing_probability}%
                  </div>
                </div>
                <div className="h-10 w-px bg-slate-800"></div>
                <div className="text-center">
                  <div className="text-xs uppercase font-semibold tracking-wider text-emerald-400">Legitimate Prob</div>
                  <div className="text-2xl sm:text-3xl font-extrabold text-emerald-400 font-mono">
                    {scanResult.legitimate_probability}%
                  </div>
                </div>
                <div className="h-10 w-px bg-slate-800"></div>
                <div className="text-center">
                  <div className="text-xs uppercase font-semibold tracking-wider text-cyan-400">Threat Score</div>
                  <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono">
                    {scanResult.risk_score} <span className="text-xs text-slate-500 font-normal">/100</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-5 space-y-6">
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-cyan-400" />
                  Website Security Review
                </h3>
                <p className="text-sm text-slate-300 leading-relaxed">
                  {scanResult.security_review.overall_summary}
                </p>

                <div className="space-y-2 pt-2">
                  <h4 className="text-xs uppercase font-bold tracking-wider text-slate-400">
                    Detected Issues ({scanResult.security_review.detected_issues.length})
                  </h4>
                  {scanResult.security_review.detected_issues.length === 0 ? (
                    <div className="text-xs text-slate-500 italic">No critical structural abnormalities detected.</div>
                  ) : (
                    <ul className="space-y-1.5">
                      {scanResult.security_review.detected_issues.map((issue, idx) => (
                        <li key={idx} className="text-xs text-red-300 flex items-start gap-2 bg-red-950/20 p-2 rounded-lg border border-red-900/30">
                          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                          <span>{issue}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="space-y-2 pt-2">
                  <h4 className="text-xs uppercase font-bold tracking-wider text-slate-400">
                    Benign Indicators ({scanResult.security_review.positive_indicators.length})
                  </h4>
                  <ul className="space-y-1.5">
                    {scanResult.security_review.positive_indicators.map((pos, idx) => (
                      <li key={idx} className="text-xs text-emerald-300 flex items-start gap-2 bg-emerald-950/20 p-2 rounded-lg border border-emerald-900/30">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                        <span>{pos}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="pt-3 border-t border-slate-800 text-[11px] text-slate-500 italic">
                  {scanResult.security_review.disclaimer}
                </div>
              </div>

              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3">
                <h3 className="text-sm font-bold text-white flex items-center justify-between">
                  <span>Extracted URL Features (24 Metrics)</span>
                  <span className="text-xs text-slate-500 font-mono">Lexical & Structural</span>
                </h3>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">URL Length:</span>
                    <span className="font-mono font-bold text-white">{scanResult.features.url_length}</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Subdomains:</span>
                    <span className="font-mono font-bold text-white">{scanResult.features.num_subdomains}</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Domain Entropy:</span>
                    <span className="font-mono font-bold text-white">{scanResult.features.domain_entropy}</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">HTTPS Protocol:</span>
                    <span className="font-mono font-bold text-white">{scanResult.features.has_https ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Numeric IP:</span>
                    <span className="font-mono font-bold text-white">{scanResult.features.has_ip ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Special Chars:</span>
                    <span className="font-mono font-bold text-white">{scanResult.features.num_special_chars}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="lg:col-span-7 space-y-6">
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      <BarChart3 className="w-5 h-5 text-cyan-400" />
                      Why Did the Model Reach This Result?
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      SHAP values explicitly measure each feature push toward Phishing (+) or Legitimacy (-).
                    </p>
                  </div>
                  <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-800 text-cyan-400 self-start sm:self-auto">
                    TreeExplainer
                  </span>
                </div>

                <div className="h-72 w-full pt-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={scanResult.explanation.slice(0, 8)}
                      margin={{ top: 5, right: 30, left: 120, bottom: 5 }}
                    >
                      <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                      <YAxis 
                        type="category" 
                        dataKey="feature_name" 
                        tick={{ fill: '#cbd5e1', fontSize: 11 }} 
                        width={110} 
                      />
                      <Tooltip 
                        content={({ active, payload }) => {
                          if (active && payload && payload.length) {
                            const d = payload[0].payload;
                            return (
                              <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl text-xs space-y-1">
                                <p className="font-bold text-white">{d.feature_name}</p>
                                <p className="text-slate-300">Raw Value: <span className="font-mono text-cyan-400">{String(d.raw_value)}</span></p>
                                <p className="text-slate-300">SHAP Contribution: <span className="font-mono font-bold">{d.shap_value}</span></p>
                                <p className="text-slate-400 italic">{d.description}</p>
                              </div>
                            );
                          }
                          return null;
                        }}
                      />
                      <Bar dataKey="shap_value" radius={[0, 4, 4, 0]}>
                        {scanResult.explanation.slice(0, 8).map((entry, index) => (
                          <Cell 
                            key={'cell-' + index} 
                            fill={entry.shap_value > 0 ? '#ef4444' : '#10b981'} 
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="space-y-2 pt-2">
                  <h4 className="text-xs uppercase font-bold tracking-wider text-slate-400">
                    Top Influential Signals
                  </h4>
                  <div className="space-y-2">
                    {scanResult.explanation.slice(0, 5).map((item, idx) => (
                      <div key={idx} className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl flex items-center justify-between text-xs">
                        <div className="space-y-0.5 max-w-[75%]">
                          <div className="font-semibold text-white flex items-center gap-2">
                            <span>{item.feature_name}</span>
                            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">val: {String(item.raw_value)}</span>
                          </div>
                          <p className="text-slate-400 text-[11px]">{item.description}</p>
                        </div>
                        <div className="text-right">
                          <span className={'font-mono font-bold text-sm ' + (item.shap_value > 0 ? 'text-red-400' : 'text-emerald-400')}>
                            {item.shap_value > 0 ? '+' + item.shap_value : item.shap_value}
                          </span>
                          <div className="text-[10px] text-slate-500">SHAP impact</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
