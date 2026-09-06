import React, { useState } from 'react';
import { AlertOctagon, X, Send, CheckCircle2 } from 'lucide-react';
import { reportPhishingUrl } from '../services/api';

export default function ReportModal({ isOpen, onClose }) {
  const [reportUrl, setReportUrl] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!reportUrl.trim()) return;

    setSubmitting(true);
    setMessage('');
    setError('');

    try {
      const data = await reportPhishingUrl(reportUrl.trim());
      setMessage(data.message || 'Phishing URL queued for continuous model retraining!');
      setReportUrl('');
    } catch (err) {
      setError(err.message || 'Failed to submit report.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5 relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-rose-950/80 border border-rose-800/60 rounded-xl text-rose-400">
            <AlertOctagon className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Report Threat Domain</h3>
            <p className="text-xs text-slate-400">Submit suspicious URLs for continuous AI model retraining.</p>
          </div>
        </div>

        {message ? (
          <div className="p-4 bg-emerald-950/60 border border-emerald-800/60 rounded-xl text-emerald-300 text-sm flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Threat Report Submitted!</p>
              <p className="text-xs text-emerald-400/90 mt-1">{message}</p>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Suspicious Website URL
              </label>
              <input
                type="text"
                value={reportUrl}
                onChange={(e) => setReportUrl(e.target.value)}
                placeholder="e.g. http://suspicious-verify-bank.xyz/login.php"
                className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-rose-500 text-sm"
              />
            </div>

            {error && (
              <p className="text-xs text-rose-400 bg-rose-950/40 p-2.5 rounded-lg border border-rose-900/50">
                {error}
              </p>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium rounded-xl transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting || !reportUrl.trim()}
                className="px-5 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-rose-600/20 flex items-center gap-2 cursor-pointer"
              >
                <Send className="w-4 h-4" />
                <span>{submitting ? 'Submitting...' : 'Submit Threat'}</span>
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
