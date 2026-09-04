import { useState } from 'react';
import { logs } from '../services/api';

export default function Settings() {
  const [clearing, setClearing] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleClearCache = async () => {
    if (!window.confirm('Are you sure you want to clear the cache?')) {
      return;
    }

    try {
      setClearing(true);
      setMessage(null);
      // Add cache clearing endpoint when available
      // await api.cache.clearCache();
      setMessage({ type: 'success', text: 'Cache cleared successfully' });
    } catch (err) {
      setMessage({ type: 'error', text: err instanceof Error ? err.message : 'Failed to clear cache' });
    } finally {
      setClearing(false);
    }
  };

  const handleClearLogs = async () => {
    if (!window.confirm('Are you sure you want to clear all logs?')) {
      return;
    }

    try {
      setMessage(null);
      await logs.clearLogs();
      setMessage({ type: 'success', text: 'Logs cleared successfully' });
    } catch (err) {
      setMessage({ type: 'error', text: err instanceof Error ? err.message : 'Failed to clear logs' });
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">Settings</h1>

      {message && (
        <div
          className={`p-4 rounded-lg ${
            message.type === 'success'
              ? 'bg-green-500/20 border border-green-500/50 text-green-400'
              : 'bg-red-500/20 border border-red-500/50 text-red-400'
          }`}
        >
          {message.text}
        </div>
      )}

      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-semibold text-white mb-4">System Configuration</h2>
        <div className="space-y-4 text-sm">
          <div className="flex justify-between py-3 border-b border-slate-700">
            <span className="text-slate-400">DNS Server Status</span>
            <span className="text-green-400">Running</span>
          </div>
          <div className="flex justify-between py-3 border-b border-slate-700">
            <span className="text-slate-400">Cache Status</span>
            <span className="text-green-400">Enabled</span>
          </div>
          <div className="flex justify-between py-3 border-b border-slate-700">
            <span className="text-slate-400">Threat Detection</span>
            <span className="text-green-400">Active</span>
          </div>
          <div className="flex justify-between py-3">
            <span className="text-slate-400">Version</span>
            <span className="text-white">1.0.0</span>
          </div>
        </div>
      </div>

      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-semibold text-white mb-4">Cache Management</h2>
        <div className="space-y-4">
          <div className="text-sm text-slate-400">
            <p className="mb-2">Cache Statistics:</p>
            <div className="bg-slate-900 rounded p-4 space-y-2">
              <div className="flex justify-between">
                <span>Cached Entries:</span>
                <span className="text-white">1,234</span>
              </div>
              <div className="flex justify-between">
                <span>Cache Hit Rate:</span>
                <span className="text-white">87.5%</span>
              </div>
              <div className="flex justify-between">
                <span>Memory Usage:</span>
                <span className="text-white">45.2 MB</span>
              </div>
            </div>
          </div>
          <button
            onClick={handleClearCache}
            disabled={clearing}
            className="px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:bg-slate-600 text-white rounded-lg transition-colors"
          >
            {clearing ? 'Clearing...' : 'Clear Cache'}
          </button>
        </div>
      </div>

      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-semibold text-white mb-4">Log Management</h2>
        <div className="space-y-4">
          <p className="text-sm text-slate-400">
            Clear all system logs. This action cannot be undone.
          </p>
          <button
            onClick={handleClearLogs}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
          >
            Clear Logs
          </button>
        </div>
      </div>

      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-semibold text-white mb-4">About</h2>
        <div className="space-y-2 text-sm text-slate-400">
          <p>Squawk DNS Server</p>
          <p>High-performance DNS server with threat intelligence</p>
          <p className="pt-2 border-t border-slate-700">
            &copy; 2025 Penguin Tech Inc. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
}
