import { useState, useEffect } from 'react';
import { blocked as blockedApi } from '../services/api';
import type { BlockedQuery } from '../types/api';

export default function Blocked() {
  const [blocked, setBlocked] = useState<BlockedQuery[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);

  const fetchBlocked = async () => {
    try {
      setLoading(true);
      const data = await blockedApi.getBlocked();
      setBlocked(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load blocked queries');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlocked();
  }, []);

  const handleClearHistory = async () => {
    if (!window.confirm('Are you sure you want to clear all blocked query history?')) {
      return;
    }

    try {
      setClearing(true);
      await blockedApi.clearBlocked();
      fetchBlocked();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear history');
    } finally {
      setClearing(false);
    }
  };

  const getThreatLevelBadge = (level: string) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-400',
      high: 'bg-orange-500/20 text-orange-400',
      medium: 'bg-amber-500/20 text-amber-400',
      low: 'bg-slate-500/20 text-slate-400',
    };
    return colors[level as keyof typeof colors] || 'bg-slate-500/20 text-slate-400';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading blocked queries...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-red-400">{error}</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Blocked Queries</h1>
          <p className="text-slate-400 mt-1">Total blocked: {blocked.length}</p>
        </div>
        <button
          onClick={handleClearHistory}
          disabled={clearing || blocked.length === 0}
          className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-slate-600 text-white rounded-lg transition-colors"
        >
          {clearing ? 'Clearing...' : 'Clear History'}
        </button>
      </div>

      {blocked.length === 0 ? (
        <div className="bg-slate-800 rounded-lg p-8 text-center">
          <p className="text-slate-400">No blocked queries</p>
        </div>
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-slate-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Domain</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Client IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Reason</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Threat Level</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Feed Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Blocked At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {blocked.map((item, index) => (
                <tr key={index} className="hover:bg-slate-700/50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-white font-mono">{item.domain}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300 font-mono">{item.client_ip}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{item.reason}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs font-medium rounded uppercase ${getThreatLevelBadge(item.threat_level)}`}>
                      {item.threat_level}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">{item.feed_source || 'N/A'}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                    {new Date(item.blocked_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
