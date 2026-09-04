import { useState, useEffect } from 'react';
import { threats as threatsApi } from '../services/api';
import type { IOCFeed, IOCEntry } from '../types/api';

export default function Threats() {
  const [threats, setThreats] = useState<{ feeds: IOCFeed[]; recent_entries: IOCEntry[] } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const data = await threatsApi.getThreats();
      setThreats(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load threat data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  const handleUpdateFeeds = async () => {
    try {
      setUpdating(true);
      await threatsApi.updateFeeds();
      fetchThreats();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update feeds');
    } finally {
      setUpdating(false);
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
        <div className="text-slate-400">Loading threat data...</div>
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
        <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
        <button
          onClick={handleUpdateFeeds}
          disabled={updating}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white rounded-lg transition-colors"
        >
          {updating ? 'Updating...' : 'Update Feeds'}
        </button>
      </div>

      <div>
        <h2 className="text-xl font-semibold text-white mb-4">Active Feeds</h2>
        {threats?.feeds && threats.feeds.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {threats.feeds.map((feed: IOCFeed) => (
              <div key={feed.id} className="bg-slate-800 rounded-lg p-6 border border-slate-700">
                <h3 className="text-lg font-semibold text-white mb-2">{feed.name}</h3>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Type:</span>
                    <span className="text-white">{feed.feed_type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Entries:</span>
                    <span className="text-white">{feed.entry_count || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Last Updated:</span>
                    <span className="text-slate-400">
                      {feed.last_updated ? new Date(feed.last_updated).toLocaleDateString() : 'Never'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800 rounded-lg p-8 text-center">
            <p className="text-slate-400">No active feeds configured</p>
          </div>
        )}
      </div>

      <div>
        <h2 className="text-xl font-semibold text-white mb-4">Recent IOC Entries</h2>
        {threats?.recent_entries && threats.recent_entries.length > 0 ? (
          <div className="bg-slate-800 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-slate-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Indicator</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Threat Level</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Description</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">First Seen</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {threats.recent_entries.map((ioc: IOCEntry, index: number) => (
                  <tr key={index} className="hover:bg-slate-700/50">
                    <td className="px-6 py-4 text-sm text-white font-mono">{ioc.indicator}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">{ioc.indicator_type}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-medium rounded uppercase ${getThreatLevelBadge(ioc.threat_level)}`}>
                        {ioc.threat_level}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-300 max-w-xs truncate">{ioc.description || 'N/A'}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                      {new Date(ioc.first_seen).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                      {new Date(ioc.last_seen).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="bg-slate-800 rounded-lg p-8 text-center">
            <p className="text-slate-400">No recent IOC entries</p>
          </div>
        )}
      </div>
    </div>
  );
}
