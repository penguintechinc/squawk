import { useState, useEffect } from 'react';
import { FormModalBuilder } from '@penguin/react_libs';
import { ioc, threats } from '../services/api';
import type { IOCFeed } from '../types/api';

export default function IOCFeeds() {
  const [feeds, setFeeds] = useState<IOCFeed[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [updating, setUpdating] = useState(false);

  const fetchFeeds = async () => {
    try {
      setLoading(true);
      const data = await ioc.getFeeds();
      setFeeds(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load IOC feeds');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFeeds();
  }, []);

  const handleSubmit = async (data: any) => {
    try {
      await ioc.createFeed(data);
      setIsModalOpen(false);
      fetchFeeds();
    } catch (err) {
      throw err;
    }
  };

  const handleUpdateAll = async () => {
    try {
      setUpdating(true);
      await threats.updateFeeds();
      fetchFeeds();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update feeds');
    } finally {
      setUpdating(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading IOC feeds...</div>
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
        <h1 className="text-2xl font-bold text-white">IOC Feeds</h1>
        <div className="flex gap-3">
          <button
            onClick={handleUpdateAll}
            disabled={updating}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white rounded-lg transition-colors"
          >
            {updating ? 'Updating...' : 'Update All Feeds'}
          </button>
          <button
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg transition-colors"
          >
            Add Feed
          </button>
        </div>
      </div>

      {feeds.length === 0 ? (
        <div className="bg-slate-800 rounded-lg p-8 text-center">
          <p className="text-slate-400">No IOC feeds configured</p>
        </div>
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-slate-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">URL</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Last Updated</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Frequency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {feeds.map((feed) => (
                <tr key={feed.id} className="hover:bg-slate-700/50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-white">{feed.name}</td>
                  <td className="px-6 py-4 text-sm text-slate-300 max-w-xs truncate">{feed.url}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">{feed.feed_type}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs font-medium rounded ${
                      feed.is_active
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-slate-500/20 text-slate-400'
                    }`}>
                      {feed.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                    {feed.last_updated ? new Date(feed.last_updated).toLocaleString() : 'Never'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                    {feed.update_frequency_hours}h
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <FormModalBuilder
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Add IOC Feed"
        fields={[
          { name: 'name', label: 'Name', type: 'text', required: true },
          { name: 'url', label: 'URL', type: 'url', required: true },
          {
            name: 'feed_type',
            label: 'Feed Type',
            type: 'select',
            required: true,
            options: [
              { value: 'domain', label: 'Domain' },
              { value: 'ip', label: 'IP' },
              { value: 'hash', label: 'Hash' },
            ],
          },
          { name: 'is_active', label: 'Active', type: 'checkbox', defaultValue: true },
          { name: 'update_frequency_hours', label: 'Update Frequency (hours)', type: 'number', defaultValue: 24 },
        ]}
        onSubmit={handleSubmit}
      />
    </div>
  );
}
