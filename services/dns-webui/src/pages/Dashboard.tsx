import React, { useState, useEffect } from 'react';
import { dashboard } from '../services/api';
import { DashboardStats } from '../types/api';

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        const data = await dashboard.getStats();
        setStats(data);
        setError(null);
      } catch (err) {
        setError('Failed to load dashboard statistics');
        console.error('Error fetching stats:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-400"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-500 text-red-400 px-4 py-3 rounded">
        {error}
      </div>
    );
  }

  if (!stats) {
    return null;
  }

  const statCards = [
    { title: 'Total Queries (24h)', value: stats.total_queries_24h.toLocaleString(), isRate: false },
    { title: 'Cache Hit Rate', value: `${stats.cache_hit_rate}%`, isRate: true },
    { title: 'Active IOC Feeds', value: stats.active_ioc_feeds.toLocaleString(), isRate: false },
    { title: 'Total IOC Entries', value: stats.total_ioc_entries.toLocaleString(), isRate: false },
    { title: 'Internal Domains', value: stats.internal_domains.toLocaleString(), isRate: false },
    { title: 'IOC Blocks (24h)', value: stats.ioc_blocks_24h.toLocaleString(), isRate: false },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {statCards.map((card, index) => (
          <div key={index} className="bg-slate-800 rounded-lg p-6">
            <p className="text-slate-400 text-sm mb-2">{card.title}</p>
            <p className={`text-2xl font-bold ${card.isRate ? 'text-amber-400' : 'text-white'}`}>
              {card.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Dashboard;
