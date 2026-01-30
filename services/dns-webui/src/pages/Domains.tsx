import React, { useState, useEffect } from 'react';
import { FormModalBuilder } from '@penguin/react_libs';
import { Domain } from '../types/api';
import { domains as domainsApi } from '../services/api';

const Domains: React.FC = () => {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [activeFilter, setActiveFilter] = useState<'all' | 'active' | 'inactive'>('all');

  useEffect(() => {
    fetchDomains();
  }, []);

  const fetchDomains = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await domainsApi.getDomains();
      setDomains(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch domains');
    } finally {
      setLoading(false);
    }
  };

  const handleAddDomain = async (data: any) => {
    try {
      await domainsApi.createDomain(data);
      setIsModalOpen(false);
      await fetchDomains();
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : 'Failed to create domain');
    }
  };

  const filteredDomains = domains.filter(domain => {
    if (activeFilter === 'active') return domain.is_active;
    if (activeFilter === 'inactive') return !domain.is_active;
    return true;
  });

  const formFields = [
    {
      name: 'domain_name',
      label: 'Domain Name',
      type: 'text' as const,
      required: true,
      placeholder: 'example.com',
    },
    {
      name: 'ip_address',
      label: 'IP Address',
      type: 'text' as const,
      required: true,
      placeholder: '192.168.1.1',
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea' as const,
      placeholder: 'Optional description',
    },
    {
      name: 'access_type',
      label: 'Access Type',
      type: 'select' as const,
      required: true,
      options: [
        { value: 'all', label: 'All' },
        { value: 'groups', label: 'Groups' },
        { value: 'users', label: 'Users' },
      ],
      defaultValue: 'all',
    },
    {
      name: 'is_active',
      label: 'Active',
      type: 'checkbox' as const,
      defaultValue: true,
    },
  ];

  const getAccessTypeBadgeColor = (accessType: string) => {
    switch (accessType) {
      case 'all':
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
      case 'groups':
        return 'bg-purple-500/20 text-purple-400 border border-purple-500/30';
      case 'users':
        return 'bg-green-500/20 text-green-400 border border-green-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border border-slate-500/30';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading domains...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-red-400">Error: {error}</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-100">Domains</h1>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-slate-900 rounded-lg font-medium transition-colors"
        >
          Add Domain
        </button>
      </div>

      <div className="flex space-x-2 border-b border-slate-700">
        <button
          onClick={() => setActiveFilter('all')}
          className={`px-4 py-2 font-medium transition-colors ${
            activeFilter === 'all'
              ? 'text-amber-400 border-b-2 border-amber-400'
              : 'text-slate-400 hover:text-slate-300'
          }`}
        >
          All
        </button>
        <button
          onClick={() => setActiveFilter('active')}
          className={`px-4 py-2 font-medium transition-colors ${
            activeFilter === 'active'
              ? 'text-amber-400 border-b-2 border-amber-400'
              : 'text-slate-400 hover:text-slate-300'
          }`}
        >
          Active
        </button>
        <button
          onClick={() => setActiveFilter('inactive')}
          className={`px-4 py-2 font-medium transition-colors ${
            activeFilter === 'inactive'
              ? 'text-amber-400 border-b-2 border-amber-400'
              : 'text-slate-400 hover:text-slate-300'
          }`}
        >
          Inactive
        </button>
      </div>

      <div className="bg-slate-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-700">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                Name
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                IP Address
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                Access Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                Created
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700">
            {filteredDomains.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-400">
                  No domains found
                </td>
              </tr>
            ) : (
              filteredDomains.map((domain) => (
                <tr key={domain.id} className="hover:bg-slate-700/50 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-100">
                    {domain.name}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {domain.ip_address}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${getAccessTypeBadgeColor(
                        domain.access_type
                      )}`}
                    >
                      {domain.access_type}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        domain.is_active
                          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                          : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                      }`}
                    >
                      {domain.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {new Date(domain.created_on).toLocaleDateString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <FormModalBuilder
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSubmit={handleAddDomain}
        title="Add Domain"
        fields={formFields}
      />
    </div>
  );
};

export default Domains;
