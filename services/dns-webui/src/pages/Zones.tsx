import { useState, useEffect } from 'react';
import { FormModalBuilder } from '@penguin/react_libs';
import { zones as zonesApi } from '../services/api';
import type { Zone } from '../types/api';

export default function Zones() {
  const [zones, setZones] = useState<Zone[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchZones = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await zonesApi.getZones();
      setZones(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch zones');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchZones();
  }, []);

  const handleSubmit = async (data: any) => {
    try {
      await zonesApi.createZone(data);
      setIsModalOpen(false);
      fetchZones();
    } catch (err) {
      throw err;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading zones...</div>
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
    <div className="p-6 bg-slate-900 min-h-screen">
      <div className="mb-6 flex justify-between items-center">
        <h1 className="text-2xl font-bold text-slate-100">DNS Zones</h1>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-slate-900 rounded-md font-medium transition-colors"
        >
          Add Zone
        </button>
      </div>

      {zones.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          No zones found. Create your first zone to get started.
        </div>
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden shadow-lg">
          <table className="w-full">
            <thead className="bg-slate-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Visibility</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Primary NS</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Admin Email</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">TTL</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {zones.map((zone) => (
                <tr key={zone.id} className="hover:bg-slate-750">
                  <td className="px-6 py-4 text-sm text-slate-300">{zone.name}</td>
                  <td className="px-6 py-4 text-sm">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        zone.visibility === 'PUBLIC'
                          ? 'bg-blue-500/20 text-blue-400'
                          : 'bg-slate-600/50 text-slate-300'
                      }`}
                    >
                      {zone.visibility}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300">{zone.primary_ns || '-'}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{zone.admin_email || '-'}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{zone.ttl}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">
                    {new Date(zone.created_on).toLocaleDateString()}
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
        onSubmit={handleSubmit}
        title="Add DNS Zone"
        fields={[
          {
            name: 'zone_name',
            label: 'Zone Name',
            type: 'text',
            required: true,
            placeholder: 'example.com',
          },
          {
            name: 'visibility',
            label: 'Visibility',
            type: 'select',
            required: true,
            options: [
              { value: 'PUBLIC', label: 'PUBLIC' },
              { value: 'PRIVATE', label: 'PRIVATE' },
            ],
          },
          {
            name: 'primary_ns',
            label: 'Primary Nameserver',
            type: 'text',
            placeholder: 'ns1.example.com',
          },
          {
            name: 'admin_email',
            label: 'Admin Email',
            type: 'email',
            placeholder: 'admin@example.com',
          },
          {
            name: 'ttl',
            label: 'TTL (seconds)',
            type: 'number',
            defaultValue: 3600,
            min: 60,
          },
        ]}
      />
    </div>
  );
}
