import { useState, useEffect } from 'react';
import { FormModalBuilder } from '@penguin/react_libs';
import { records as recordsApi } from '../services/api';
import type { DnsRecord } from '../types/api';

const RECORD_TYPE_COLORS: Record<string, string> = {
  A: 'bg-green-500/20 text-green-400',
  AAAA: 'bg-blue-500/20 text-blue-400',
  CNAME: 'bg-purple-500/20 text-purple-400',
  MX: 'bg-amber-500/20 text-amber-400',
  TXT: 'bg-slate-500/20 text-slate-300',
  NS: 'bg-teal-500/20 text-teal-400',
  SRV: 'bg-indigo-500/20 text-indigo-400',
  PTR: 'bg-pink-500/20 text-pink-400',
};

export default function Records() {
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchRecords = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await recordsApi.getRecords();
      setRecords(data.records);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const handleSubmit = async (data: any) => {
    try {
      await recordsApi.createRecord(data);
      setIsModalOpen(false);
      fetchRecords();
    } catch (err) {
      throw err;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading records...</div>
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
        <h1 className="text-2xl font-bold text-slate-100">DNS Records</h1>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-slate-900 rounded-md font-medium transition-colors"
        >
          Add Record
        </button>
      </div>

      {records.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          No records found. Create your first DNS record to get started.
        </div>
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden shadow-lg">
          <table className="w-full">
            <thead className="bg-slate-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Zone</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Value</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">TTL</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {records.map((record) => (
                <tr key={record.id} className="hover:bg-slate-750">
                  <td className="px-6 py-4 text-sm text-slate-300">{record.zone}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{record.name}</td>
                  <td className="px-6 py-4 text-sm">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        RECORD_TYPE_COLORS[record.record_type] || 'bg-gray-500/20 text-gray-400'
                      }`}
                    >
                      {record.record_type}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300 max-w-xs truncate">
                    {record.value}
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300">{record.ttl}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">
                    {new Date(record.created_on).toLocaleDateString()}
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
        title="Add DNS Record"
        fields={[
          {
            name: 'zone',
            label: 'Zone',
            type: 'text',
            required: true,
            placeholder: 'example.com',
          },
          {
            name: 'record_name',
            label: 'Record Name',
            type: 'text',
            required: true,
            placeholder: 'www or @ for root',
          },
          {
            name: 'record_type',
            label: 'Record Type',
            type: 'select',
            required: true,
            options: [
              { value: 'A', label: 'A' },
              { value: 'AAAA', label: 'AAAA' },
              { value: 'CNAME', label: 'CNAME' },
              { value: 'MX', label: 'MX' },
              { value: 'TXT', label: 'TXT' },
              { value: 'NS', label: 'NS' },
              { value: 'SRV', label: 'SRV' },
              { value: 'PTR', label: 'PTR' },
            ],
          },
          {
            name: 'record_value',
            label: 'Record Value',
            type: 'text',
            required: true,
            placeholder: 'IP address, hostname, or text value',
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
