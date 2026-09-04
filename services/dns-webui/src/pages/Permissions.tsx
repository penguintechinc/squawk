import { useState, useEffect } from 'react';
import { FormModalBuilder } from '@penguintechinc/react-libs';
import { permissions as permsApi } from '../services/api';
import type { Permission } from '../types/api';

export default function Permissions() {
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchPermissions = async () => {
    try {
      setLoading(true);
      const data = await permsApi.getPermissions();
      setPermissions(data.permissions);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load permissions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPermissions();
  }, []);

  const handleSubmit = async (data: any) => {
    try {
      await permsApi.createPermission(data);
      setIsModalOpen(false);
      fetchPermissions();
    } catch (err) {
      throw err;
    }
  };

  const getAccessLevelBadge = (level: string) => {
    const colors = {
      READ: 'bg-blue-500/20 text-blue-400',
      WRITE: 'bg-amber-500/20 text-amber-400',
      ADMIN: 'bg-red-500/20 text-red-400',
    };
    return colors[level as keyof typeof colors] || 'bg-slate-500/20 text-slate-400';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading permissions...</div>
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
        <h1 className="text-2xl font-bold text-white">Permissions</h1>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg transition-colors"
        >
          Add Permission
        </button>
      </div>

      {permissions.length === 0 ? (
        <div className="bg-slate-800 rounded-lg p-8 text-center">
          <p className="text-slate-400">No permissions configured</p>
        </div>
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-slate-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Group</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Zone Pattern</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Access Level</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Can Query</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Can Modify</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {permissions.map((permission) => (
                <tr key={permission.id} className="hover:bg-slate-700/50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-white">{permission.group_name}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">{permission.zone_pattern}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs font-medium rounded ${getAccessLevelBadge(permission.access_level)}`}>
                      {permission.access_level}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    {permission.can_query ? (
                      <span className="text-green-400">✓</span>
                    ) : (
                      <span className="text-red-400">✗</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    {permission.can_modify ? (
                      <span className="text-green-400">✓</span>
                    ) : (
                      <span className="text-red-400">✗</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                    {new Date(permission.created_on).toLocaleDateString()}
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
        title="Add Permission"
        fields={[
          { name: 'group', label: 'Group', type: 'text', required: true },
          { name: 'zone_pattern', label: 'Zone Pattern', type: 'text', required: true, placeholder: '*.example.com' },
          {
            name: 'access_level',
            label: 'Access Level',
            type: 'select',
            required: true,
            options: [
              { value: 'READ', label: 'READ' },
              { value: 'WRITE', label: 'WRITE' },
              { value: 'ADMIN', label: 'ADMIN' },
            ],
          },
          { name: 'can_query', label: 'Can Query', type: 'checkbox', defaultValue: true },
          { name: 'can_modify', label: 'Can Modify', type: 'checkbox' },
        ]}
        onSubmit={handleSubmit}
      />
    </div>
  );
}
