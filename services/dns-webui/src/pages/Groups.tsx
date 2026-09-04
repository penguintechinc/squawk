import { useState, useEffect } from 'react';
import { FormModalBuilder } from '@penguintechinc/react-libs';
import { groups as groupsApi } from '../services/api';
import type { Group } from '../types/api';

export default function Groups() {
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchGroups = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await groupsApi.getGroups();
      setGroups(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch groups');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGroups();
  }, []);

  const handleSubmit = async (data: any) => {
    try {
      await groupsApi.createGroup(data);
      setIsModalOpen(false);
      fetchGroups();
    } catch (err) {
      throw err;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading groups...</div>
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
        <h1 className="text-2xl font-bold text-slate-100">Groups</h1>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-slate-900 rounded-md font-medium transition-colors"
        >
          Add Group
        </button>
      </div>

      {groups.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          No groups found. Create your first group to get started.
        </div>
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden shadow-lg">
          <table className="w-full">
            <thead className="bg-slate-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Description</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {groups.map((group) => (
                <tr key={group.id} className="hover:bg-slate-750">
                  <td className="px-6 py-4 text-sm text-slate-300">{group.name}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{group.group_type}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{group.description || '-'}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">
                    {new Date(group.created_on).toLocaleDateString()}
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
        title="Add Group"
        fields={[
          {
            name: 'name',
            label: 'Name',
            type: 'text',
            required: true,
            placeholder: 'Enter group name',
          },
          {
            name: 'group_type',
            label: 'Type',
            type: 'select',
            required: true,
            options: [
              { value: 'Department', label: 'Department' },
              { value: 'Team', label: 'Team' },
              { value: 'Project', label: 'Project' },
              { value: 'Custom', label: 'Custom' },
            ],
          },
          {
            name: 'description',
            label: 'Description',
            type: 'textarea',
            placeholder: 'Enter group description',
          },
        ]}
      />
    </div>
  );
}
