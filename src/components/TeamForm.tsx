import React, { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import { Team } from '../types';
import { useTeam } from '../contexts/TeamContext';
import { useUser } from '../contexts/UserContext';

interface TeamFormProps {
  team?: Team | null;
  onClose: () => void;
}

export const TeamForm: React.FC<TeamFormProps> = ({ team, onClose }) => {
  const { addTeam, updateTeam } = useTeam();
  const { currentUser, users } = useUser();
  
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    members: [] as string[]
  });

  useEffect(() => {
    if (team) {
      setFormData({
        name: team.name,
        description: team.description,
        members: team.members
      });
    }
  }, [team]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (team) {
      updateTeam({
        ...team,
        ...formData
      });
    } else {
      addTeam({
        ...formData,
        adminId: currentUser.id,
        members: [currentUser.id, ...formData.members]
      });
    }
    
    onClose();
  };

  const toggleMember = (userId: string) => {
    setFormData(prev => ({
      ...prev,
      members: prev.members.includes(userId)
        ? prev.members.filter(id => id !== userId)
        : [...prev.members, userId]
    }));
  };

  const availableUsers = users.filter(user => user.id !== currentUser.id);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">
            {team ? 'Edit Team' : 'Create New Team'}
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Team Name *
            </label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter team name"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              rows={3}
              placeholder="Enter team description"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Team Members
            </label>
            <div className="space-y-2 max-h-40 overflow-y-auto border border-gray-300 rounded-md p-2">
              {availableUsers.map(user => (
                <label key={user.id} className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={formData.members.includes(user.id)}
                    onChange={() => toggleMember(user.id)}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-700">{user.name}</span>
                  <span className="text-xs text-gray-500">({user.email})</span>
                </label>
              ))}
              {availableUsers.length === 0 && (
                <p className="text-sm text-gray-500 text-center py-2">
                  No other users available
                </p>
              )}
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              {team ? 'Update Team' : 'Create Team'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};