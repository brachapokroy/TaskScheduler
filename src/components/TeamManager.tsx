import React, { useState } from 'react';
import { Plus, Users, UserPlus, Trash2 } from 'lucide-react';
import { useTeam } from '../contexts/TeamContext';
import { useUser } from '../contexts/UserContext';
import { TeamForm } from './TeamForm';
import { Team } from '../types';

export const TeamManager: React.FC = () => {
  const { teams, deleteTeam, addMemberToTeam, removeMemberFromTeam } = useTeam();
  const { users, currentUser } = useUser();
  const [showTeamForm, setShowTeamForm] = useState(false);
  const [editingTeam, setEditingTeam] = useState<Team | null>(null);

  const handleEditTeam = (team: Team) => {
    setEditingTeam(team);
    setShowTeamForm(true);
  };

  const handleCloseForm = () => {
    setShowTeamForm(false);
    setEditingTeam(null);
  };

  const getUserName = (userId: string) => {
    const user = users.find(u => u.id === userId);
    return user ? user.name : 'Unknown User';
  };

  const canManageTeam = (team: Team) => {
    return currentUser.role === 'admin' || team.adminId === currentUser.id;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-gray-900">Teams</h2>
          <p className="text-gray-600 mt-1">Manage teams and collaborate on tasks</p>
        </div>
        
        <button
          onClick={() => setShowTeamForm(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
        >
          <Plus className="w-4 h-4" />
          <span>Create Team</span>
        </button>
      </div>

      {teams.length === 0 ? (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-12 text-center">
          <Users className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Teams Yet</h3>
          <p className="text-gray-600 mb-4">
            Create your first team to start collaborating on tasks.
          </p>
          <button
            onClick={() => setShowTeamForm(true)}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Create Team
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {teams.map(team => (
            <div key={team.id} className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">{team.name}</h3>
                    <p className="text-sm text-gray-600">Admin: {getUserName(team.adminId)}</p>
                  </div>
                  {canManageTeam(team) && (
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleEditTeam(team)}
                        className="text-blue-600 hover:text-blue-800 text-sm"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => deleteTeam(team.id)}
                        className="text-red-600 hover:text-red-800"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  )}
                </div>

                {team.description && (
                  <p className="text-gray-600 text-sm mb-4">{team.description}</p>
                )}

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-gray-700">
                      Members ({team.members.length})
                    </span>
                    {canManageTeam(team) && (
                      <button className="text-blue-600 hover:text-blue-800">
                        <UserPlus className="w-4 h-4" />
                      </button>
                    )}
                  </div>

                  <div className="space-y-2 max-h-32 overflow-y-auto">
                    {team.members.map(memberId => (
                      <div key={memberId} className="flex items-center justify-between">
                        <span className="text-sm text-gray-700">{getUserName(memberId)}</span>
                        {canManageTeam(team) && memberId !== team.adminId && (
                          <button
                            onClick={() => removeMemberFromTeam(team.id, memberId)}
                            className="text-red-600 hover:text-red-800 text-xs"
                          >
                            Remove
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="bg-gray-50 px-6 py-3 text-xs text-gray-500">
                Created {new Date(team.createdAt).toLocaleDateString()}
              </div>
            </div>
          ))}
        </div>
      )}

      {showTeamForm && (
        <TeamForm
          team={editingTeam}
          onClose={handleCloseForm}
        />
      )}
    </div>
  );
};