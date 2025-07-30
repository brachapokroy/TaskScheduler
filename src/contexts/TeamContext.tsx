import React, { createContext, useContext, useState, ReactNode } from 'react';
import { apiService } from '../services/api';
import { Team } from '../types';

interface TeamContextType {
  teams: Team[];
  addTeam: (team: Omit<Team, 'id' | 'createdAt'>) => void;
  updateTeam: (team: Team) => void;
  deleteTeam: (teamId: string) => void;
  addMemberToTeam: (teamId: string, userId: string) => void;
  removeMemberFromTeam: (teamId: string, userId: string) => void;
  loadTeams: () => Promise<void>;
}

const TeamContext = createContext<TeamContextType | undefined>(undefined);

export const TeamProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [teams, setTeams] = useState<Team[]>([]);

  const loadTeams = async () => {
    try {
      const fetchedTeams = await apiService.getTeams();
      setTeams(fetchedTeams);
    } catch (error) {
      console.error('Failed to load teams:', error);
    }
  };

  const addTeam = async (teamData: Omit<Team, 'id' | 'createdAt'>) => {
    try {
      const newTeam = await apiService.createTeam(teamData);
      setTeams(prev => [...prev, newTeam]);
    } catch (error) {
      console.error('Failed to create team:', error);
      throw error;
    }
  };

  const updateTeam = async (updatedTeam: Team) => {
    try {
      const updated = await apiService.updateTeam(updatedTeam.id, updatedTeam);
      setTeams(prev => prev.map(team => team.id === updatedTeam.id ? updated : team));
    } catch (error) {
      console.error('Failed to update team:', error);
      throw error;
    }
  };

  const deleteTeam = async (teamId: string) => {
    try {
      await apiService.deleteTeam(teamId);
      setTeams(prev => prev.filter(team => team.id !== teamId));
    } catch (error) {
      console.error('Failed to delete team:', error);
      throw error;
    }
  };

  const addMemberToTeam = (teamId: string, userId: string) => {
    setTeams(prev => prev.map(team => 
      team.id === teamId 
        ? { ...team, members: [...team.members, userId] }
        : team
    ));
  };

  const removeMemberFromTeam = (teamId: string, userId: string) => {
    setTeams(prev => prev.map(team => 
      team.id === teamId 
        ? { ...team, members: team.members.filter(id => id !== userId) }
        : team
    ));
  };

  return (
    <TeamContext.Provider value={{
      teams,
      addTeam,
      updateTeam,
      deleteTeam,
      addMemberToTeam,
      removeMemberFromTeam,
      loadTeams
    }}>
      {children}
    </TeamContext.Provider>
  );
};

export const useTeam = () => {
  const context = useContext(TeamContext);
  if (context === undefined) {
    throw new Error('useTeam must be used within a TeamProvider');
  }
  return context;
};