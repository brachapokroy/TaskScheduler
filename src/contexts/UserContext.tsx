import React, { createContext, useContext, useState, ReactNode } from 'react';
import { apiService } from '../services/api';
import { User } from '../types';

interface UserContextType {
  currentUser: User | null;
  users: User[];
  login: (user: User) => void;
  logout: () => void;
  updateUser: (user: User) => void;
  addUser: (user: Omit<User, 'id'>) => void;
  loadUsers: () => Promise<void>;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

export const UserProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);

  const login = (user: User) => {
    setCurrentUser(user);
  };

  const logout = () => {
    setCurrentUser(null);
    apiService.logout();
  };

  const updateUser = (updatedUser: User) => {
    setUsers(prev => prev.map(user => user.id === updatedUser.id ? updatedUser : user));
    if (updatedUser.id === currentUser.id) {
      setCurrentUser(updatedUser);
    }
  };

  const addUser = (userData: Omit<User, 'id'>) => {
    const newUser: User = {
      ...userData,
      id: Date.now().toString()
    };
    setUsers(prev => [...prev, newUser]);
  };

  const loadUsers = async () => {
    try {
      const fetchedUsers = await apiService.getUsers();
      setUsers(fetchedUsers);
    } catch (error) {
      console.error('Failed to load users:', error);
    }
  };

  return (
    <UserContext.Provider value={{ 
      currentUser, 
      users, 
      login, 
      logout, 
      updateUser, 
      addUser, 
      loadUsers 
    }}>
      {children}
    </UserContext.Provider>
  );
};

export const useUser = () => {
  const context = useContext(UserContext);
  if (context === undefined) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};