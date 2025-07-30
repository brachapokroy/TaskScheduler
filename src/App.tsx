import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { LoginForm } from './components/LoginForm';
import { TaskManager } from './components/TaskManager';
import { ScheduleView } from './components/ScheduleView';
import { TeamManager } from './components/TeamManager';
import { UserProfile } from './components/UserProfile';
import { TaskProvider } from './contexts/TaskContext';
import { UserProvider } from './contexts/UserContext';
import { TeamProvider } from './contexts/TeamContext';
import { useUser } from './contexts/UserContext';

export type ViewType = 'tasks' | 'schedule' | 'teams' | 'profile';

const AppContent: React.FC = () => {
  const { currentUser, login, loadUsers } = useUser();
  const [currentView, setCurrentView] = useState<ViewType>('tasks');

  useEffect(() => {
    if (currentUser) {
      loadUsers();
    }
  }, [currentUser, loadUsers]);

  if (!currentUser) {
    return <LoginForm onLogin={login} />;
  }

  const renderCurrentView = () => {
    switch (currentView) {
      case 'tasks':
        return <TaskManager />;
      case 'schedule':
        return <ScheduleView />;
      case 'teams':
        return <TeamManager />;
      case 'profile':
        return <UserProfile />;
      default:
        return <TaskManager />;
    }
  };

  return (
    <TaskProvider>
      <TeamProvider>
        <div className="min-h-screen bg-gray-50">
          <Header />
          <div className="flex">
            <Sidebar currentView={currentView} onViewChange={setCurrentView} />
            <main className="flex-1 ml-64 p-6">
              {renderCurrentView()}
            </main>
          </div>
        </div>
      </TeamProvider>
    </TaskProvider>
  );
};

function App() {
  return (
    <UserProvider>
      <AppContent />
    </UserProvider>
  );
}

export default App;