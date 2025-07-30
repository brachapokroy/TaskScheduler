import React from 'react';
import { CheckSquare, Calendar, Users, UserCircle } from 'lucide-react';
import { ViewType } from '../App';

interface SidebarProps {
  currentView: ViewType;
  onViewChange: (view: ViewType) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentView, onViewChange }) => {
  const menuItems = [
    { id: 'tasks' as ViewType, label: 'Tasks', icon: CheckSquare },
    { id: 'schedule' as ViewType, label: 'Schedule', icon: Calendar },
    { id: 'teams' as ViewType, label: 'Teams', icon: Users },
    { id: 'profile' as ViewType, label: 'Profile', icon: UserCircle },
  ];

  return (
    <aside className="fixed left-0 top-16 h-full w-64 bg-white shadow-sm border-r border-gray-200">
      <nav className="p-4">
        <ul className="space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            
            return (
              <li key={item.id}>
                <button
                  onClick={() => onViewChange(item.id)}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-colors ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 border border-blue-200'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${isActive ? 'text-blue-700' : 'text-gray-500'}`} />
                  <span className="font-medium">{item.label}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
};