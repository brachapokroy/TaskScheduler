import React, { useState } from 'react';
import { Save, Clock, Calendar } from 'lucide-react';
import { useUser } from '../contexts/UserContext';

export const UserProfile: React.FC = () => {
  const { currentUser, updateUser } = useUser();
  const [formData, setFormData] = useState({
    name: currentUser.name,
    email: currentUser.email,
    workingHours: {
      start: currentUser.workingHours.start,
      end: currentUser.workingHours.end,
      daysOfWeek: currentUser.workingHours.daysOfWeek
    }
  });

  const [saved, setSaved] = useState(false);

  const daysOfWeek = [
    { id: 0, name: 'Sunday' },
    { id: 1, name: 'Monday' },
    { id: 2, name: 'Tuesday' },
    { id: 3, name: 'Wednesday' },
    { id: 4, name: 'Thursday' },
    { id: 5, name: 'Friday' },
    { id: 6, name: 'Saturday' }
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateUser({
      ...currentUser,
      ...formData
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const toggleWorkingDay = (dayId: number) => {
    setFormData(prev => ({
      ...prev,
      workingHours: {
        ...prev.workingHours,
        daysOfWeek: prev.workingHours.daysOfWeek.includes(dayId)
          ? prev.workingHours.daysOfWeek.filter(id => id !== dayId)
          : [...prev.workingHours.daysOfWeek, dayId]
      }
    }));
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-gray-900">Profile</h2>
        <p className="text-gray-600 mt-1">Manage your account settings and preferences</p>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="p-6">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">
                <Clock className="w-4 h-4 inline mr-2" />
                Working Hours
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-600 mb-1">Start Time</label>
                  <input
                    type="time"
                    value={formData.workingHours.start}
                    onChange={(e) => setFormData({
                      ...formData,
                      workingHours: { ...formData.workingHours, start: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-600 mb-1">End Time</label>
                  <input
                    type="time"
                    value={formData.workingHours.end}
                    onChange={(e) => setFormData({
                      ...formData,
                      workingHours: { ...formData.workingHours, end: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">
                <Calendar className="w-4 h-4 inline mr-2" />
                Working Days
              </label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {daysOfWeek.map(day => (
                  <label key={day.id} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={formData.workingHours.daysOfWeek.includes(day.id)}
                      onChange={() => toggleWorkingDay(day.id)}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-sm text-gray-700">{day.name}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="pt-4 border-t border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">
                    Role: <span className="font-medium capitalize">{currentUser.role}</span>
                  </p>
                  <p className="text-sm text-gray-600">
                    Member since: {new Date().toLocaleDateString()}
                  </p>
                </div>
                
                <button
                  type="submit"
                  className={`px-6 py-2 rounded-md transition-colors flex items-center space-x-2 ${
                    saved
                      ? 'bg-green-600 text-white'
                      : 'bg-blue-600 text-white hover:bg-blue-700'
                  }`}
                >
                  <Save className="w-4 h-4" />
                  <span>{saved ? 'Saved!' : 'Save Changes'}</span>
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};