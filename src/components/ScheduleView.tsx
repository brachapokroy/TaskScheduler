import React, { useState } from 'react';
import { Calendar, Clock, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react';
import { useTask } from '../contexts/TaskContext';
import { useUser } from '../contexts/UserContext';

export const ScheduleView: React.FC = () => {
  const { scheduleEntries, generateSchedule } = useTask();
  const { currentUser } = useUser();
  const [view, setView] = useState<'day' | 'week' | 'month'>('week');
  const [currentDate, setCurrentDate] = useState(new Date());

  const handleGenerateSchedule = () => {
    generateSchedule(currentUser.id);
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatDate = (date: Date) => {
    return date.toLocaleDateString();
  };

  const getPriorityColor = (priority: string) => {
    const colors = {
      low: 'bg-green-100 border-green-500 text-green-800',
      medium: 'bg-yellow-100 border-yellow-500 text-yellow-800',
      high: 'bg-orange-100 border-orange-500 text-orange-800',
      urgent: 'bg-red-100 border-red-500 text-red-800'
    };
    return colors[priority as keyof typeof colors] || 'bg-gray-100 border-gray-500 text-gray-800';
  };

  const navigateDate = (direction: 'prev' | 'next') => {
    const newDate = new Date(currentDate);
    if (view === 'day') {
      newDate.setDate(newDate.getDate() + (direction === 'next' ? 1 : -1));
    } else if (view === 'week') {
      newDate.setDate(newDate.getDate() + (direction === 'next' ? 7 : -7));
    } else {
      newDate.setMonth(newDate.getMonth() + (direction === 'next' ? 1 : -1));
    }
    setCurrentDate(newDate);
  };

  const getDateRangeDisplay = () => {
    if (view === 'day') {
      return formatDate(currentDate);
    } else if (view === 'week') {
      const startOfWeek = new Date(currentDate);
      startOfWeek.setDate(currentDate.getDate() - currentDate.getDay());
      const endOfWeek = new Date(startOfWeek);
      endOfWeek.setDate(startOfWeek.getDate() + 6);
      return `${formatDate(startOfWeek)} - ${formatDate(endOfWeek)}`;
    } else {
      return currentDate.toLocaleDateString([], { month: 'long', year: 'numeric' });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-gray-900">Schedule</h2>
          <p className="text-gray-600 mt-1">View and manage your task schedule</p>
        </div>
        
        <div className="flex items-center space-x-3">
          <div className="flex items-center border border-gray-300 rounded-lg">
            <button
              onClick={() => setView('day')}
              className={`px-3 py-2 text-sm font-medium transition-colors ${
                view === 'day' ? 'bg-blue-600 text-white' : 'text-gray-700 hover:bg-gray-50'
              }`}
            >
              Day
            </button>
            <button
              onClick={() => setView('week')}
              className={`px-3 py-2 text-sm font-medium transition-colors ${
                view === 'week' ? 'bg-blue-600 text-white' : 'text-gray-700 hover:bg-gray-50'
              }`}
            >
              Week
            </button>
            <button
              onClick={() => setView('month')}
              className={`px-3 py-2 text-sm font-medium transition-colors ${
                view === 'month' ? 'bg-blue-600 text-white' : 'text-gray-700 hover:bg-gray-50'
              }`}
            >
              Month
            </button>
          </div>
          
          <button
            onClick={handleGenerateSchedule}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Generate Schedule</span>
          </button>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="p-4 border-b border-gray-200 flex items-center justify-between">
          <button
            onClick={() => navigateDate('prev')}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>
          
          <h3 className="text-lg font-semibold text-gray-900">
            {getDateRangeDisplay()}
          </h3>
          
          <button
            onClick={() => navigateDate('next')}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          {scheduleEntries.length === 0 ? (
            <div className="text-center py-12">
              <Calendar className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No Schedule Generated</h3>
              <p className="text-gray-600 mb-4">
                Generate a schedule to see your tasks organized by time.
              </p>
              <button
                onClick={handleGenerateSchedule}
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Generate Schedule
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {scheduleEntries
                .sort((a, b) => a.start.getTime() - b.start.getTime())
                .map(entry => (
                  <div
                    key={entry.id}
                    className={`border-l-4 rounded-lg p-4 ${getPriorityColor(entry.priority)}`}
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-medium text-gray-900">{entry.title}</h4>
                        <div className="flex items-center space-x-4 mt-2 text-sm text-gray-600">
                          <div className="flex items-center space-x-1">
                            <Clock className="w-4 h-4" />
                            <span>
                              {formatTime(entry.start)} - {formatTime(entry.end)}
                            </span>
                          </div>
                          <div className="flex items-center space-x-1">
                            <Calendar className="w-4 h-4" />
                            <span>{formatDate(entry.start)}</span>
                          </div>
                        </div>
                      </div>
                      <span className="px-2 py-1 bg-white bg-opacity-70 rounded-full text-xs font-medium capitalize">
                        {entry.priority}
                      </span>
                    </div>
                  </div>
                ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};