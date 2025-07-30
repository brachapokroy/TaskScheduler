import React from 'react';
import { Calendar, Clock, User, MoreVertical, Scissors } from 'lucide-react';
import { Task } from '../types';
import { useTask } from '../contexts/TaskContext';

interface TaskCardProps {
  task: Task;
  onEdit: (task: Task) => void;
  onDelete: (taskId: string) => void;
  onStatusChange: (taskId: string, status: Task['status']) => void;
}

export const TaskCard: React.FC<TaskCardProps> = ({ task, onEdit, onDelete, onStatusChange }) => {
  const { splitTask } = useTask();
  
  const priorityColors = {
    low: 'bg-green-100 text-green-800',
    medium: 'bg-yellow-100 text-yellow-800',
    high: 'bg-orange-100 text-orange-800',
    urgent: 'bg-red-100 text-red-800'
  };

  const statusColors = {
    todo: 'bg-gray-100 text-gray-800',
    'in-progress': 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800'
  };

  const formatDuration = (minutes: number) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
  };

  const isOverdue = new Date(task.dueDate) < new Date() && task.status !== 'completed';

  return (
    <div className={`bg-white border rounded-lg p-4 hover:shadow-md transition-shadow ${
      isOverdue ? 'border-red-300 bg-red-50' : 'border-gray-200'
    }`}>
      <div className="flex items-start justify-between mb-3">
        <h4 className="font-medium text-gray-900 flex-1">{task.title}</h4>
        <div className="relative">
          <button className="text-gray-400 hover:text-gray-600">
            <MoreVertical className="w-4 h-4" />
          </button>
        </div>
      </div>

      {task.description && (
        <p className="text-gray-600 text-sm mb-3 line-clamp-2">{task.description}</p>
      )}

      <div className="flex items-center space-x-2 mb-3">
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${priorityColors[task.priority]}`}>
          {task.priority}
        </span>
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusColors[task.status]}`}>
          {task.status.replace('-', ' ')}
        </span>
      </div>

      <div className="space-y-2 text-sm text-gray-600">
        <div className="flex items-center space-x-2">
          <Calendar className="w-4 h-4" />
          <span className={isOverdue ? 'text-red-600 font-medium' : ''}>
            {new Date(task.dueDate).toLocaleDateString()}
          </span>
        </div>
        
        <div className="flex items-center space-x-2">
          <Clock className="w-4 h-4" />
          <span>{formatDuration(task.estimatedDuration)}</span>
        </div>

        {task.assignedTo && (
          <div className="flex items-center space-x-2">
            <User className="w-4 h-4" />
            <span>Assigned</span>
          </div>
        )}
      </div>

      {task.intervals && task.intervals.length > 0 && (
        <div className="mt-3 pt-3 border-t border-gray-200">
          <p className="text-xs text-gray-500 mb-2">
            Split into {task.intervals.length} intervals
          </p>
          <div className="space-y-1">
            {task.intervals.map((interval, index) => (
              <div key={interval.id} className="flex items-center justify-between text-xs">
                <span>Part {index + 1}</span>
                <div className="flex items-center space-x-2">
                  <span>{formatDuration(interval.duration)}</span>
                  <div className={`w-2 h-2 rounded-full ${
                    interval.isCompleted ? 'bg-green-500' : 'bg-gray-300'
                  }`} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-center justify-between mt-4 pt-3 border-t border-gray-200">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => onEdit(task)}
            className="text-blue-600 hover:text-blue-800 text-sm font-medium"
          >
            Edit
          </button>
          <button
            onClick={() => onDelete(task.id)}
            className="text-red-600 hover:text-red-800 text-sm font-medium"
          >
            Delete
          </button>
          {!task.intervals && task.estimatedDuration > 60 && (
            <button
              onClick={() => splitTask(task.id, 3)}
              className="text-purple-600 hover:text-purple-800 text-sm font-medium flex items-center space-x-1"
            >
              <Scissors className="w-3 h-3" />
              <span>Split</span>
            </button>
          )}
        </div>
        
        {task.status !== 'completed' && (
          <select
            value={task.status}
            onChange={(e) => onStatusChange(task.id, e.target.value as Task['status'])}
            className="text-xs border border-gray-300 rounded px-2 py-1"
          >
            <option value="todo">To Do</option>
            <option value="in-progress">In Progress</option>
            <option value="completed">Completed</option>
          </select>
        )}
      </div>
    </div>
  );
};