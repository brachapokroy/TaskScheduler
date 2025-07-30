import React, { useState } from 'react';
import { Plus, Filter, MoreHorizontal } from 'lucide-react';
import { TaskCard } from './TaskCard';
import { TaskForm } from './TaskForm';
import { useTask } from '../contexts/TaskContext';
import { useUser } from '../contexts/UserContext';
import { Task } from '../types';

export const TaskManager: React.FC = () => {
  const { tasks, addTask, updateTask, deleteTask } = useTask();
  const { currentUser } = useUser();
  const [showTaskForm, setShowTaskForm] = useState(false);
  const [editingTask, setEditingTask] = useState<Task | null>(null);
  const [filter, setFilter] = useState<'all' | 'todo' | 'in-progress' | 'completed'>('all');

  const filteredTasks = tasks.filter(task => {
    if (filter === 'all') return true;
    return task.status === filter;
  });

  const tasksByStatus = {
    todo: filteredTasks.filter(task => task.status === 'todo'),
    'in-progress': filteredTasks.filter(task => task.status === 'in-progress'),
    completed: filteredTasks.filter(task => task.status === 'completed')
  };

  const handleEditTask = (task: Task) => {
    setEditingTask(task);
    setShowTaskForm(true);
  };

  const handleCloseForm = () => {
    setShowTaskForm(false);
    setEditingTask(null);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-gray-900">Tasks</h2>
          <p className="text-gray-600 mt-1">Manage your tasks and stay organized</p>
        </div>
        
        <div className="flex items-center space-x-3">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as any)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Tasks</option>
            <option value="todo">To Do</option>
            <option value="in-progress">In Progress</option>
            <option value="completed">Completed</option>
          </select>
          
          <button
            onClick={() => setShowTaskForm(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Add Task</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {Object.entries(tasksByStatus).map(([status, statusTasks]) => (
          <div key={status} className="bg-white rounded-lg shadow-sm border border-gray-200">
            <div className="p-4 border-b border-gray-200">
              <h3 className="font-semibold text-gray-900 capitalize flex items-center justify-between">
                {status.replace('-', ' ')}
                <span className="bg-gray-100 text-gray-600 px-2 py-1 rounded-full text-sm">
                  {statusTasks.length}
                </span>
              </h3>
            </div>
            
            <div className="p-4 space-y-3 max-h-96 overflow-y-auto">
              {statusTasks.map(task => (
                <TaskCard
                  key={task.id}
                  task={task}
                  onEdit={handleEditTask}
                  onDelete={deleteTask}
                  onStatusChange={(taskId, newStatus) => {
                    const task = tasks.find(t => t.id === taskId);
                    if (task) {
                      updateTask({ ...task, status: newStatus });
                    }
                  }}
                />
              ))}
              {statusTasks.length === 0 && (
                <p className="text-gray-500 text-center py-8">No tasks</p>
              )}
            </div>
          </div>
        ))}
      </div>

      {showTaskForm && (
        <TaskForm
          task={editingTask}
          onSave={(taskData) => {
            if (editingTask) {
              updateTask({ ...editingTask, ...taskData });
            } else {
              addTask({ ...taskData, createdBy: currentUser.id });
            }
            handleCloseForm();
          }}
          onCancel={handleCloseForm}
        />
      )}
    </div>
  );
};