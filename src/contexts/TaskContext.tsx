import React, { createContext, useContext, useState, ReactNode } from 'react';
import { apiService } from '../services/api';
import { Task, TaskInterval, ScheduleEntry } from '../types';

interface TaskContextType {
  tasks: Task[];
  scheduleEntries: ScheduleEntry[];
  addTask: (task: Omit<Task, 'id' | 'createdAt'>) => void;
  updateTask: (task: Task) => void;
  deleteTask: (taskId: string) => void;
  generateSchedule: (userId: string) => void;
  splitTask: (taskId: string, intervals: number) => void;
  loadTasks: () => Promise<void>;
  loadSchedule: () => Promise<void>;
}

const TaskContext = createContext<TaskContextType | undefined>(undefined);

export const TaskProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [scheduleEntries, setScheduleEntries] = useState<ScheduleEntry[]>([]);

  const loadTasks = async () => {
    try {
      const fetchedTasks = await apiService.getTasks();
      setTasks(fetchedTasks);
    } catch (error) {
      console.error('Failed to load tasks:', error);
    }
  };

  const addTask = async (taskData: Omit<Task, 'id' | 'createdAt'>) => {
    try {
      const newTask = await apiService.createTask(taskData);
      setTasks(prev => [...prev, newTask]);
    } catch (error) {
      console.error('Failed to create task:', error);
      throw error;
    }
  };

  const updateTask = async (updatedTask: Task) => {
    try {
      const updated = await apiService.updateTask(updatedTask.id, updatedTask);
      setTasks(prev => prev.map(task => task.id === updatedTask.id ? updated : task));
    } catch (error) {
      console.error('Failed to update task:', error);
      throw error;
    }
  };

  const deleteTask = async (taskId: string) => {
    try {
      await apiService.deleteTask(taskId);
      setTasks(prev => prev.filter(task => task.id !== taskId));
      setScheduleEntries(prev => prev.filter(entry => entry.taskId !== taskId));
    } catch (error) {
      console.error('Failed to delete task:', error);
      throw error;
    }
  };

  const splitTask = async (taskId: string, intervals: number) => {
    try {
      const taskIntervals = await apiService.splitTask(taskId, intervals);
      const task = tasks.find(t => t.id === taskId);
      if (task) {
        setTasks(prev => prev.map(t => 
          t.id === taskId ? { ...t, intervals: taskIntervals } : t
        ));
      }
    } catch (error) {
      console.error('Failed to split task:', error);
      throw error;
    }
  };

  const generateSchedule = async (userId: string) => {
    try {
      const newScheduleEntries = await apiService.generateSchedule();
      setScheduleEntries(newScheduleEntries);
    } catch (error) {
      console.error('Failed to generate schedule:', error);
      throw error;
    }
  };

  const loadSchedule = async () => {
    try {
      const entries = await apiService.getSchedule();
      setScheduleEntries(entries);
    } catch (error) {
      console.error('Failed to load schedule:', error);
    }
  };

  return (
    <TaskContext.Provider value={{
      tasks,
      scheduleEntries,
      addTask,
      updateTask,
      deleteTask,
      generateSchedule,
      splitTask,
      loadTasks,
      loadSchedule
    }}>
      {children}
    </TaskContext.Provider>
  );
};

export const useTask = () => {
  const context = useContext(TaskContext);
  if (context === undefined) {
    throw new Error('useTask must be used within a TaskProvider');
  }
  return context;
};