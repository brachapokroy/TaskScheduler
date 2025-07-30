export interface User {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'team-member' | 'admin';
  workingHours: {
    start: string;
    end: string;
    daysOfWeek: number[];
  };
  teams: string[];
}

export interface Task {
  id: string;
  title: string;
  description: string;
  dueDate: Date;
  estimatedDuration: number; // in minutes
  priority: 'low' | 'medium' | 'high' | 'urgent';
  status: 'todo' | 'in-progress' | 'completed';
  assignedTo?: string;
  teamId?: string;
  createdBy: string;
  createdAt: Date;
  intervals?: TaskInterval[];
  tags: string[];
}

export interface TaskInterval {
  id: string;
  taskId: string;
  duration: number;
  scheduledStart?: Date;
  isCompleted: boolean;
}

export interface Team {
  id: string;
  name: string;
  description: string;
  members: string[];
  adminId: string;
  createdAt: Date;
}

export interface ScheduleEntry {
  id: string;
  taskId: string;
  intervalId?: string;
  start: Date;
  end: Date;
  title: string;
  priority: Task['priority'];
}