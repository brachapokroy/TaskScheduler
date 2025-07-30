const API_BASE_URL = 'http://localhost:3001/api';

class ApiService {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem('token');
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...(this.token && { Authorization: `Bearer ${this.token}` }),
        ...options.headers,
      },
      ...options,
    };

    const response = await fetch(url, config);
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Network error' }));
      throw new Error(error.error || 'Request failed');
    }

    return response.json();
  }

  // Auth methods
  async login(email: string, password: string) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    
    this.token = response.token;
    localStorage.setItem('token', response.token);
    return response;
  }

  async register(name: string, email: string, password: string, role = 'user') {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, role }),
    });
    
    this.token = response.token;
    localStorage.setItem('token', response.token);
    return response;
  }

  logout() {
    this.token = null;
    localStorage.removeItem('token');
  }

  // Task methods
  async getTasks() {
    return this.request('/tasks');
  }

  async createTask(task: any) {
    return this.request('/tasks', {
      method: 'POST',
      body: JSON.stringify(task),
    });
  }

  async updateTask(id: string, task: any) {
    return this.request(`/tasks/${id}`, {
      method: 'PUT',
      body: JSON.stringify(task),
    });
  }

  async deleteTask(id: string) {
    return this.request(`/tasks/${id}`, {
      method: 'DELETE',
    });
  }

  async splitTask(id: string, intervals: number) {
    return this.request(`/tasks/${id}/split`, {
      method: 'POST',
      body: JSON.stringify({ intervals }),
    });
  }

  // Team methods
  async getTeams() {
    return this.request('/teams');
  }

  async createTeam(team: any) {
    return this.request('/teams', {
      method: 'POST',
      body: JSON.stringify(team),
    });
  }

  async updateTeam(id: string, team: any) {
    return this.request(`/teams/${id}`, {
      method: 'PUT',
      body: JSON.stringify(team),
    });
  }

  async deleteTeam(id: string) {
    return this.request(`/teams/${id}`, {
      method: 'DELETE',
    });
  }

  // User methods
  async getUsers() {
    return this.request('/users');
  }

  async updateProfile(profile: any) {
    return this.request('/users/profile', {
      method: 'PUT',
      body: JSON.stringify(profile),
    });
  }

  // Schedule methods
  async generateSchedule() {
    return this.request('/schedule/generate', {
      method: 'POST',
    });
  }

  async getSchedule() {
    return this.request('/schedule');
  }
}

export const apiService = new ApiService();