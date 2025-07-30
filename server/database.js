const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Initialize database
const db = new Database(path.join(__dirname, 'taskmanagement.db'));

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create tables
const createTables = () => {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT CHECK(role IN ('user', 'team-member', 'admin')) DEFAULT 'user',
      working_hours_start TEXT DEFAULT '09:00',
      working_hours_end TEXT DEFAULT '17:00',
      working_days TEXT DEFAULT '[1,2,3,4,5]',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Teams table
  db.exec(`
    CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      admin_id TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  // Team members junction table
  db.exec(`
    CREATE TABLE IF NOT EXISTS team_members (
      team_id TEXT,
      user_id TEXT,
      joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (team_id) REFERENCES teams (id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  // Tasks table
  db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      due_date DATETIME NOT NULL,
      estimated_duration INTEGER NOT NULL,
      priority TEXT CHECK(priority IN ('low', 'medium', 'high', 'urgent')) DEFAULT 'medium',
      status TEXT CHECK(status IN ('todo', 'in-progress', 'completed')) DEFAULT 'todo',
      assigned_to TEXT,
      team_id TEXT,
      created_by TEXT NOT NULL,
      tags TEXT DEFAULT '[]',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (assigned_to) REFERENCES users (id) ON DELETE SET NULL,
      FOREIGN KEY (team_id) REFERENCES teams (id) ON DELETE SET NULL,
      FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  // Task intervals table
  db.exec(`
    CREATE TABLE IF NOT EXISTS task_intervals (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      duration INTEGER NOT NULL,
      scheduled_start DATETIME,
      is_completed BOOLEAN DEFAULT FALSE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE
    )
  `);

  // Schedule entries table
  db.exec(`
    CREATE TABLE IF NOT EXISTS schedule_entries (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      interval_id TEXT,
      user_id TEXT NOT NULL,
      start_time DATETIME NOT NULL,
      end_time DATETIME NOT NULL,
      title TEXT NOT NULL,
      priority TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
      FOREIGN KEY (interval_id) REFERENCES task_intervals (id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  console.log('Database tables created successfully');
};

// Seed default admin user
const seedDefaultUser = async () => {
  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@taskmanagement.com');
  
  if (!existingUser) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    const userId = uuidv4();
    
    db.prepare(`
      INSERT INTO users (id, name, email, password, role)
      VALUES (?, ?, ?, ?, ?)
    `).run(userId, 'Admin User', 'admin@taskmanagement.com', hashedPassword, 'admin');
    
    console.log('Default admin user created: admin@taskmanagement.com / admin123');
  }
};

// Initialize database
const initializeDatabase = async () => {
  createTables();
  await seedDefaultUser();
};

module.exports = { db, initializeDatabase };