const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get all tasks for user
router.get('/', authenticateToken, (req, res) => {
  try {
    const tasks = db.prepare(`
      SELECT t.*, 
             u.name as assigned_to_name,
             tm.name as team_name
      FROM tasks t
      LEFT JOIN users u ON t.assigned_to = u.id
      LEFT JOIN teams tm ON t.team_id = tm.id
      WHERE t.created_by = ? OR t.assigned_to = ? OR t.team_id IN (
        SELECT team_id FROM team_members WHERE user_id = ?
      )
      ORDER BY t.created_at DESC
    `).all(req.user.id, req.user.id, req.user.id);

    // Get intervals for each task
    const tasksWithIntervals = tasks.map(task => {
      const intervals = db.prepare(`
        SELECT * FROM task_intervals WHERE task_id = ? ORDER BY created_at
      `).all(task.id);

      return {
        id: task.id,
        title: task.title,
        description: task.description,
        dueDate: new Date(task.due_date),
        estimatedDuration: task.estimated_duration,
        priority: task.priority,
        status: task.status,
        assignedTo: task.assigned_to,
        teamId: task.team_id,
        createdBy: task.created_by,
        createdAt: new Date(task.created_at),
        tags: JSON.parse(task.tags || '[]'),
        intervals: intervals.map(interval => ({
          id: interval.id,
          taskId: interval.task_id,
          duration: interval.duration,
          scheduledStart: interval.scheduled_start ? new Date(interval.scheduled_start) : null,
          isCompleted: Boolean(interval.is_completed)
        }))
      };
    });

    res.json(tasksWithIntervals);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create task
router.post('/', authenticateToken, (req, res) => {
  try {
    const {
      title,
      description,
      dueDate,
      estimatedDuration,
      priority = 'medium',
      status = 'todo',
      assignedTo,
      teamId,
      tags = []
    } = req.body;

    const taskId = uuidv4();

    db.prepare(`
      INSERT INTO tasks (
        id, title, description, due_date, estimated_duration,
        priority, status, assigned_to, team_id, created_by, tags
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      taskId, title, description, dueDate, estimatedDuration,
      priority, status, assignedTo || null, teamId || null,
      req.user.id, JSON.stringify(tags)
    );

    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId);
    
    res.status(201).json({
      id: task.id,
      title: task.title,
      description: task.description,
      dueDate: new Date(task.due_date),
      estimatedDuration: task.estimated_duration,
      priority: task.priority,
      status: task.status,
      assignedTo: task.assigned_to,
      teamId: task.team_id,
      createdBy: task.created_by,
      createdAt: new Date(task.created_at),
      tags: JSON.parse(task.tags || '[]'),
      intervals: []
    });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update task
router.put('/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const {
      title,
      description,
      dueDate,
      estimatedDuration,
      priority,
      status,
      assignedTo,
      teamId,
      tags
    } = req.body;

    // Check if user can update this task
    const task = db.prepare(`
      SELECT * FROM tasks WHERE id = ? AND (
        created_by = ? OR assigned_to = ? OR team_id IN (
          SELECT team_id FROM team_members WHERE user_id = ?
        )
      )
    `).get(id, req.user.id, req.user.id, req.user.id);

    if (!task) {
      return res.status(404).json({ error: 'Task not found or access denied' });
    }

    db.prepare(`
      UPDATE tasks SET
        title = ?, description = ?, due_date = ?, estimated_duration = ?,
        priority = ?, status = ?, assigned_to = ?, team_id = ?, tags = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      title, description, dueDate, estimatedDuration,
      priority, status, assignedTo || null, teamId || null,
      JSON.stringify(tags || []), id
    );

    const updatedTask = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
    const intervals = db.prepare('SELECT * FROM task_intervals WHERE task_id = ?').all(id);

    res.json({
      id: updatedTask.id,
      title: updatedTask.title,
      description: updatedTask.description,
      dueDate: new Date(updatedTask.due_date),
      estimatedDuration: updatedTask.estimated_duration,
      priority: updatedTask.priority,
      status: updatedTask.status,
      assignedTo: updatedTask.assigned_to,
      teamId: updatedTask.team_id,
      createdBy: updatedTask.created_by,
      createdAt: new Date(updatedTask.created_at),
      tags: JSON.parse(updatedTask.tags || '[]'),
      intervals: intervals.map(interval => ({
        id: interval.id,
        taskId: interval.task_id,
        duration: interval.duration,
        scheduledStart: interval.scheduled_start ? new Date(interval.scheduled_start) : null,
        isCompleted: Boolean(interval.is_completed)
      }))
    });
  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete task
router.delete('/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;

    // Check if user can delete this task
    const task = db.prepare(`
      SELECT * FROM tasks WHERE id = ? AND created_by = ?
    `).get(id, req.user.id);

    if (!task) {
      return res.status(404).json({ error: 'Task not found or access denied' });
    }

    db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
    res.status(204).send();
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Split task into intervals
router.post('/:id/split', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const { intervals: intervalCount } = req.body;

    const task = db.prepare(`
      SELECT * FROM tasks WHERE id = ? AND (
        created_by = ? OR assigned_to = ?
      )
    `).get(id, req.user.id, req.user.id);

    if (!task) {
      return res.status(404).json({ error: 'Task not found or access denied' });
    }

    // Delete existing intervals
    db.prepare('DELETE FROM task_intervals WHERE task_id = ?').run(id);

    // Create new intervals
    const intervalDuration = Math.ceil(task.estimated_duration / intervalCount);
    const intervals = [];

    for (let i = 0; i < intervalCount; i++) {
      const intervalId = uuidv4();
      const duration = i === intervalCount - 1 
        ? task.estimated_duration - (intervalDuration * (intervalCount - 1))
        : intervalDuration;

      db.prepare(`
        INSERT INTO task_intervals (id, task_id, duration)
        VALUES (?, ?, ?)
      `).run(intervalId, id, duration);

      intervals.push({
        id: intervalId,
        taskId: id,
        duration,
        scheduledStart: null,
        isCompleted: false
      });
    }

    res.json(intervals);
  } catch (error) {
    console.error('Split task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;