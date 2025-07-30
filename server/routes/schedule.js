const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Generate schedule
router.post('/generate', authenticateToken, (req, res) => {
  try {
    // Clear existing schedule entries for user
    db.prepare('DELETE FROM schedule_entries WHERE user_id = ?').run(req.user.id);

    // Get user's tasks
    const tasks = db.prepare(`
      SELECT t.*, ti.id as interval_id, ti.duration as interval_duration
      FROM tasks t
      LEFT JOIN task_intervals ti ON t.id = ti.task_id AND ti.is_completed = 0
      WHERE (t.created_by = ? OR t.assigned_to = ?) AND t.status != 'completed'
      ORDER BY 
        CASE t.priority 
          WHEN 'urgent' THEN 4 
          WHEN 'high' THEN 3 
          WHEN 'medium' THEN 2 
          WHEN 'low' THEN 1 
        END DESC,
        t.due_date ASC
    `).all(req.user.id, req.user.id);

    const scheduleEntries = [];
    let currentTime = new Date();
    currentTime.setHours(9, 0, 0, 0); // Start at 9 AM

    tasks.forEach(task => {
      const duration = task.interval_id ? task.interval_duration : task.estimated_duration;
      const endTime = new Date(currentTime.getTime() + duration * 60000);
      
      const entryId = uuidv4();
      const title = task.interval_id 
        ? `${task.title} (Interval)`
        : task.title;

      // Insert into database
      db.prepare(`
        INSERT INTO schedule_entries (
          id, task_id, interval_id, user_id, start_time, end_time, title, priority
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        entryId,
        task.id,
        task.interval_id || null,
        req.user.id,
        currentTime.toISOString(),
        endTime.toISOString(),
        title,
        task.priority
      );

      scheduleEntries.push({
        id: entryId,
        taskId: task.id,
        intervalId: task.interval_id || undefined,
        start: currentTime,
        end: endTime,
        title,
        priority: task.priority
      });

      // Add 15 minute break
      currentTime = new Date(endTime.getTime() + 15 * 60000);
    });

    res.json(scheduleEntries);
  } catch (error) {
    console.error('Generate schedule error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get schedule entries
router.get('/', authenticateToken, (req, res) => {
  try {
    const entries = db.prepare(`
      SELECT * FROM schedule_entries 
      WHERE user_id = ? 
      ORDER BY start_time
    `).all(req.user.id);

    const scheduleEntries = entries.map(entry => ({
      id: entry.id,
      taskId: entry.task_id,
      intervalId: entry.interval_id || undefined,
      start: new Date(entry.start_time),
      end: new Date(entry.end_time),
      title: entry.title,
      priority: entry.priority
    }));

    res.json(scheduleEntries);
  } catch (error) {
    console.error('Get schedule error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;