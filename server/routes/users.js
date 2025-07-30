const express = require('express');
const { db } = require('../database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get all users (for team assignment)
router.get('/', authenticateToken, (req, res) => {
  try {
    const users = db.prepare(`
      SELECT id, name, email, role
      FROM users
      ORDER BY name
    `).all();

    res.json(users.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      workingHours: {
        start: '09:00',
        end: '17:00',
        daysOfWeek: [1, 2, 3, 4, 5]
      },
      teams: []
    })));
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
router.put('/profile', authenticateToken, (req, res) => {
  try {
    const { name, email, workingHours } = req.body;

    db.prepare(`
      UPDATE users SET
        name = ?,
        email = ?,
        working_hours_start = ?,
        working_hours_end = ?,
        working_days = ?
      WHERE id = ?
    `).run(
      name,
      email,
      workingHours.start,
      workingHours.end,
      JSON.stringify(workingHours.daysOfWeek),
      req.user.id
    );

    const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

    res.json({
      id: updatedUser.id,
      name: updatedUser.name,
      email: updatedUser.email,
      role: updatedUser.role,
      workingHours: {
        start: updatedUser.working_hours_start,
        end: updatedUser.working_hours_end,
        daysOfWeek: JSON.parse(updatedUser.working_days)
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;