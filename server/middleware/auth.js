const jwt = require('jsonwebtoken');
const { db } = require('../database');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    // Get full user data from database
    const userData = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }

    req.user = {
      id: userData.id,
      name: userData.name,
      email: userData.email,
      role: userData.role,
      workingHours: {
        start: userData.working_hours_start,
        end: userData.working_hours_end,
        daysOfWeek: JSON.parse(userData.working_days)
      }
    };
    next();
  });
};

const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

module.exports = { authenticateToken, requireRole, JWT_SECRET };