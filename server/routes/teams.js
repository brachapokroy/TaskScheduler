const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get all teams for user
router.get('/', authenticateToken, (req, res) => {
  try {
    const teams = db.prepare(`
      SELECT DISTINCT t.*, u.name as admin_name
      FROM teams t
      LEFT JOIN users u ON t.admin_id = u.id
      LEFT JOIN team_members tm ON t.id = tm.team_id
      WHERE t.admin_id = ? OR tm.user_id = ?
      ORDER BY t.created_at DESC
    `).all(req.user.id, req.user.id);

    const teamsWithMembers = teams.map(team => {
      const members = db.prepare(`
        SELECT u.id, u.name, u.email
        FROM users u
        JOIN team_members tm ON u.id = tm.user_id
        WHERE tm.team_id = ?
      `).all(team.id);

      return {
        id: team.id,
        name: team.name,
        description: team.description,
        adminId: team.admin_id,
        members: members.map(m => m.id),
        createdAt: new Date(team.created_at)
      };
    });

    res.json(teamsWithMembers);
  } catch (error) {
    console.error('Get teams error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create team
router.post('/', authenticateToken, (req, res) => {
  try {
    const { name, description, members = [] } = req.body;
    const teamId = uuidv4();

    // Create team
    db.prepare(`
      INSERT INTO teams (id, name, description, admin_id)
      VALUES (?, ?, ?, ?)
    `).run(teamId, name, description, req.user.id);

    // Add admin as member
    db.prepare(`
      INSERT INTO team_members (team_id, user_id)
      VALUES (?, ?)
    `).run(teamId, req.user.id);

    // Add other members
    const addMember = db.prepare(`
      INSERT OR IGNORE INTO team_members (team_id, user_id)
      VALUES (?, ?)
    `);

    members.forEach(memberId => {
      if (memberId !== req.user.id) {
        addMember.run(teamId, memberId);
      }
    });

    const team = db.prepare('SELECT * FROM teams WHERE id = ?').get(teamId);
    
    res.status(201).json({
      id: team.id,
      name: team.name,
      description: team.description,
      adminId: team.admin_id,
      members: [req.user.id, ...members.filter(id => id !== req.user.id)],
      createdAt: new Date(team.created_at)
    });
  } catch (error) {
    console.error('Create team error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update team
router.put('/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, members = [] } = req.body;

    // Check if user is admin of this team
    const team = db.prepare(`
      SELECT * FROM teams WHERE id = ? AND admin_id = ?
    `).get(id, req.user.id);

    if (!team) {
      return res.status(404).json({ error: 'Team not found or access denied' });
    }

    // Update team
    db.prepare(`
      UPDATE teams SET name = ?, description = ?
      WHERE id = ?
    `).run(name, description, id);

    // Update members
    db.prepare('DELETE FROM team_members WHERE team_id = ?').run(id);
    
    // Re-add admin
    db.prepare(`
      INSERT INTO team_members (team_id, user_id)
      VALUES (?, ?)
    `).run(id, req.user.id);

    // Add other members
    const addMember = db.prepare(`
      INSERT OR IGNORE INTO team_members (team_id, user_id)
      VALUES (?, ?)
    `);

    members.forEach(memberId => {
      if (memberId !== req.user.id) {
        addMember.run(id, memberId);
      }
    });

    const updatedTeam = db.prepare('SELECT * FROM teams WHERE id = ?').get(id);
    
    res.json({
      id: updatedTeam.id,
      name: updatedTeam.name,
      description: updatedTeam.description,
      adminId: updatedTeam.admin_id,
      members: [req.user.id, ...members.filter(memberId => memberId !== req.user.id)],
      createdAt: new Date(updatedTeam.created_at)
    });
  } catch (error) {
    console.error('Update team error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete team
router.delete('/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;

    // Check if user is admin of this team
    const team = db.prepare(`
      SELECT * FROM teams WHERE id = ? AND admin_id = ?
    `).get(id, req.user.id);

    if (!team) {
      return res.status(404).json({ error: 'Team not found or access denied' });
    }

    db.prepare('DELETE FROM teams WHERE id = ?').run(id);
    res.status(204).send();
  } catch (error) {
    console.error('Delete team error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;