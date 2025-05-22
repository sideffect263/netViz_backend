const express = require('express');
const router = express.Router();
const aiAgentController = require('../controllers/aiAgentController');

/**
 * @route   POST /api/agent/command
 * @desc    Process a command through the AI agent
 * @access  Public
 */
router.post('/command', aiAgentController.processCommand);

/**
 * @route   GET /api/agent/health
 * @desc    Check the health of the AI agent
 * @access  Public
 */
router.get('/health', aiAgentController.healthCheck);

module.exports = router; 