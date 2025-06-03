const express = require('express');
const router = express.Router();
const aiAgentController = require('../controllers/aiAgentController');
const { optionalAuth } = require('../middleware/auth');
const { targetIntelligenceService } = require('../services/targetIntelligenceService');

/**
 * @route   POST /api/agent/command
 * @desc    Process a command through the AI agent
 * @access  Public (but auth is checked if provided)
 */
router.post('/command', optionalAuth, aiAgentController.processCommand);

/**
 * @route   GET /api/agent/health
 * @desc    Check the health of the AI agent
 * @access  Public
 */
router.get('/health', aiAgentController.healthCheck);

/**
 * @route   GET /api/agent/session/:sessionId/stats
 * @desc    Get session statistics and context insights
 * @access  Public
 */
router.get('/session/:sessionId/stats', aiAgentController.getSessionStats);

// **NEW: Target Intelligence Routes**

/**
 * @route   GET /api/agent/targets/:sessionId
 * @desc    Get target intelligence summary for current session
 * @access  Public
 */
router.get('/targets/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const targets = targetIntelligenceService.getSessionTargets(sessionId);
    const summary = targetIntelligenceService.getSessionIntelligenceSummary(sessionId);
    const suggestions = targetIntelligenceService.generateSuggestedActions(sessionId);
    
    res.json({
      success: true,
      data: {
        targets,
        summary,
        suggestions,
        sessionId
      }
    });
  } catch (error) {
    console.error('Error fetching target intelligence:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching target intelligence',
      error: error.message
    });
  }
});

/**
 * @route   GET /api/agent/target/:targetId
 * @desc    Get detailed target information
 * @access  Public
 */
router.get('/target/:targetId', async (req, res) => {
  try {
    const { targetId } = req.params;
    
    const target = targetIntelligenceService.getTarget(targetId);
    
    if (!target) {
      return res.status(404).json({
        success: false,
        message: 'Target not found'
      });
    }
    
    res.json({
      success: true,
      data: target
    });
  } catch (error) {
    console.error('Error fetching target details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching target details',
      error: error.message
    });
  }
});

module.exports = router; 