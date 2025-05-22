const { v4: uuidv4 } = require('uuid');
const { processUserCommand } = require('../services/aiAgentService');
const websocketManager = require('../websocketManager');

/**
 * Process a command through the AI agent
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.processCommand = async (req, res) => {
  try {
    const { command } = req.body;
    let { sessionId } = req.body;
    
    // Validate command
    if (!command || typeof command !== 'string' || command.trim() === '') {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid command. Please provide a non-empty command string.' 
      });
    }
    
    // If no sessionId provided, generate one
    if (!sessionId) {
      sessionId = uuidv4();
      console.log(`Generated new sessionId: ${sessionId}`);
    }
    
    // Create a function to send events to the WebSocket for this session
    const sendEventToSocket = (eventData) => {
      websocketManager.sendEventToSession(sessionId, eventData);
    };
    
    // Process the command (this happens asynchronously)
    // We'll start processing and return the sessionId immediately
    res.status(202).json({
      success: true,
      message: 'Command received and processing started',
      sessionId: sessionId
    });
    
    // Now process the command
    try {
      const result = await processUserCommand(command, sessionId, sendEventToSocket);
      
      // Send final result via WebSocket too
      sendEventToSocket({
        type: 'command_result',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        result: result
      });
      
    } catch (error) {
      console.error('Error processing command:', error);
      
      // Send error via WebSocket
      sendEventToSocket({
        type: 'error',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        error: error.message
      });
    }
    
  } catch (error) {
    console.error('Controller error in processCommand:', error);
    // If we haven't sent a response yet
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: error.message
      });
    }
  }
};

/**
 * Health check for the AI agent
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.healthCheck = (req, res) => {
  const wsConnectionCount = websocketManager.getConnectionCount();
  const wsSessionCount = websocketManager.getSessionCount();
  
  res.status(200).json({
    success: true,
    message: 'AI Agent is operational',
    websocket: {
      connections: wsConnectionCount,
      sessions: wsSessionCount
    }
  });
}; 