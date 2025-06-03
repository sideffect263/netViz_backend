const { v4: uuidv4 } = require('uuid');
const { processUserCommand } = require('../services/aiAgentService');
const { contextManager } = require('../services/contextManager');
const websocketManager = require('../websocketManager');
const Conversation = require('../models/Conversation');

/**
 * Process a command through the AI agent
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.processCommand = async (req, res) => {
  try {
    const { command, conversationId } = req.body;
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
    
    // Get conversation history if conversationId is provided and user is authenticated
    let conversationHistory = [];
    let conversation = null;
    
    if (conversationId && req.user) {
      try {
        conversation = await Conversation.findById(conversationId);
        
        // Verify the conversation belongs to the user
        if (conversation && conversation.user.toString() === req.user.id) {
          // Add the new user message to the conversation only if it's not a duplicate of the last one
          const lastMessage = conversation.messages[conversation.messages.length - 1];

          if (!(lastMessage && lastMessage.role === 'user' && lastMessage.content === command)) {
            conversation.messages.push({
              role: 'user',
              content: command
            });
          }

          conversation.sessionId = sessionId;
          await conversation.save();
          
          conversationHistory = conversation.messages;
        }
      } catch (error) {
        console.error('Error fetching conversation:', error);
        // Continue without conversation history
      }
    }
    // Create new conversation if authenticated but no conversationId
    else if (req.user && !conversationId) {
      try {
        conversation = await Conversation.create({
          user: req.user.id,
          messages: [{
            role: 'user',
            content: command
          }],
          sessionId
        });
        
        conversationHistory = conversation.messages;
      } catch (error) {
        console.error('Error creating conversation:', error);
        // Continue without saving conversation
      }
    }
    
    // Process the command (this happens asynchronously)
    // We'll start processing and return the sessionId and conversationId immediately
    res.status(202).json({
      success: true,
      message: 'Command received and processing started',
      sessionId: sessionId,
      conversationId: conversation ? conversation._id : null
    });
    
    // Now process the command
    try {
      const result = await processUserCommand(command, sessionId, sendEventToSocket, conversationHistory);
      
      // Send final result via WebSocket too
      sendEventToSocket({
        type: 'command_result',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        result: result
      });
      
      // Save the assistant's response to the conversation if one exists
      if (conversation && req.user) {
        conversation.messages.push({
          role: 'assistant',
          content: result
        });
        await conversation.save();
      }
      
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

/**
 * Get session statistics and context insights
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.getSessionStats = (req, res) => {
  try {
    const { sessionId } = req.params;
    
    if (!sessionId) {
      return res.status(400).json({
        success: false,
        error: 'Session ID is required'
      });
    }
    
    const stats = contextManager.getSessionStats(sessionId);
    const insights = contextManager.getContextualInsights(sessionId);
    
    res.status(200).json({
      success: true,
      data: {
        ...stats,
        insights
      }
    });
  } catch (error) {
    console.error('Error getting session stats:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
}; 