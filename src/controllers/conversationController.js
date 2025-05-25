const Conversation = require('../models/Conversation');

/**
 * Get all conversations for the authenticated user
 * @route GET /api/conversations
 */
exports.getConversations = async (req, res) => {
  try {
    const conversations = await Conversation.find({ user: req.user.id })
      .select('title createdAt updatedAt messages')
      .sort({ updatedAt: -1 });
    
    res.status(200).json({
      success: true,
      count: conversations.length,
      data: conversations
    });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

/**
 * Get a single conversation by ID
 * @route GET /api/conversations/:id
 */
exports.getConversation = async (req, res) => {
  try {
    const conversation = await Conversation.findById(req.params.id);
    
    // Check if conversation exists
    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found'
      });
    }
    
    // Check if user owns the conversation
    if (conversation.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this conversation'
      });
    }
    
    res.status(200).json({
      success: true,
      data: conversation
    });
  } catch (error) {
    console.error('Error fetching conversation:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

/**
 * Create a new conversation
 * @route POST /api/conversations
 */
exports.createConversation = async (req, res) => {
  try {
    const { title, message, sessionId } = req.body;
    
    // Validate input
    if (!message) {
      return res.status(400).json({
        success: false,
        message: 'Initial message is required'
      });
    }
    
    // Create conversation with initial message
    const conversation = await Conversation.create({
      title: title || 'New Conversation',
      user: req.user.id,
      messages: [{
        role: 'user',
        content: message
      }],
      sessionId
    });
    
    res.status(201).json({
      success: true,
      data: conversation
    });
  } catch (error) {
    console.error('Error creating conversation:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

/**
 * Add a message to an existing conversation
 * @route POST /api/conversations/:id/messages
 */
exports.addMessage = async (req, res) => {
  try {
    const { role, content } = req.body;
    
    // Validate input
    if (!role || !content) {
      return res.status(400).json({
        success: false,
        message: 'Role and content are required'
      });
    }
    
    // Check if role is valid
    if (!['user', 'assistant'].includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Role must be either "user" or "assistant"'
      });
    }
    
    // Find conversation
    let conversation = await Conversation.findById(req.params.id);
    
    // Check if conversation exists
    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found'
      });
    }
    
    // Check if user owns the conversation
    if (conversation.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to modify this conversation'
      });
    }
    
    // Add message to conversation
    conversation.messages.push({
      role,
      content
    });
    
    // Update sessionId if provided
    if (req.body.sessionId) {
      conversation.sessionId = req.body.sessionId;
    }
    
    // Save the updated conversation
    await conversation.save();
    
    res.status(200).json({
      success: true,
      data: conversation
    });
  } catch (error) {
    console.error('Error adding message:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

/**
 * Update conversation title
 * @route PUT /api/conversations/:id
 */
exports.updateConversation = async (req, res) => {
  try {
    const { title } = req.body;
    
    // Find conversation
    let conversation = await Conversation.findById(req.params.id);
    
    // Check if conversation exists
    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found'
      });
    }
    
    // Check if user owns the conversation
    if (conversation.user.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to modify this conversation'
      });
    }
    
    // Update title
    if (title) {
      conversation.title = title;
    }
    
    // Save the updated conversation
    await conversation.save();
    
    res.status(200).json({
      success: true,
      data: conversation
    });
  } catch (error) {
    console.error('Error updating conversation:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

/**
 * Delete a conversation
 * @route DELETE /api/conversations/:id
 */
exports.deleteConversation = async (req, res) => {
  try {
    // Find conversation and ensure ownership in a single query
    const conversation = await Conversation.findOne({ _id: req.params.id, user: req.user.id });

    if (!conversation) {
      // Either not found or not owned by the user
      return res.status(404).json({
        success: false,
        message: 'Conversation not found or not accessible'
      });
    }

    // Use deleteOne to avoid deprecation issues with remove()
    await Conversation.deleteOne({ _id: conversation._id });
    
    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (error) {
    console.error('Error deleting conversation:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
}; 