const mongoose = require('mongoose');

// Message schema for individual messages in a conversation
const MessageSchema = new mongoose.Schema({
  role: {
    type: String,
    enum: ['user', 'assistant'],
    required: true
  },
  content: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

// Conversation schema to store the entire conversation history
const ConversationSchema = new mongoose.Schema({
  title: {
    type: String,
    default: 'New Conversation'
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  messages: [MessageSchema],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  // Optional: Store the most recent sessionId used with this conversation
  sessionId: {
    type: String
  }
});

// Update the updatedAt timestamp before saving
ConversationSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Generate a title from the first user message if not provided
ConversationSchema.pre('save', function(next) {
  if (this.isNew && !this.title && this.messages.length > 0) {
    // Find the first user message
    const firstUserMessage = this.messages.find(msg => msg.role === 'user');
    if (firstUserMessage) {
      // Truncate and use as title
      this.title = firstUserMessage.content.substring(0, 40) + (firstUserMessage.content.length > 40 ? '...' : '');
    }
  }
  next();
});

module.exports = mongoose.model('Conversation', ConversationSchema); 