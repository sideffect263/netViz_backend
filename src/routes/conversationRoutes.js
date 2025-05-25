const express = require('express');
const router = express.Router();
const { 
  getConversations, 
  getConversation, 
  createConversation, 
  addMessage, 
  updateConversation, 
  deleteConversation 
} = require('../controllers/conversationController');
const { protect } = require('../middleware/auth');

// Apply auth middleware to all routes
router.use(protect);

// Routes
router.route('/')
  .get(getConversations)
  .post(createConversation);

router.route('/:id')
  .get(getConversation)
  .put(updateConversation)
  .delete(deleteConversation);

router.route('/:id/messages')
  .post(addMessage);

module.exports = router; 