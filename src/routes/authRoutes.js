const express = require('express');
const { register, login, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

const router = express.Router();

// Register and login routes (public)
router.post('/register', register);
router.post('/login', login);

// Get current user route (protected)
router.get('/me', protect, getMe);

module.exports = router; 