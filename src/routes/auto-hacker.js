const express = require('express');
const router = express.Router();
const { recordRequest } = require('./metrics');
const autoHackerController = require('../controllers/autoHackerController');
const rateLimit = require('express-rate-limit');

// Stricter rate limiting for auto hacker features due to resource intensity
const autoHackerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many scan requests. Please wait 10 minutes before trying again.',
    error: 'Auto hacker rate limit exceeded'
  }
});

// Start a new autonomous scan
router.post('/scan', recordRequest('autoHacker'), autoHackerLimiter, autoHackerController.startScan);

// Get scan status by ID
router.get('/status/:scanId', recordRequest('autoHacker'), autoHackerController.getScanStatus);

// Get scan results by ID
router.get('/results/:scanId', recordRequest('autoHacker'), autoHackerController.getScanResults);

// Get all scans for the current user/session
router.get('/history', recordRequest('autoHacker'), autoHackerController.getScanHistory);

// Cancel a running scan
router.post('/cancel/:scanId', recordRequest('autoHacker'), autoHackerController.cancelScan);

module.exports = router; 