require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const http = require('http');
const cookieParser = require('cookie-parser');

// Connect to MongoDB
const connectDB = require('./config/db');
connectDB();

// Import WebSocket manager
const websocketManager = require('./websocketManager');

// Import routes
const dnsRoutes = require('./routes/dns');
const networkRoutes = require('./routes/network');
const securityRoutes = require('./routes/security');
const techRoutes = require('./routes/technology');
const shodanRoutes = require('./routes/shodan');
const { router: metricsRoutes, recordRequest } = require('./routes/metrics');
// Import AI Agent routes
const aiAgentRoutes = require('./routes/aiAgentRoutes');
// Import Auth routes
const authRoutes = require('./routes/authRoutes');
// Import Conversation routes
const conversationRoutes = require('./routes/conversationRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

// Create HTTP server from Express app (needed for WebSocket)
const server = http.createServer(app);

// Middleware
app.use(cors({
  // Configure CORS properly
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Allow cookies to be sent
}));
app.use(express.json());
app.use(cookieParser()); // Add cookie parser

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '../public')));

// Enhanced Helmet configuration with explicit security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'ws:', 'wss:'], // Allow WebSocket connections
      fontSrc: ["'self'", "cdnjs.cloudflare.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: {
    maxAge: 15552000, // 180 days in seconds
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  expectCt: {
    maxAge: 86400,
    enforce: true
  }
}));

// Add Permissions Policy header (not included in Helmet by default)
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 
    'camera=(), microphone=(), geolocation=(), interest-cohort=()'
  );
  next();
});

app.use(morgan('dev'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many requests, please try again later after cooling down.',
    error: 'Rate limit exceeded',
    rateLimitInfo: {
      windowMs: 15 * 60 * 1000,
      maxRequests: 100
    }
  }
});
app.use(limiter);

// Route-specific rate limiters
const dnsLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30, // limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many DNS lookup requests. Please wait a few minutes before trying again.',
    error: 'DNS rate limit exceeded',
    rateLimitInfo: {
      windowMs: 5 * 60 * 1000,
      maxRequests: 30
    }
  }
});

// AI Agent rate limiter
const aiAgentLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many AI agent requests. Please wait a minute before trying again.',
    error: 'AI Agent rate limit exceeded',
    rateLimitInfo: {
      windowMs: 1 * 60 * 1000,
      maxRequests: 10
    }
  }
});

// Auth rate limiters
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 30, // limit each IP to 30 requests per windowMs for login/register
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many authentication requests. Please wait a few minutes before trying again.',
    error: 'Auth rate limit exceeded'
  }
});

// Separate, more lenient rate limiter for /me endpoint
const profileLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // Higher limit for profile requests
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many profile requests. Please wait a minute before trying again.',
    error: 'Profile rate limit exceeded'
  }
});

// Conversation rate limiter
const conversationLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 50, // Higher limit for conversation requests
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    message: 'Too many conversation requests. Please wait a minute before trying again.',
    error: 'Conversation rate limit exceeded'
  }
});

// Routes with request monitoring
app.use('/api/dns', recordRequest('dns'), dnsLimiter, dnsRoutes);
app.use('/api/network', recordRequest('network'), networkRoutes);
app.use('/api/security', recordRequest('security'), securityRoutes);
app.use('/api/tech', recordRequest('tech'), techRoutes);
app.use('/api/shodan', recordRequest('shodan'), shodanRoutes);
app.use('/api/metrics', metricsRoutes);
// Add AI Agent routes
app.use('/api/agent', recordRequest('aiAgent'), aiAgentLimiter, aiAgentRoutes);
// Add Auth routes - use different rate limiters for different auth endpoints
app.use('/api/auth', recordRequest('auth'), authRoutes);
// Add Conversation routes
app.use('/api/conversations', recordRequest('conversations'), conversationLimiter, conversationRoutes);

// Apply specific rate limiters to auth routes
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/me', profileLimiter);

// Serve index.html at the root path
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Health check route
app.get('/api/health', recordRequest('health'), (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'An unexpected error occurred',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Initialize WebSocket server with HTTP server
websocketManager.initialize(server);

// Start HTTP server on PORT
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server initialized on the same port`);
});

module.exports = server; // Export server instead of app for testing 