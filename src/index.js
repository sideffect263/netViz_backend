require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Import routes
const dnsRoutes = require('./routes/dns');
const networkRoutes = require('./routes/network');
const securityRoutes = require('./routes/security');
const techRoutes = require('./routes/technology');
const shodanRoutes = require('./routes/shodan');
const { router: metricsRoutes, recordRequest } = require('./routes/metrics');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  // Configure CORS properly
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '../public')));

// Enhanced Helmet configuration with explicit security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
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
});
app.use(limiter);

// Routes with request monitoring
app.use('/api/dns', recordRequest('dns'), dnsRoutes);
app.use('/api/network', recordRequest('network'), networkRoutes);
app.use('/api/security', recordRequest('security'), securityRoutes);
app.use('/api/tech', recordRequest('tech'), techRoutes);
app.use('/api/shodan', recordRequest('shodan'), shodanRoutes);
app.use('/api/metrics', metricsRoutes);

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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app; // For testing 