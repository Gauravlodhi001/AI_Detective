const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Load validated configuration and logger
const config = require('./utils/config');
const logger = require('./utils/logger');

const app = express();
const PORT = config.PORT;

// Helmet middleware for secure HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "https://cdn.jsdelivr.net"]
    }
  }
}));

// Strict CORS Configuration (Only allow local dashboard origins)
const allowedOrigins = [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Ensure required directories exist on startup
const directories = [
  path.join(__dirname, '../reports'),
  path.join(__dirname, '../uploads'),
  path.join(__dirname, '../cloned_repos')
];

directories.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    logger.info(`Created directory: ${dir}`);
  }
});

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// Global Rate Limiting: 200 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, message: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(globalLimiter);

// Tight Rate Limiting for resource-heavy endpoints: 10 requests per 15 minutes
const heavyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Heavy scan endpoint rate limit exceeded. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Import Routes
const authRouter = require('./routes/auth');
const scanRouter = require('./routes/scan');
const reportRouter = require('./routes/report');
const settingsRouter = require('./routes/settings');
const waptRouter = require('./routes/wapt');

// Mount Public Auth Endpoints
app.use('/api/auth', authRouter);

// Apply rate limiting to triggers (placed before auth check for DOS mitigation)
app.use('/api/scan/paste', heavyLimiter);
app.use('/api/scan/upload', heavyLimiter);
app.use('/api/scan/git', heavyLimiter);
app.use('/api/wapt/scan', heavyLimiter);

// Enforce authentication globally for all other API endpoints
const { authenticateToken } = require('./utils/auth');
app.use('/api', authenticateToken);

// Mount API Endpoints
app.use('/api/scan', scanRouter);
app.use('/api/reports', reportRouter);
app.use('/api/settings', settingsRouter);
app.use('/api/wapt', waptRouter);

// Fallback: serve frontend index.html for undefined routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Global Error Handler (Sanitizes stack trace leaks)
app.use((err, req, res, next) => {
  logger.error('Unhandled Server Error', { error: err, url: req.url, method: req.method });
  
  res.status(500).json({
    success: false,
    message: config.NODE_ENV === 'production'
      ? 'An unexpected server error occurred.'
      : (err.message || 'An unexpected server error occurred.')
  });
});

app.listen(PORT, () => {
  logger.info(`AI-Detective Backend running at http://localhost:${PORT}`);
});
