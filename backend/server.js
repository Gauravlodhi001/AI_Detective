const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS and parsing of JSON/URL-encoded data
app.use(cors());
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
    console.log(`Created directory: ${dir}`);
  }
});

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// Import Routes
const scanRouter = require('./routes/scan');
const reportRouter = require('./routes/report');
const settingsRouter = require('./routes/settings');
const waptRouter = require('./routes/wapt');

// Mount API Endpoints
app.use('/api/scan', scanRouter);
app.use('/api/reports', reportRouter);
app.use('/api/settings', settingsRouter);
app.use('/api/wapt', waptRouter);

// Fallback: serve frontend index.html for undefined routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err);
  res.status(500).json({
    success: false,
    message: err.message || 'An unexpected server error occurred.'
  });
});

app.listen(PORT, () => {
  console.log(`AI-Detective Backend running at http://localhost:${PORT}`);
});
