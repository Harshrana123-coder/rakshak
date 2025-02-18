// server/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { exec } = require('child_process');
const { checkSecurityHeaders } = require('./utils/headersCheck');
const { checkXSS } = require('./utils/xssCheck');
const { checkSQLi } = require('./utils/sqliCheck');
const { checkSSL } = require('./utils/sslCheck');

// Initialize Express app
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// Validation middleware
const validateScanRequest = (req, res, next) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ message: 'URL is required' });
  }
  try {
    new URL(url);
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid URL' });
  }
};

// Scan endpoint with parallel processing
app.post('/api/scan', validateScanRequest, async (req, res) => {
  try {
    const { url } = req.body;
    
    // Timeout configuration
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Scan timeout')), 30000);
    });

    // Check functions with error handling
    const runCheck = (checkFn, param = url) => 
      checkFn(param).catch(() => []);

    // Execute all security checks in parallel
    const vulnerabilities = await Promise.race([
      Promise.allSettled([
        runCheck(checkSecurityHeaders),
        runCheck(checkSSL, new URL(url).hostname),
        runCheck(checkXSS),
        runCheck(checkSQLi)
      ]).then(results => 
        results.flatMap(result => 
          result.status === 'fulfilled' ? result.value : []
        )
      ),
      timeoutPromise
    ]);

    res.json({ vulnerabilities });
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      message: error.message.includes('timeout') 
        ? 'Scan timed out (max 30 seconds)' 
        : 'Scan failed'
    });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});