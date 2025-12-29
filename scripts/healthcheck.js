#!/usr/bin/env node
/**
 * Health check script for Docker container
 * Exits with 0 if the service is healthy, 1 otherwise
 * 
 * Note: This script uses HTTP to check the health endpoint. If your application
 * is configured to only listen on HTTPS, you'll need to modify this script
 * or configure a separate HTTP health endpoint internally.
 */

const http = require('http');

const options = {
  hostname: 'localhost',
  port: process.env.PORT || 3000,
  path: '/health',
  method: 'GET',
  timeout: 2000
};

const req = http.request(options, (res) => {
  if (res.statusCode === 200) {
    process.exit(0);
  } else {
    console.error(`Health check failed: HTTP ${res.statusCode}`);
    process.exit(1);
  }
});

req.on('error', (err) => {
  console.error(`Health check failed: ${err.message}`);
  process.exit(1);
});

req.on('timeout', () => {
  console.error('Health check failed: Request timeout');
  req.destroy();
  process.exit(1);
});

req.end();
