#!/usr/bin/env node
/**
 * Health check script for Docker container
 * Exits with 0 if the service is healthy, 1 otherwise
 * 
 * By default, this script uses HTTP to check the health endpoint. If your
 * application is configured to only listen on HTTPS, set
 * HEALTHCHECK_USE_HTTPS=true in the environment to have this script use HTTPS
 * instead, or configure a separate HTTP health endpoint internally.
 */

const useHttps = process.env.HEALTHCHECK_USE_HTTPS === 'true';
const transport = useHttps ? require('https') : require('http');

const options = {
  hostname: 'localhost',
  port: process.env.PORT || (useHttps ? 443 : 3000),
  path: '/health',
  method: 'GET',
  timeout: 2000,
  // For HTTPS, ignore self-signed certificate errors in health checks
  rejectUnauthorized: false
};

const req = transport.request(options, (res) => {
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
