// K6 Load Test Script for Squawk DNS System
import http from 'k6/http';
import { check, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const dnsQueries = new Counter('dns_queries_total');
const dnsErrors = new Counter('dns_errors_total');
const dnsResponseTime = new Trend('dns_response_time');
const authFailures = new Rate('auth_failures_rate');

// Test configuration
export let options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up
    { duration: '1m', target: 50 },    // Stay at 50 users
    { duration: '30s', target: 100 },  // Ramp to 100 users
    { duration: '2m', target: 100 },   // Stay at 100 users
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<1000'], // 95% of requests under 1s
    http_req_failed: ['rate<0.05'],    // Error rate under 5%
    dns_response_time: ['p(99)<2000'], // 99% under 2s
    auth_failures_rate: ['rate<0.01'], // Auth failures under 1%
  },
};

// Test data
const domains = [
  'example.com',
  'google.com',
  'cloudflare.com',
  'github.com',
  'stackoverflow.com',
  'test.com',
  'api.example.com',
  'subdomain.example.com'
];

const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS'];

const tokens = [
  'test-token-for-development',
  'admin-token-12345',
  'client-token-67890',
  'invalid-token-123' // This should fail
];

// Base URL for DNS server
const BASE_URL = 'http://dns-server:8080';

export default function() {
  group('DNS Query Tests', function() {

    // Test 1: Valid DNS queries with valid tokens
    group('Valid DNS Queries', function() {
      const domain = domains[Math.floor(Math.random() * domains.length)];
      const recordType = recordTypes[Math.floor(Math.random() * recordTypes.length)];
      const token = tokens[Math.floor(Math.random() * (tokens.length - 1))]; // Exclude invalid token

      const url = `${BASE_URL}/dns-query?name=${domain}&type=${recordType}`;
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      };

      const startTime = Date.now();
      const response = http.get(url, { headers });
      const responseTime = Date.now() - startTime;

      dnsQueries.add(1);
      dnsResponseTime.add(responseTime);

      const isSuccess = check(response, {
        'status is 200': (r) => r.status === 200,
        'response has Status field': (r) => {
          try {
            const body = JSON.parse(r.body);
            return 'Status' in body;
          } catch {
            return false;
          }
        },
        'response time < 1000ms': () => responseTime < 1000,
      });

      if (!isSuccess) {
        dnsErrors.add(1);
      }
    });

    // Test 2: Authentication failures
    group('Authentication Tests', function() {
      const domain = 'example.com';
      const invalidToken = 'invalid-token-123';

      const url = `${BASE_URL}/dns-query?name=${domain}&type=A`;
      const headers = {
        'Authorization': `Bearer ${invalidToken}`,
        'Accept': 'application/json'
      };

      const response = http.get(url, { headers });

      const authFailed = check(response, {
        'auth failure returns 403': (r) => r.status === 403,
      });

      authFailures.add(authFailed ? 0 : 1); // Inverted because we expect auth to fail
    });

    // Test 3: No authentication token
    group('No Token Tests', function() {
      const domain = 'example.com';
      const url = `${BASE_URL}/dns-query?name=${domain}&type=A`;

      const response = http.get(url);

      check(response, {
        'no token returns 403': (r) => r.status === 403,
      });
    });

    // Test 4: Invalid domain names
    group('Invalid Domain Tests', function() {
      const invalidDomains = [
        'invalid..domain',
        'domain with spaces',
        '',
        'very-long-domain-name-that-exceeds-limits.com'
      ];

      const invalidDomain = invalidDomains[Math.floor(Math.random() * invalidDomains.length)];
      const token = 'test-token-for-development';

      const url = `${BASE_URL}/dns-query?name=${encodeURIComponent(invalidDomain)}&type=A`;
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      };

      const response = http.get(url, { headers });

      check(response, {
        'invalid domain returns 400': (r) => r.status === 400,
      });
    });

    // Test 5: Web Console API
    group('Web Console API Tests', function() {
      const token = 'admin-token-12345';

      // Test token validation endpoint
      const validateUrl = `${BASE_URL}/dns_console/api/validate/${token}`;
      const validateResponse = http.get(validateUrl);

      check(validateResponse, {
        'validate endpoint returns 200': (r) => r.status === 200,
        'validate response is valid': (r) => {
          try {
            const body = JSON.parse(r.body);
            return body.valid === true;
          } catch {
            return false;
          }
        },
      });

      // Test permission check endpoint
      const permUrl = `${BASE_URL}/dns_console/api/check_permission`;
      const permPayload = JSON.stringify({
        token: token,
        domain: 'example.com'
      });

      const permResponse = http.post(permUrl, permPayload, {
        headers: { 'Content-Type': 'application/json' }
      });

      check(permResponse, {
        'permission check returns 200': (r) => r.status === 200,
        'permission check response valid': (r) => {
          try {
            const body = JSON.parse(r.body);
            return 'allowed' in body;
          } catch {
            return false;
          }
        },
      });
    });
  });

  // Small delay between iterations
  sleep(Math.random() * 2);
}

// Setup function - runs once before the test
export function setup() {
  console.log('Starting Squawk DNS Load Test...');
  console.log(`Target: ${BASE_URL}`);
  console.log(`Test domains: ${domains.join(', ')}`);
  console.log(`Record types: ${recordTypes.join(', ')}`);

  // Verify the server is responding
  const healthCheck = http.get(`${BASE_URL}/health`);
  if (healthCheck.status !== 200) {
    console.warn('Warning: Health check failed, server may not be ready');
  }

  return {};
}

// Teardown function - runs once after the test
export function teardown(data) {
  console.log('Load test completed!');
  console.log('Check the test results for detailed metrics.');
}

// Helper function for random delays
function sleep(seconds) {
  // K6 doesn't have a built-in sleep in this context, simulate with a loop
  const start = Date.now();
  while (Date.now() - start < seconds * 1000) {
    // Busy wait
  }
}
