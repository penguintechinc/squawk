/**
 * Screenshot Capture Script for Squawk DNS Web Console
 * Uses Puppeteer to capture screenshots of all dashboard pages
 */

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const BASE_URL = process.env.WEB_CONSOLE_URL || 'http://localhost:8005';
const OUTPUT_DIR = path.join(__dirname, '..', 'docs', 'screenshots');

// Pages to capture
const pages = [
  { name: 'login', path: '/auth/login', authenticated: false },
  { name: 'dashboard', path: '/dashboard/', authenticated: true },
  { name: 'queries', path: '/dashboard/queries', authenticated: true },
  { name: 'users', path: '/dashboard/users', authenticated: true },
  { name: 'groups', path: '/dashboard/groups', authenticated: true },
  { name: 'zones', path: '/dashboard/zones', authenticated: true },
  { name: 'records', path: '/dashboard/records', authenticated: true },
  { name: 'permissions', path: '/dashboard/permissions', authenticated: true },
  { name: 'ioc', path: '/dashboard/ioc', authenticated: true },
  { name: 'threats', path: '/dashboard/threats', authenticated: true },
  { name: 'blocked', path: '/dashboard/blocked', authenticated: true },
  { name: 'logs', path: '/dashboard/logs', authenticated: true },
  { name: 'cache', path: '/dashboard/cache', authenticated: true },
  { name: 'config', path: '/dashboard/config', authenticated: true },
  { name: 'analytics', path: '/dashboard/analytics', authenticated: true },
];

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function captureScreenshots() {
  console.log('Squawk DNS - Screenshot Capture');
  console.log('================================');
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Output Dir: ${OUTPUT_DIR}`);
  console.log('');

  // Create output directory
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    console.log(`Created output directory: ${OUTPUT_DIR}`);
  }

  // Launch browser
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  let isAuthenticated = false;

  for (const pageInfo of pages) {
    try {
      // Handle authentication
      if (pageInfo.authenticated && !isAuthenticated) {
        console.log('Authenticating...');
        await page.goto(`${BASE_URL}/auth/login`, { waitUntil: 'networkidle0', timeout: 30000 });
        await sleep(500);

        // Fill login form
        await page.type('input[name="email"]', 'admin@localhost');
        await page.type('input[name="password"]', 'admin123');

        // Submit form
        await page.click('button[type="submit"]');

        // Wait for redirect
        try {
          await page.waitForFunction(
            () => !window.location.pathname.includes('/login'),
            { timeout: 10000 }
          );
          isAuthenticated = true;
          console.log('  Authenticated successfully');
        } catch (e) {
          console.error('  Authentication failed - continuing with unauthenticated captures');
        }
        await sleep(1000);
      }

      console.log(`Capturing ${pageInfo.name}...`);
      await page.goto(`${BASE_URL}${pageInfo.path}`, {
        waitUntil: 'networkidle0',
        timeout: 30000
      });
      await sleep(1500); // Wait for any animations/data to load

      // Check if redirected to login (session expired)
      const currentUrl = page.url();
      if (pageInfo.authenticated && currentUrl.includes('/login')) {
        console.log(`  WARNING: Redirected to login, skipping ${pageInfo.name}`);
        isAuthenticated = false;
        continue;
      }

      // Capture screenshot
      const filename = `${pageInfo.name}.png`;
      await page.screenshot({
        path: path.join(OUTPUT_DIR, filename),
        fullPage: false,
      });
      console.log(`  Saved: ${filename}`);

    } catch (error) {
      console.error(`  Error capturing ${pageInfo.name}: ${error.message}`);
    }
  }

  await browser.close();

  console.log('');
  console.log('Screenshot capture complete!');
  console.log(`Screenshots saved to: ${OUTPUT_DIR}`);

  // List captured files
  const files = fs.readdirSync(OUTPUT_DIR).filter(f => f.endsWith('.png'));
  console.log(`\nCaptured ${files.length} screenshots:`);
  files.forEach(f => console.log(`  - ${f}`));
}

// Run
captureScreenshots().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
