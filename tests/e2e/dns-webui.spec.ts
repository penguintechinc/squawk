import { test, expect, Browser, BrowserContext } from '@playwright/test';
import path from 'path';
import fs from 'fs';

const BASE = process.env.DNS_WEBUI_URL ?? 'http://localhost:5173';
const TEST_USER = process.env.TEST_USER ?? 'admin@localhost';
const TEST_PASS = process.env.TEST_PASS ?? 'admin123';
const AUTH_FILE = path.join(__dirname, '.auth', 'user.json');

const servicesRunning = () => process.env.CI_SERVICES_RUNNING === 'true';

// Protected console routes every authenticated user should reach without JS errors.
const PROTECTED_ROUTES = [
  '/dns_console/index',
  '/dns_console/tokens',
  '/dns_console/domains',
  '/dns_console/permissions',
  '/dns_console/blacklist',
  '/dns_console/certificates',
  '/dns_console/logs',
] as const;

// ---------------------------------------------------------------------------
// Auth setup — log in once, reuse storage state for protected-route tests
// ---------------------------------------------------------------------------

let authContext: BrowserContext | null = null;

test.beforeAll(async ({ browser }: { browser: Browser }) => {
  if (!servicesRunning()) return;

  fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true });

  authContext = await browser.newContext();
  const page = await authContext.newPage();

  await page.goto(`${BASE}/login`);
  await page
    .locator('input[type="email"], input[name="username"], input[name="email"]')
    .first()
    .fill(TEST_USER);
  await page.locator('input[type="password"]').fill(TEST_PASS);
  await page.keyboard.press('Enter');

  // Wait for redirect away from login; swallow if login fails (no live server)
  await page.waitForURL(/\/dns_console\//, { timeout: 10_000 }).catch(() => {});

  await authContext.storageState({ path: AUTH_FILE });
  await page.close();
});

test.afterAll(async () => {
  await authContext?.close();
  authContext = null;
});

// ---------------------------------------------------------------------------
// Unauthenticated smoke tests
// ---------------------------------------------------------------------------

test.describe('DNS WebUI — page loads', () => {
  test('login page loads without JS errors', async ({ page }) => {
    test.skip(!servicesRunning(), 'Services not running — skipping live test');
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto(`${BASE}/login`);
    await expect(page.locator('[data-testid="login-page"], form, input[type="password"]')).toBeVisible();
    expect(errors).toHaveLength(0);
  });

  test('unauthenticated navigation redirects to login', async ({ page }) => {
    test.skip(!servicesRunning(), 'Services not running — skipping live test');
    await page.goto(`${BASE}/`);
    await page.waitForURL(`${BASE}/login`);
    await expect(page).toHaveURL(/\/login/);
  });

  test('login page has password field', async ({ page }) => {
    test.skip(!servicesRunning(), 'Services not running — skipping live test');
    await page.goto(`${BASE}/login`);
    await expect(page.locator('input[type="password"]')).toBeVisible();
  });

  test('invalid credentials show error', async ({ page }) => {
    test.skip(!servicesRunning(), 'Services not running — skipping live test');
    await page.goto(`${BASE}/login`);
    const emailOrUser = page.locator('input[type="email"], input[name="username"], input[name="email"]').first();
    const password = page.locator('input[type="password"]');

    await emailOrUser.fill('invalid@example.com');
    await password.fill('wrongpassword');
    await page.keyboard.press('Enter');

    await page.waitForTimeout(1000);
    await expect(page).toHaveURL(/\/login/);
  });
});

// ---------------------------------------------------------------------------
// Authenticated smoke tests — protected routes
// ---------------------------------------------------------------------------

test.describe('DNS WebUI — protected pages', () => {
  test.use({ storageState: AUTH_FILE });

  for (const route of PROTECTED_ROUTES) {
    test(`${route} loads without JS errors`, async ({ page }) => {
      test.skip(!servicesRunning(), 'Services not running — skipping live test');

      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(e.message));

      await page.goto(`${BASE}${route}`);

      // Should not be bounced back to login
      await expect(page).not.toHaveURL(/\/login/);
      expect(errors).toHaveLength(0);
    });
  }
});

// ---------------------------------------------------------------------------
// Form modal tests — open, empty submit triggers validation error
// ---------------------------------------------------------------------------

test.describe('DNS WebUI — form modals', () => {
  test.use({ storageState: AUTH_FILE });

  test('new token form shows validation error on empty submit', async ({ page }) => {
    test.skip(!servicesRunning(), 'Services not running — skipping live test');

    await page.goto(`${BASE}/dns_console/tokens/new`);
    await page.locator('button[type="submit"], [data-testid="submit"]').click();

    await expect(
      page.locator('.error, .invalid-feedback, [data-testid="form-error"], .flash-error, .alert-danger').first()
    ).toBeVisible({ timeout: 5_000 });
  });

  test('new domain form shows validation error on empty submit', async ({ page }) => {
    test.skip(!servicesRunning(), 'Services not running — skipping live test');

    await page.goto(`${BASE}/dns_console/domains/new`);
    await page.locator('button[type="submit"], [data-testid="submit"]').click();

    await expect(
      page.locator('.error, .invalid-feedback, [data-testid="form-error"], .flash-error, .alert-danger').first()
    ).toBeVisible({ timeout: 5_000 });
  });
});
