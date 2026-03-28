import { test, expect } from '@playwright/test';

const BASE = process.env.DNS_WEBUI_URL ?? 'http://localhost:5173';

test.describe('DNS WebUI — page loads', () => {
  test('login page loads without JS errors', async ({ page }) => {
    test.skip(
      process.env.CI_SERVICES_RUNNING !== 'true',
      'Services not running — skipping live test'
    );
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto(`${BASE}/login`);
    await expect(page.locator('[data-testid="login-page"], form, input[type="password"]')).toBeVisible();
    expect(errors).toHaveLength(0);
  });

  test('unauthenticated navigation redirects to login', async ({ page }) => {
    test.skip(
      process.env.CI_SERVICES_RUNNING !== 'true',
      'Services not running — skipping live test'
    );
    await page.goto(`${BASE}/`);
    await page.waitForURL(`${BASE}/login`);
    await expect(page).toHaveURL(/\/login/);
  });

  test('login page has password field', async ({ page }) => {
    test.skip(
      process.env.CI_SERVICES_RUNNING !== 'true',
      'Services not running — skipping live test'
    );
    await page.goto(`${BASE}/login`);
    await expect(page.locator('input[type="password"]')).toBeVisible();
  });

  test('invalid credentials show error', async ({ page }) => {
    test.skip(
      process.env.CI_SERVICES_RUNNING !== 'true',
      'Services not running — skipping live test'
    );
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
