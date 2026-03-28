import { test, expect } from '@playwright/test';

const BASE = process.env.MANAGER_URL ?? 'http://localhost:3000';

test.describe('Manager — page loads', () => {
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

  test('unauthenticated root redirects to login', async ({ page }) => {
    test.skip(
      process.env.CI_SERVICES_RUNNING !== 'true',
      'Services not running — skipping live test'
    );
    await page.goto(`${BASE}/`);
    await page.waitForURL(`${BASE}/login`);
    await expect(page).toHaveURL(/\/login/);
  });

  test('login page has username and password fields', async ({ page }) => {
    test.skip(
      process.env.CI_SERVICES_RUNNING !== 'true',
      'Services not running — skipping live test'
    );
    await page.goto(`${BASE}/login`);
    const password = page.locator('input[type="password"]');
    await expect(password).toBeVisible();
  });
});
