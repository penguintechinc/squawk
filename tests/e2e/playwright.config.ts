import { defineConfig, devices } from '@playwright/test';
import path from 'path';
import { execFileSync } from 'child_process';

const repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], {
  encoding: 'utf8',
}).trim();
const repoName = path.basename(repoRoot);
const artifactDir = `/tmp/playwright-${repoName}`;

export default defineConfig({
  testDir: '.',
  outputDir: artifactDir,
  timeout: 30_000,
  retries: 1,
  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
