import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  use: {
    ...devices['Desktop Chrome'],
    channel: 'msedge',
    baseURL: process.env.WAS_LAB_BASE_URL || 'http://127.0.0.1:5173',
  },
});
