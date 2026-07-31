import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: '/crypto-lab-stream-ward/',
  build: { target: 'es2022' },
  test: {
    // Colocated unit tests only — keeps the Playwright specs in e2e/ out of the Vitest run.
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
})
