# Agent Instructions

## Commands
- **Build**: `pnpm run build` (using tsup)
- **Type check**: `pnpm run check` (tsc --noEmit)
- **Test**: `pnpm run test` (vitest run)
- **Test watch**: `pnpm run test:watch` (vitest)
- **Single test**: `pnpm run test -- --grep "test name"`

## Architecture
- Simple TypeScript library with single main function `sanitizeUrl`
- Source in `src/index.ts`, tests in `src/index.test.ts`
- Built to `dist/` directory with ESM format and TypeScript declarations
- Focus: Security-first URL sanitization preventing XSS and command injection

## Code Style
- TypeScript with strict mode enabled
- ESM modules (`import`/`export`)
- Use `URL` constructor for URL parsing
- Vitest for testing with `describe`/`it`/`expect` pattern
- Function expressions over arrow functions for main exports
- Throw errors with descriptive messages for invalid inputs
- Use `encodeURIComponent` for sanitization
- camelCase naming convention
