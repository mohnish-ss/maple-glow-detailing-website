# Repository Guidelines

## Project Structure & Module Organization

This is a Node.js 20+ Express application using EJS server-rendered pages and MongoDB.

- `index.js` contains application setup, middleware, routes, validation, session handling, and database operations.
- `views/` contains page templates; shared page fragments are in `views/layouts/`.
- `public/` contains static assets: shared CSS, browser scripts, and images.
- `.env.example` documents required environment variables. Never commit `.env`, database credentials, or session secrets.

Keep route behavior and its corresponding EJS page aligned.

## Build, Test, and Development Commands

- `npm install` installs locked dependencies.
- `npm start` runs `node index.js`; it requires valid MongoDB and session configuration in `.env`.
- `npm run check` performs a Node syntax check on `index.js`.
- `npm test` currently runs the same syntax check. Run it before submitting changes.

There is no configured formatter or browser test suite. Validate template and CSS changes manually at relevant viewport sizes.

## Coding Style & Naming Conventions

Use two-space JavaScript indentation and the surrounding ESM style: top-level `import`, `const` by default, semicolons, and double-quoted route strings. Use camelCase for functions and variables (`normalizeUsername`), PascalCase for constructors, and kebab-case for CSS classes (`booking-grid`).

Prefer existing CSS variables such as `--primary`, `--border-light`, and `--transition` over hard-coded repeated values. Keep validation close to the route it protects and preserve the existing CSRF, rate-limit, and authentication middleware.

## Testing Guidelines

Run `npm test` for every change. For routes, verify authenticated and unauthenticated paths, invalid input, and expected JSON or redirects. For UI work, test keyboard focus and mobile widths. When a test framework is introduced, name tests after the covered route or behavior.

## Commit & Pull Request Guidelines

Recent commits use short imperative summaries, such as `Upgrade runtime dependencies`. Keep them concise, present-tense, and scoped to one change. Pull requests should state user impact, verification performed, related issues, and include screenshots for visual changes. Avoid unrelated refactors in a targeted fix.

## Security & Configuration

Set `SESSION_SECRET` to at least 32 characters and supply `MONGODB_URI` (or its documented fallback) before running locally. Treat request data as untrusted, use existing validators, and do not weaken Helmet, CSRF, session-cookie, or authorization settings without a documented reason.
