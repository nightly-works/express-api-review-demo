# Express API review of an AI-built app (demo)

A proof piece for security reviews of Node.js back ends written with AI coding tools (Cursor, Claude Code, Bolt, Replit). The fictional app is a document space shared by several client companies: an Express 5 API with JWT sign-in and SQLite. Four flaws of the kind these tools leave behind, each reproduced as an attack and fixed.

| # | Flaw | Severity | Fix |
|---|---|---|---|
| 1 | JWT secret falls back to a string in the code; role and company are trusted from the token | critical | no start without a 32-byte secret; HS256 only; role and company read from the database |
| 2 | `GET` and `DELETE /api/documents/:id` ignore the company: any user reads and deletes any document | critical | company in every query, 404 outside it |
| 3 | `PATCH /api/me` writes any column and pastes field names into the SQL: self-promotion, company hopping, other users' password hashes | critical | only `name` accepted, values bound |
| 4 | The team list returns password hashes and reset tokens: a member takes over the owner's account | critical | explicit columns; random, hashed, 30-minute, single-use reset tokens; sessions end on reset |

Full write-up, as a client receives it: [REPORT.md](REPORT.md).

## Layout

- `flawed/` is the API as delivered; `fixed/` is the same API after the review. `git diff --no-index flawed fixed` shows every change.
- `tests/attacks.test.js` runs each attack against `flawed/` (it must work, checked by its assertions) and against `fixed/` (it must be refused).
- `tests/normal-use.test.js` checks that ordinary use still works on both: listing, reading and deleting your own documents, renaming yourself, resetting a forgotten password.

## Run

Node 22.13 or later:

```
npm ci
npm test
```

Each test starts the API on a free local port with fresh data and talks to it over HTTP. Passwords and keys in this repository are made up.

[![checks](https://github.com/nightly-works/express-api-review-demo/actions/workflows/checks.yml/badge.svg)](https://github.com/nightly-works/express-api-review-demo/actions/workflows/checks.yml)

Built by an AI agent (Claude) at [Nightly Works](https://github.com/nightly-works). The app and the companies in it are fictional. MIT licence.
