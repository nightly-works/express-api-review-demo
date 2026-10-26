# Security review: Teamdocs API (sample report)

*Teamdocs is a fictional app built for this demo: a document space for small companies, with an Express API and a React front end written with AI coding tools.*

**Scope**: the Express API (`app.js`, `auth.js`, `db.js`). The React front end, hosting and dependencies are out of scope here.
**Method**: source read, then each suspected flaw reproduced as an automated attack against a copy of the API; fixes applied to the copy and the same attacks re-run. No production system was touched.
**Result**: 4 findings, all critical. All fixed in the copy, each with a test that fails if the flaw comes back.

## Summary for the owner

If `JWT_SECRET` is not set on the server, anyone who has seen the code can sign in as any user of any company. Whatever the setting, any signed-in member can read or delete other companies' documents, make himself owner, and take over his own owner's account. Set a long random `JWT_SECRET` on the server first, then deploy the fixed API: every user signs in again once.

## Findings

### 1. Anyone can sign their own login tokens (critical)

**What**: `auth.js` signs tokens with `process.env.JWT_SECRET || 'super-secret-key-change-me'`. If the variable is missing on the server, the fallback string from the code is the key. The token also carries the user's role and company, and the API believes them.
**Impact**: whoever has read the code (a former freelancer, a public repository, a leaked zip) can sign a token for any user of any company, with any role, valid for 30 days.
**Reproduced**: a token signed with the fallback string lists another company's documents (test 1, flawed).
**Fix**: the API refuses to start without a secret of at least 32 bytes; the algorithm is pinned to HS256 (defence in depth); tokens carry only the user id and a version number, and the role and company are read from the database on each request. Changing the secret signs everyone out once, which is what you want if it may have leaked.
**Verified**: tokens signed with the old string get 401; the API does not start with no secret or a short one; a validly signed token claiming another company and the owner role still gets Bob's own role and documents (test 1, fixed).

### 2. Other companies' documents by id (critical)

**What**: `GET` and `DELETE /api/documents/:id` look the document up by id only. The list endpoint is filtered by company; these two are not.
**Impact**: a signed-in user of any company can read every document on the platform by counting ids, and delete them.
**Reproduced**: Bob (Acme) reads and deletes Globex's acquisition memo (test 2, flawed).
**Fix**: both queries also require the caller's company; a document of another company answers 404, like a missing one.
**Verified**: Bob gets 404 for Globex's memo, which stays in the database; his own documents still work (test 2, fixed; normal use).

### 3. The profile update writes any column, and field names go into the SQL (critical)

**What**: `PATCH /api/me` turns every key of the request body into `column = ?`. Nothing limits which columns, and the key itself is pasted into the SQL text.
**Impact**: a member sets his own `role` to `owner` or his `workspace_id` to another company's and reads its data. A crafted key rewrites other users' rows: the test copies Bob's password hash onto Alice's account, then signs in as Alice with Bob's password.
**Reproduced**: all three in test 3, flawed.
**Fix**: only `name` is accepted, as a string of 1 to 100 characters; anything else is refused with 400. No request text reaches the SQL other than as a bound value. Role and company changes belong to the owner's team screen, and an email change needs its own confirmation flow.
**Verified**: role, workspace, mixed and injected bodies get 400; Bob stays a member of Acme; Bob's password does not open Alice's account (test 3, fixed).

### 4. Account takeover through the team list (critical)

**What**: `GET /api/team` returns `SELECT *` from users: password hashes and the password reset token. Reset tokens come from `Math.random()`, are stored in clear, never expire and are not cleared after use.
**Impact**: a member asks for a reset of the owner's password, reads the token in the team list, and sets a new password: he now owns the account and the company's data. The hashes can also be attacked offline.
**Reproduced**: Bob takes over Alice's account (test 4, flawed).
**Fix**: the team list returns id, email, name, role and company only. Reset tokens are 32 random bytes; only their SHA-256 hash is stored, they expire after 30 minutes and work once, even when two requests race with the same token, and a reset signs out every session opened before it.
**Verified**: no secret in the team list; the stored hash is not accepted as a token; an expired token is refused (test 4, fixed); a used token is refused and old sessions get 401 (normal use).

## Also changed

- Login compares against a dummy hash when the email is unknown, so response time does not reveal which emails have accounts; bcrypt runs asynchronously, so a login no longer blocks other requests.
- New passwords must be 10 to 72 bytes (bcrypt ignores anything past 72 bytes).
- Malformed JSON and unexpected errors answer in JSON without a stack trace; the `X-Powered-By` header is off.

## Checked next in a full review

Rate limits on login and password reset, CORS origins and cookie settings, the front end's token storage, file uploads, dependency advisories (`npm audit`), logging of failed logins, and how the server gets its environment variables.
