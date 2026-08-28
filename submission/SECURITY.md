# Security Architecture & Policies (SECURITY.md)

## 1. Authentication & Session Management
- **Password Protection**: User passwords are stored using secure salted hashes (`scrypt` / `pbkdf2` via `node:crypto`). Plaintext passwords are never stored or logged.
- **Session Tokens**: Cryptographically strong random 32-byte tokens generated via `randomBytes(32).toString('base64url')`.
- **Cookie Security**: Session tokens are passed via HTTP cookies (`hg_session`) with `path: '/'` and bounded TTL (`SESSION_TTL_SECONDS`).
- **Session Revocation**: Executing `/api/logout` explicitly deletes the token from SQLite `sessions` table.

## 2. Role-Based Access Control (RBAC) Matrix
The application enforces strict separation of privileges between `student` and `warden` roles.

| Resource / Endpoint | Action | Permitted Roles | Conditions / Restrictions |
|---------------------|--------|-----------------|--------------------------|
| `/api/login` | POST | Anonymous | Rate limited (15 req / 15 min) |
| `/api/logout` | POST | Authenticated | Deletes session token from DB |
| `/api/me` | GET | Authenticated | Returns public user profile |
| `/api/grievances` | GET | `student`, `warden` | Student sees own grievances; Warden sees all |
| `/api/grievances` | POST | `student` | Creates new grievance (`status = 'open'`) |
| `/api/grievances/:id` | GET | `student`, `warden` | Student must be owner (`student_id === user.id`) |
| `/api/grievances/:id` | PATCH | `student`, `warden` | Student can edit title/description/category of open grievance. Warden can only update status. |
| `/api/grievances/:id/comments` | GET / POST | `student`, `warden` | Requires grievance view permission |
| `/api/grievances/:id/attachments` | POST | `student` | Student must be owner & grievance status must not be `resolved` |
| `/api/attachments/:id` | GET | `student`, `warden` | User must own parent grievance or be a warden |

## 3. SQL Injection Prevention
- All database interactions use `better-sqlite3` parameterized queries (`db.prepare('SELECT ... WHERE id = ?').get(id)`).
- SQL statements never concatenate untrusted user input directly into query strings.

## 4. Input Validation & Data Handling
- **Length Bounds**: Title (min 5 chars), Description (min 20 chars).
- **Category Validation**: Strict allowlist check (`Maintenance`, `Water`, `Electricity`, `Internet`, `Cleanliness`, `Room`, `Other`).
- **File Upload Security**:
  - MIME type allowlist: `image/jpeg`, `image/png`, `image/gif`, `image/webp`.
  - Size limitation: Maximum 2 MB per file.
  - Path Traversal Guard: Stored files use random hexadecimal names (`randomBytes(16).toString('hex')`) and `readStoredFile` checks canonical paths using `resolve()`.

## 5. Defense-in-Depth & Rate Limiting
- **Rate Limiting**: In-memory sliding-window limiter protecting `/api/login` and general `/api/*` endpoints.
- **Security Response Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
