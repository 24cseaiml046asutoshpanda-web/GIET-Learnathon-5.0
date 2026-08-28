# Security Architecture & Policies (SECURITY.md)

## 1. Authentication & Session Management

- **Password Protection**: User passwords are stored using secure salted hashes (`scrypt` / `pbkdf2` via `node:crypto`). Plaintext passwords are never stored or logged.
- **Dual-Token Architecture**: Login issues two tokens:
  - **Access Token** (`hg_access`): Short-lived (15 min), HMAC-SHA256 signed JWT-like token (`signAccessToken`). Stateless verification via `verifyAccessToken`.
  - **Refresh Token** (`hg_refresh`): Long-lived (7 days), cryptographically random 32-byte token stored **hashed** (`sha256:<hex>`) in the `refresh_tokens` table. Raw token sent to client only.
- **Token Rotation**: `POST /api/refresh` revokes the old refresh token (marks `revoked = 1`) and issues a fresh pair, preventing refresh token reuse.
- **Cookie Security**: All auth cookies (`hg_access`, `hg_refresh`, `hg_session`) set with `httpOnly: true`, `sameSite: 'Strict'`, `secure: true` (production), bounded TTL.
- **Effective Logout**: `POST /api/logout` revokes the refresh token in the DB. `requireUser` and `readSessionUser` verify an active (non-revoked, non-expired) refresh token exists before honoring an access token, making logout immediately effective even within the access token TTL.
- **CSRF Protection**: CSRF token issued at login (`hg_csrf` cookie + JSON body `csrfToken`). All mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) require a non-empty `X-CSRF-Token` header (custom-header pattern — browsers cannot set arbitrary headers cross-origin).
- **Constant-Time Comparisons**: All security-sensitive string comparisons use `timingSafeEqual` via `constantTimeCompare()` to prevent timing side-channel attacks.

## 2. Role-Based Access Control (RBAC) Matrix

The application enforces strict separation of privileges between `student` and `warden` roles.

| Resource / Endpoint | Action | Permitted Roles | Conditions / Restrictions |
|---------------------|--------|-----------------|--------------------------|
| `/api/csrf-token` | GET | Anonymous | Issues CSRF token |
| `/api/login` | POST | Anonymous | Rate limited (15 req / 15 min) |
| `/api/refresh` | POST | Authenticated | Rate limited (30 req / 15 min). Rotates token pair. |
| `/api/logout` | POST | Authenticated | Revokes refresh token in DB |
| `/api/me` | GET | Authenticated | Returns public user profile |
| `/api/grievances` | GET | `student`, `warden` | Student sees own grievances; Warden sees all |
| `/api/grievances` | POST | `student` | Creates new grievance (`status = 'open'`). CSRF required. |
| `/api/grievances/:id` | GET | `student`, `warden` | Student must be owner (`student_id === user.id`) |
| `/api/grievances/:id` | PATCH | `student`, `warden` | Student can edit title/description/category of open grievance. Warden can only update status. CSRF required. |
| `/api/grievances/:id/comments` | GET / POST | `student`, `warden` | Requires grievance view permission. POST requires CSRF. |
| `/api/grievances/:id/attachments` | POST | `student` | Student must be owner & grievance status must not be `resolved`. CSRF required. |
| `/api/attachments/:id` | GET | `student`, `warden` | User must own parent grievance or be a warden |

## 3. SQL Injection Prevention

- All database interactions use `better-sqlite3` parameterized queries (`db.prepare('SELECT ... WHERE id = ?').get(id)`).
- SQL statements never concatenate untrusted user input directly into query strings.

## 4. Input Validation & Data Handling

- **Sanitization**: `sanitizeString()` strips null bytes (`\0`), control characters (`\x00-\x1F`), HTML/XML tags, and `javascript:` URIs before any field is stored.
- **Length Bounds**: Title (3–200 chars), Description (10–5000 chars), Comment body (1–2000 chars), Email (≤255 chars).
- **Category Allowlist**: Strict check (`Room`, `Water`, `Electricity`, `Mess`, `Other`).
- **Email Validation**: Regex format check + lowercase normalization.
- **File Upload Security**:
  - MIME type allowlist: `image/jpeg`, `image/png`, `image/gif`, `image/webp`.
  - Size limit: Maximum 2 MB per file (`MAX_ATTACHMENT_BYTES`).
  - **Magic Byte Validation**: `verifyImageMagicBytes()` inspects the binary signature (PNG: `89 50 4E 47`, JPEG: `FF D8 FF`, GIF: `47 49 46`, WebP: `RIFF…WEBP`). MIME type mismatch → HTTP 400.
  - **Double-Extension Blocking**: `originalBasename()` checks all `.`-separated extensions in the filename, rejecting files with dangerous extensions (exe, php, js, bat, sh, …) at any position.
  - **Path Traversal Guard**: Stored files use random hex names and `readStoredFile` verifies canonical paths using `resolve()` and prefix checks.

## 5. Defense-in-Depth

- **CORS Whitelist**: `hono/cors` configured with an explicit origin allowlist (`ALLOWED_CORS_ORIGINS`). Unlisted origins receive `Access-Control-Allow-Origin: null`.
- **Body Size Limit**: Non-multipart JSON payloads limited to 1 MB (`MAX_BODY_SIZE_BYTES`). Oversized payloads rejected with HTTP 413 before body is parsed.
- **Smart Rate Limiting**: `RateLimitMiddleware` uses a hybrid key strategy — authenticated requests keyed by `user.id`, partial-session requests by truncated token prefix, anonymous by `ip:path` composite — preventing single-IP bottlenecks on shared Wi-Fi/NAT networks.
  - `/api/login`: 15 requests / 15 min
  - `/api/refresh`: 30 requests / 15 min
  - `/api/*` (global): 200 requests / 15 min
- **Security Response Headers** (applied globally):
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
