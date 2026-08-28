# STRIDE Threat Model Analysis (THREAT-MODEL.md)

This threat model analyzes the Hostel Grievance Management System architecture using the STRIDE methodology.

---

## 1. System Architecture & Trust Boundaries

```
[ Unauthenticated Client ] ──( HTTP )──────────────────────────────────────────────────────────┐
                                                                                                 │
[ Authenticated Student  ] ──( HTTPS / hg_access + hg_refresh + X-CSRF-Token cookies )─────────┤
                                                                                                 ▼
[ Authenticated Warden   ] ──( HTTPS / hg_access + hg_refresh + X-CSRF-Token cookies )──[ Security Header MW ]
                                                                                                 │
                                                                                         [ CORS Whitelist MW ]
                                                                                                 │
                                                                                         [ Body Limit MW (1MB) ]
                                                                                                 │
                                                                                         [ CSRF Protection MW ]
                                                                                                 │
                                                                                         [ Rate Limiter MW ]
                                                                                                 │
                                                                                         [ Auth MW & RBAC ]
                                                                                                 │
                                                                                   [ Controllers & Services ]
                                                                                                 │
                                                                              [ Input Sanitizer & Validators ]
                                                                                                 │
                                                                             [ SQLite DB & Filesystem Storage ]
```

### Trust Boundaries

1. **Client to Server Boundary**: Public internet / browser requests hitting `/api/*`. CORS, rate limiting, body size limiting, and CSRF operate here.
2. **Middleware Boundary**: Authentication verification, role enforcement, CSRF validation. Only requests with valid, non-revoked session tokens and correct CSRF headers may proceed.
3. **Application to Data Layer Boundary**: Parameterized SQLite query execution and local disk filesystem. Magic byte validation, path traversal checks, and filename sanitization apply here.

---

## 2. STRIDE Threats & Mitigations

### 1. Spoofing Identity

- **Threat**: Attacker impersonates a student or warden to perform actions on their behalf.
- **Risk**: High.
- **Mitigations**:
  - **Access tokens**: Short-lived (15 min) HMAC-SHA256 signed tokens. Forgery requires knowledge of `ACCESS_TOKEN_SECRET`.
  - **Refresh tokens**: Cryptographically random 32-byte tokens stored as SHA-256 hashes in the DB. A DB read leak cannot be used directly to forge a session.
  - **Constant-time comparisons**: All token/hash comparisons use `timingSafeEqual` preventing timing oracle attacks.
  - **Cookie flags**: `HttpOnly`, `SameSite=Strict`, `Secure` (production) prevent JavaScript access and cross-site transmission.

### 2. Tampering with Data

- **Threat**: Attacker modifies grievance titles, descriptions, or updates status of grievances without permission. Attacker injects malicious HTML or SQL into stored fields.
- **Risk**: High.
- **Mitigations**:
  - `GrievanceService.updateGrievance` enforces ownership for students and restricts status changes exclusively to `warden` role.
  - Resolved grievances cannot be edited by students.
  - **Input sanitization**: `sanitizeString()` strips HTML tags, null bytes, control characters, and `javascript:` URIs from all free-text input.
  - **SQL parameterization**: All queries use `?` positional bindings — untrusted input is never interpolated into SQL strings.
  - **CSRF protection**: Mutating endpoints require `X-CSRF-Token` header, blocking cross-site request forgery.

### 3. Repudiation

- **Threat**: User claims they did not submit a grievance, comment, or attachment.
- **Risk**: Medium.
- **Mitigation**: All grievances, comments, and attachments record immutable author/student references (`student_id`, `author_id`) and ISO timestamps (`created_at`) upon database insertion. `refresh_tokens` table records `created_at` per issued token.

### 4. Information Disclosure

- **Threat**: Unauthorized student views private grievances, downloads file attachments of other students, or obtains session tokens from a database read.
- **Risk**: High.
- **Mitigations**:
  - `listGrievances` filters records by `student_id = user.id` for students.
  - `assertCanViewGrievance` verifies student ownership before returning single grievance or comment details.
  - `AttachmentService.getAttachment` checks parent grievance permissions before streaming files from disk.
  - **Hashed refresh tokens**: Stored as `sha256:<hex>`. A DB dump does not expose usable session credentials.
  - **Path traversal guard**: `readStoredFile` uses `resolve()` and canonical prefix checks. Stored filenames are random hex strings, never user-supplied.
  - **Error sanitization**: `handleError` never leaks SQLite internals, stack traces, or file system paths in API responses.

### 5. Denial of Service (DoS)

- **Threat**: Attacker floods login or upload endpoints with automated requests or uploads huge files to exhaust server memory/disk.
- **Risk**: Medium.
- **Mitigations**:
  - **Smart rate limiting**: `RateLimitMiddleware` with hybrid key resolution (user ID → token prefix → IP+path) prevents shared-IP rate limit bypass. Limits: login 15/15 min, refresh 30/15 min, global 200/15 min.
  - **Body size limit**: Non-multipart request bodies limited to 1 MB before parsing.
  - **Attachment size limit**: File uploads capped at 2 MB with strict MIME type allowlisting.
  - **Magic byte validation**: Rejects non-image binary content before disk write.

### 6. Elevation of Privilege

- **Threat**: Student user attempts to perform warden administrative tasks (e.g. status changes, viewing all grievances). Attacker reuses a revoked or expired token after logout.
- **Risk**: High.
- **Mitigations**:
  - Role-based access control enforced via `AuthMiddleware.requireRole('warden')` and role checks inside service methods.
  - **Immediate logout invalidation**: `requireUser` cross-checks that the user has at least one active (non-revoked, non-expired) refresh token in the DB before honoring a signed access token, making logout effective immediately.
  - **Token rotation**: `/api/refresh` revokes the old refresh token before issuing a new pair, preventing token reuse after rotation.
  - **CSRF prevention**: Browser-originated cross-site privilege escalation attacks blocked by custom-header CSRF pattern.
