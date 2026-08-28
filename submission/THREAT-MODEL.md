# STRIDE Threat Model Analysis (THREAT-MODEL.md)

This threat model analyzes the Hostel Grievance Management System architecture using the STRIDE methodology.

---

## 1. System Architecture & Trust Boundaries

```
[ Unauthenticated Client ] ──( HTTP / Cookie )──> [ RateLimiter & Security Headers ]
                                                               │
[ Authenticated Student  ] ──( HTTP / Session Token )──────────┼──> [ AuthMiddleware & RBAC ]
                                                               │         │
[ Authenticated Warden   ] ──( HTTP / Session Token )──────────┘         ▼
                                                             [ Controllers & Services ]
                                                                       │
                                                                       ▼
                                                             [ SQLite DB & Storage ]
```

### Trust Boundaries
1. **Client to Server Boundary**: Public internet / browser requests hitting `/api/*`.
2. **Middleware Boundary**: Authentication verification, rate limiting, and RBAC policy enforcement.
3. **Application to Data Layer Boundary**: Parameterized SQLite query execution and local disk storage filesystem operations.

---

## 2. STRIDE Threats & Mitigations

### 1. Spoofing Identity
- **Threat**: Attacker impersonates a student or warden to perform actions on their behalf.
- **Risk**: High.
- **Mitigation**: Cryptographically secure 32-byte session tokens stored in HTTP cookies (`hg_session`). Session validation checks token existence and TTL expiration on every protected request via `AuthMiddleware.authenticate()`.

### 2. Tampering with Data
- **Threat**: Attacker modifies grievance titles, descriptions, or updates status of grievances without permission.
- **Risk**: High.
- **Mitigation**:
  - `GrievanceService.updateGrievance` enforces ownership for students and restricts status changes exclusively to `warden` role.
  - Resolved grievances cannot be edited by students.
  - SQL parameterization (`?` positional bindings) prevents SQL injection data tampering.

### 3. Repudiation
- **Threat**: User claims they did not submit a grievance or comment.
- **Risk**: Medium.
- **Mitigation**: All grievances, comments, and attachments record immutable author/student references (`student_id`, `author_id`) and ISO timestamps (`created_at`) upon database insertion.

### 4. Information Disclosure
- **Threat**: Unauthorized student views private grievances or downloads file attachments of other students.
- **Risk**: High.
- **Mitigation**:
  - `listGrievances` filters records by `student_id = user.id` for students.
  - `assertCanViewGrievance` verifies student ownership before returning single grievance or comment details.
  - `AttachmentService.getAttachment` checks parent grievance permissions before streaming files from disk.

### 5. Denial of Service (DoS)
- **Threat**: Attacker floods login or upload endpoints with automated requests or uploads huge files to exhaust server resources.
- **Risk**: Medium.
- **Mitigation**:
  - `RateLimitMiddleware` limits sensitive endpoints (e.g., 15 requests per 15 min for `/api/login`, 200 requests per 15 min for `/api/*`).
  - Attachment upload size is capped at 2 MB with strict MIME type allowlisting.

### 6. Elevation of Privilege
- **Threat**: Student user attempts to perform warden administrative tasks (e.g. status changes, viewing all grievances).
- **Risk**: High.
- **Mitigation**: Role-based access control enforced via `AuthMiddleware.requireRole('warden')` and role checks inside service methods.
