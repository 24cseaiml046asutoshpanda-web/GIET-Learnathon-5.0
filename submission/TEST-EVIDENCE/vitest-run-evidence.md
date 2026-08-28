# Automated Test Execution Evidence (TEST-EVIDENCE)

**Timestamp**: 2026-08-28 22:28:41 IST  
**Environment**: Windows / Node.js  
**Test Runner**: Vitest v4.1.11  

---

## 📊 Summary Output

```text
 RUN  v4.1.11 D:/All codes and Projects/college/GIET-Learnathon-5.0

 ✓ src/server/app.test.ts (19 tests) 554ms

 Test Files  1 passed (1)
      Tests  19 passed (19)
   Start at  22:28:41
   Duration  2.33s (transform 220ms, setup 0ms, import 319ms, tests 554ms, environment 0ms)
```

---

## 📜 Executed Test Cases List

1. `security headers are present in responses` — **PASSED**
2. `login works for dummy student and warden accounts` — **PASSED**
3. `rejects invalid credentials` — **PASSED**
4. `current-user works after login and fails after logout` — **PASSED**
5. `student can create a grievance` — **PASSED**
6. `student can retrieve a permitted grievance` — **PASSED**
7. `student cannot access another student's grievance` — **PASSED**
8. `warden can access management functionality` — **PASSED**
9. `comments work for permitted users` — **PASSED**
10. `status changes work for wardens and are forbidden for students` — **PASSED**
11. `attachment metadata and storage work` — **PASSED**
12. `rejects double extension and malicious binary file uploads` — **PASSED**
13. `rejects mutating requests without valid CSRF token` — **PASSED**
14. `token refresh works and revokes old refresh token` — **PASSED**
15. `input sanitization strips HTML and script tags` — **PASSED**
16. `lets a student edit their own open grievance but not a resolved one` — **PASSED**
17. `rejects unauthenticated grievance access` — **PASSED**
18. `returns 404 for unknown grievance ids without leaking internals` — **PASSED**
19. `enforces rate limiting on excessive login attempts` — **PASSED**

---

## 🛡 Security Verification Highlights

- **RBAC Ownership Enforced**: `student cannot access another student's grievance` returned HTTP 403.
- **Status Change Privilege Escalation Blocked**: `status changes work for wardens and are forbidden for students` returned HTTP 403 for student role.
- **Attachment Stealing Blocked**: `attachment metadata and storage work` returned HTTP 403 when another student attempted unauthorized file access.
- **CSRF Protection Active**: `rejects mutating requests without valid CSRF token` returned HTTP 403 with code `csrf_invalid` when `X-CSRF-Token` header was absent.
- **Token Refresh Rotation Enforced**: `token refresh works and revokes old refresh token` confirmed HTTP 401 on reuse of the old (revoked) refresh token.
- **Input Sanitization Active**: `input sanitization strips HTML and script tags` confirmed `<script>` tags stripped before storage.
- **File Security — Double Extension Blocked**: `rejects double extension and malicious binary file uploads` returned HTTP 400 for `locker.png.exe`.
- **File Security — Magic Byte Mismatch Blocked**: `rejects double extension and malicious binary file uploads` returned HTTP 400 for a text file masquerading as PNG.
- **Logout Effective Immediately**: `current-user works after login and fails after logout` returned HTTP 401 after logout even with previously valid access token still in cookie header.
- **Rate Limiting Enforced**: `enforces rate limiting on excessive login attempts` returned HTTP 429 after threshold exceeded.
- **Windows SQLite Lock Cleared**: `db.close()` in lifecycle hooks ensured 100% clean test execution without EPERM file locking errors.
