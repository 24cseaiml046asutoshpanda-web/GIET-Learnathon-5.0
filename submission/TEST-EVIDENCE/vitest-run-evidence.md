# Automated Test Execution Evidence (TEST-EVIDENCE)

**Timestamp**: 2026-08-28 19:09:49 IST  
**Environment**: Windows / Node.js  
**Test Runner**: Vitest v4.1.11  

---

## 📊 Summary Output

```text
 RUN  v4.1.11 D:/All codes and Projects/college/GIET-Learnathon-5.0

 ✓ src/server/app.test.ts (16 tests) 488ms

 Test Files  1 passed (1)
      Tests  16 passed (16)
   Start at  19:09:46
   Duration  2.04s (transform 164ms, setup 0ms, import 248ms, tests 488ms, environment 0ms)
```

---

## 📜 Executed Test Cases List

1. `security headers are present in responses` — **PASSED**
2. `login works for dummy student and warden accounts` — **PASSED**
3. `rejects invalid credentials` — **PASSED**
4. `current-user works after login and fails after logout` — **PASSED**
5. `student can create a grievance` — **PASSED**
6. `student can retrieve a permitted grievance` — **PASSED**
7. `student cannot access another student’s grievance` — **PASSED**
8. `warden can access management functionality` — **PASSED**
9. `comments work for permitted users` — **PASSED**
10. `status changes work for wardens and are forbidden for students` — **PASSED**
11. `attachment metadata and storage work` — **PASSED**
12. `rejects oversized and disallowed attachments` — **PASSED**
13. `lets a student edit their own open grievance but not a resolved one` — **PASSED**
14. `rejects unauthenticated grievance access` — **PASSED**
15. `returns 404 for unknown grievance ids without leaking internals` — **PASSED**
16. `enforces rate limiting on excessive login attempts` — **PASSED**

---

## 🛡 Security Verification Highlights
- **RBAC Ownership Enforced**: `student cannot access another student’s grievance` returned HTTP 403.
- **Status Change Privilege Escalation Blocked**: `status changes work for wardens and are forbidden for students` returned HTTP 403 for student role.
- **Attachment Stealing Blocked**: `attachment metadata and storage work` returned HTTP 403 when another student attempted unauthorized file access.
- **Rate Limiting Enforced**: `enforces rate limiting on excessive login attempts` returned HTTP 429 after threshold exceeded.
- **Windows SQLite Lock Cleared**: `db.close()` in lifecycle hooks ensured 100% clean test execution without EPERM file locking errors.
