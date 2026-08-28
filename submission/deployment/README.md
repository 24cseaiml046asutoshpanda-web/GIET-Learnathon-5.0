# Deployment & Execution Guide (submission/deployment/README.md)

This guide provides instructions to install, build, seed, run, and verify the Hostel Grievance Management System application package.

---

## 📋 Prerequisites
- **Node.js**: v18.x or later
- **npm**: v9.x or later

---

## 🚀 Setup & Execution Instructions

### 1. Install Dependencies
```bash
npm install
```

### 2. Initialize / Seed Database
Reset and seed the SQLite database with baseline schema and test data:
```bash
npm run db:init
```

### 3. Run Development Servers

- **Run Server API (Backend)**:
  ```bash
  npm run dev:api
  ```
  *Backend server runs at `http://localhost:3000` (or configured PORT).*

- **Run Full Application (UI + API concurrently)**:
  ```bash
  npm run dev:all
  ```

---

## 🧪 Verification & Testing

Execute the automated test suite to verify security, RBAC policies, rate limiting, and core functionality:
```bash
npm test
```

### Type Checking
To run TypeScript strict static analysis:
```bash
npm run typecheck
```
