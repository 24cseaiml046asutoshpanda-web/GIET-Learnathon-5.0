import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER_DIR = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(SERVER_DIR, '../..');

export const DEFAULT_DB_PATH =
	process.env.HOSTEL_DB_PATH ?? path.join(REPO_ROOT, 'data', 'hostel.db');

export const DEFAULT_UPLOADS_DIR =
	process.env.HOSTEL_UPLOADS_DIR ?? path.join(REPO_ROOT, 'uploads');

export const API_PORT = Number(process.env.HOSTEL_API_PORT ?? 3001);

export const SESSION_COOKIE = 'hg_session';
export const ACCESS_COOKIE_NAME = 'hg_access';
export const REFRESH_COOKIE_NAME = 'hg_refresh';
export const CSRF_COOKIE_NAME = 'hg_csrf';

export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
export const ACCESS_TOKEN_TTL_SECONDS = 60 * 15; // 15 minutes
export const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export const ACCESS_TOKEN_SECRET =
	process.env.ACCESS_TOKEN_SECRET ?? 'super-secret-access-token-key-change-in-prod-1234567890';

export const ALLOWED_CORS_ORIGINS = process.env.ALLOWED_ORIGINS
	? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
	: ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173', 'http://localhost:4173'];

export const MAX_BODY_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB limit for standard request body
export const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024; // 2 MB limit for file attachment

export const ALLOWED_ATTACHMENT_TYPES = new Set([
	'image/jpeg',
	'image/png',
	'image/gif',
	'image/webp'
]);

