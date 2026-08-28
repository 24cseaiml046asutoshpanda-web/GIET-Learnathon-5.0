import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Database } from 'better-sqlite3';
import { createApp } from '../app.ts';
import { openDatabase } from '../db/connection.ts';
import { seedDatabase } from '../db/seed.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimiter.ts';

export const PNG_BUFFER = Buffer.from(
	'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
	'base64'
);

export function cookieHeader(res: Response): string {
	const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
	const list = anyHeaders.getSetCookie?.() ?? [];
	if (list.length > 0) {
		return list.map((v) => v.split(';')[0]).join('; ');
	}
	const raw = res.headers.get('set-cookie');
	return raw ? raw.split(';')[0] : '';
}

export function extractCookieValue(cookieStr: string, cookieName: string): string | undefined {
	const parts = cookieStr.split('; ');
	for (const part of parts) {
		if (part.startsWith(`${cookieName}=`)) {
			return part.slice(cookieName.length + 1);
		}
	}
	return undefined;
}

export async function loginHelper(app: ReturnType<typeof createApp>, email: string, password: string) {
	const res = await app.request('/api/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	const json = (await res.json()) as any;
	const cookie = cookieHeader(res);
	const csrfToken = json.csrfToken || extractCookieValue(cookie, 'hg_csrf') || '';
	return { res, json, cookie, csrfToken };
}

export function createTestEnvironment() {
	RateLimitMiddleware.reset();
	const dir = mkdtempSync(join(tmpdir(), 'hg-api-test-'));
	const db = openDatabase(join(dir, 'hostel.db'));
	const uploadDir = join(dir, 'uploads');
	seedDatabase(db, uploadDir);
	const app = createApp({ db, uploadsDir: uploadDir });

	const cleanup = () => {
		if (db) {
			db.close();
		}
		rmSync(dir, { recursive: true, force: true });
	};

	return { app, db, dir, uploadDir, cleanup };
}
