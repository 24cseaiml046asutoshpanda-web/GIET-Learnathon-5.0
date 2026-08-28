import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestEnvironment, loginHelper } from './helpers.ts';

describe('Auth & Session Service Tests', () => {
	let env: ReturnType<typeof createTestEnvironment>;

	beforeEach(() => {
		env = createTestEnvironment();
	});

	afterEach(() => {
		env.cleanup();
	});

	it('login works for dummy student and warden accounts', async () => {
		const student = await loginHelper(env.app, 'student@example.test', 'student123');
		expect(student.res.status).toBe(200);
		expect(student.json.user.email).toBe('student@example.test');
		expect(student.json.user.role).toBe('student');
		expect(student.json.user.password).toBeUndefined();
		expect(student.json.user.password_hash).toBeUndefined();
		expect(student.cookie).toContain('hg_refresh=');
		expect(student.csrfToken.length).toBeGreaterThan(0);

		const warden = await loginHelper(env.app, 'warden@example.test', 'warden123');
		expect(warden.res.status).toBe(200);
		expect(warden.json.user.role).toBe('warden');
	});

	it('rejects invalid credentials', async () => {
		const bad = await loginHelper(env.app, 'student@example.test', 'wrong');
		expect(bad.res.status).toBe(401);
		expect(bad.json.code).toBe('unauthenticated');
	});

	it('current-user works after login and fails after logout', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');
		const me = await env.app.request('/api/me', { headers: { Cookie: cookie } });
		expect(me.status).toBe(200);
		const meJson = await me.json();
		expect(meJson.user.id).toBe('stu-1');
		expect(meJson.user.password_hash).toBeUndefined();

		const unauth = await env.app.request('/api/me');
		expect(unauth.status).toBe(401);

		await env.app.request('/api/logout', {
			method: 'POST',
			headers: { Cookie: cookie, 'X-CSRF-Token': csrfToken }
		});
		const after = await env.app.request('/api/me', { headers: { Cookie: cookie } });
		expect(after.status).toBe(401);
	});

	it('token refresh works and revokes old refresh token', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');

		const refreshRes = await env.app.request('/api/refresh', {
			method: 'POST',
			headers: { Cookie: cookie, 'X-CSRF-Token': csrfToken }
		});
		expect(refreshRes.status).toBe(200);
		const newCookie = refreshRes.headers.get('set-cookie') || '';
		expect(newCookie).toContain('hg_refresh=');

		// Re-using old revoked refresh token fails
		const reusedRes = await env.app.request('/api/refresh', {
			method: 'POST',
			headers: { Cookie: cookie, 'X-CSRF-Token': csrfToken }
		});
		expect(reusedRes.status).toBe(401);
	});

	it('enforces rate limiting on excessive login attempts', async () => {
		for (let i = 0; i < 15; i++) {
			await loginHelper(env.app, 'student@example.test', 'wrongpassword');
		}
		const rateLimited = await loginHelper(env.app, 'student@example.test', 'wrongpassword');
		expect(rateLimited.res.status).toBe(429);
		expect(rateLimited.json.code).toBe('rate_limit_exceeded');
	});
});
