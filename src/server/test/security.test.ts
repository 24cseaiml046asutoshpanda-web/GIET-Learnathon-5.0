import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestEnvironment, loginHelper } from './helpers.ts';

describe('Security & Middleware Tests', () => {
	let env: ReturnType<typeof createTestEnvironment>;

	beforeEach(() => {
		env = createTestEnvironment();
	});

	afterEach(() => {
		env.cleanup();
	});

	it('security headers are present in responses', async () => {
		const res = await env.app.request('/api/health');
		expect(res.status).toBe(200);
		expect(res.headers.get('x-content-type-options')).toBe('nosniff');
		expect(res.headers.get('x-frame-options')).toBe('DENY');
		expect(res.headers.get('x-xss-protection')).toBe('1; mode=block');
	});

	it('rejects mutating requests without valid CSRF token', async () => {
		const { cookie } = await loginHelper(env.app, 'student@example.test', 'student123');
		const res = await env.app.request('/api/grievances', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({
				title: 'CSRF attack test',
				category: 'Room',
				description: 'This should fail because no CSRF token header is provided.'
			})
		});
		expect(res.status).toBe(403);
		const json = await res.json();
		expect(json.code).toBe('csrf_invalid');
	});

	it('input sanitization strips HTML and script tags', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');
		const res = await env.app.request('/api/grievances', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				'X-CSRF-Token': csrfToken
			},
			body: JSON.stringify({
				title: '<script>alert(1)</script>Leaking tap in room',
				category: 'Water',
				description: '<iframe src="evil.com"></iframe>The tap in room 204 has been leaking continuously.'
			})
		});
		expect(res.status).toBe(201);
		const json = await res.json();
		expect(json.data.title).toBe('alert(1)Leaking tap in room');
		expect(json.data.description).not.toContain('<iframe');
	});
});
