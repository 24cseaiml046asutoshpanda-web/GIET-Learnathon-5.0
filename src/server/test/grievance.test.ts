import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestEnvironment, loginHelper } from './helpers.ts';

describe('Grievance Service Tests', () => {
	let env: ReturnType<typeof createTestEnvironment>;

	beforeEach(() => {
		env = createTestEnvironment();
	});

	afterEach(() => {
		env.cleanup();
	});

	it('student can create a grievance', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');
		const res = await env.app.request('/api/grievances', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				'X-CSRF-Token': csrfToken
			},
			body: JSON.stringify({
				title: 'Broken cupboard hinge',
				category: 'Room',
				description: 'The cupboard hinge in B-204 is broken and the door will not close properly.'
			})
		});
		expect(res.status).toBe(201);
		const json = await res.json();
		expect(json.data.id).toMatch(/^GRV-\d{4}$/);
		expect(json.data.studentId).toBe('stu-1');
		expect(json.data.status).toBe('Open');
		expect(json.data.student.email).toBe('student@example.test');
	});

	it('student can retrieve a permitted grievance', async () => {
		const { cookie } = await loginHelper(env.app, 'student@example.test', 'student123');
		const res = await env.app.request('/api/grievances/GRV-0001', { headers: { Cookie: cookie } });
		expect(res.status).toBe(200);
		const json = await res.json();
		expect(json.data.id).toBe('GRV-0001');
		expect(json.data.comments.length).toBeGreaterThan(0);
		expect(json.data.attachments[0].filename).toBe('leaking-tap.jpg');
	});

	it('student cannot access another student’s grievance', async () => {
		const { cookie } = await loginHelper(env.app, 'student@example.test', 'student123');
		const res = await env.app.request('/api/grievances/GRV-0003', { headers: { Cookie: cookie } });
		expect(res.status).toBe(403);
		const json = await res.json();
		expect(json.code).toBe('unauthorized');

		const list = await env.app.request('/api/grievances', { headers: { Cookie: cookie } });
		const listJson = await list.json();
		expect(listJson.data.every((g: { studentId: string }) => g.studentId === 'stu-1')).toBe(true);
		expect(listJson.data.some((g: { id: string }) => g.id === 'GRV-0003')).toBe(false);
	});

	it('warden can access management functionality', async () => {
		const { cookie } = await loginHelper(env.app, 'warden@example.test', 'warden123');
		const list = await env.app.request('/api/grievances', { headers: { Cookie: cookie } });
		expect(list.status).toBe(200);
		const listJson = await list.json();
		expect(listJson.data.length).toBeGreaterThanOrEqual(8);

		const one = await env.app.request('/api/grievances/GRV-0003', { headers: { Cookie: cookie } });
		expect(one.status).toBe(200);
	});

	it('comments work for permitted users', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');
		const res = await env.app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				'X-CSRF-Token': csrfToken
			},
			body: JSON.stringify({ body: 'Following up on the leak this morning.' })
		});
		expect(res.status).toBe(201);
		const json = await res.json();
		expect(json.data.body).toContain('Following up');
		expect(json.data.author.id).toBe('stu-1');
		expect(json.data.author.password_hash).toBeUndefined();

		const list = await env.app.request('/api/grievances/GRV-0001/comments', { headers: { Cookie: cookie } });
		const listed = await list.json();
		expect(listed.data.some((c: { id: string }) => c.id === json.data.id)).toBe(true);
	});

	it('status changes work for wardens and are forbidden for students', async () => {
		const student = await loginHelper(env.app, 'student@example.test', 'student123');
		const denied = await env.app.request('/api/grievances/GRV-0001', {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Cookie: student.cookie,
				'X-CSRF-Token': student.csrfToken
			},
			body: JSON.stringify({ status: 'Resolved' })
		});
		expect(denied.status).toBe(403);

		const warden = await loginHelper(env.app, 'warden@example.test', 'warden123');
		const updated = await env.app.request('/api/grievances/GRV-0008', {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Cookie: warden.cookie,
				'X-CSRF-Token': warden.csrfToken
			},
			body: JSON.stringify({ status: 'In Progress' })
		});
		expect(updated.status).toBe(200);
		const json = await updated.json();
		expect(json.data.status).toBe('In Progress');
	});

	it('lets a student edit their own open grievance but not a resolved one', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');
		const edited = await env.app.request('/api/grievances/GRV-0008', {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				'X-CSRF-Token': csrfToken
			},
			body: JSON.stringify({ title: 'Mess tables still dirty before dinner' })
		});
		expect(edited.status).toBe(200);
		const editedJson = await edited.json();
		expect(editedJson.data.title).toContain('still dirty');

		const other = await loginHelper(env.app, 'priya@example.test', 'student123');
		const forbidden = await env.app.request('/api/grievances/GRV-0008', {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Cookie: other.cookie,
				'X-CSRF-Token': other.csrfToken
			},
			body: JSON.stringify({ title: 'Should not work at all here' })
		});
		expect(forbidden.status).toBe(403);

		const rohan = await loginHelper(env.app, 'rohan@example.test', 'student123');
		const resolved = await env.app.request('/api/grievances/GRV-0004', {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Cookie: rohan.cookie,
				'X-CSRF-Token': rohan.csrfToken
			},
			body: JSON.stringify({ title: 'Trying to change a resolved ticket' })
		});
		expect(resolved.status).toBe(409);
		const resolvedJson = await resolved.json();
		expect(resolvedJson.code).toBe('conflict');
	});

	it('rejects unauthenticated grievance access', async () => {
		const res = await env.app.request('/api/grievances');
		expect(res.status).toBe(401);
	});

	it('returns 404 for unknown grievance ids without leaking internals', async () => {
		const { cookie } = await loginHelper(env.app, 'warden@example.test', 'warden123');
		const res = await env.app.request('/api/grievances/GRV-9999', { headers: { Cookie: cookie } });
		expect(res.status).toBe(404);
		const json = await res.json();
		expect(json.code).toBe('not_found');
		expect(JSON.stringify(json)).not.toMatch(/sqlite|stack|ENOENT/i);
	});
});
