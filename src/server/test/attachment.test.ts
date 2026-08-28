import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestEnvironment, loginHelper, PNG_BUFFER } from './helpers.ts';

describe('Attachment Service Tests', () => {
	let env: ReturnType<typeof createTestEnvironment>;

	beforeEach(() => {
		env = createTestEnvironment();
	});

	afterEach(() => {
		env.cleanup();
	});

	it('attachment metadata and storage work', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');
		const created = await env.app.request('/api/grievances', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				'X-CSRF-Token': csrfToken
			},
			body: JSON.stringify({
				title: 'Need a photo on file',
				category: 'Other',
				description: 'Filing this so I can attach a photo of the damaged locker door.'
			})
		});
		const grievance = await created.json();
		const id = grievance.data.id as string;

		const form = new FormData();
		form.append('file', new File([PNG_BUFFER], 'locker.png', { type: 'image/png' }));
		const uploaded = await env.app.request(`/api/grievances/${id}/attachments`, {
			method: 'POST',
			headers: { Cookie: cookie, 'X-CSRF-Token': csrfToken },
			body: form
		});
		expect(uploaded.status).toBe(201);
		const meta = await uploaded.json();
		expect(meta.data.filename).toBe('locker.png');
		expect(meta.data.contentType).toBe('image/png');
		expect(meta.data.sizeBytes).toBe(PNG_BUFFER.length);

		const fileRes = await env.app.request(`/api/attachments/${meta.data.id}`, { headers: { Cookie: cookie } });
		expect(fileRes.status).toBe(200);
		expect(fileRes.headers.get('content-type')).toBe('image/png');
		const bytes = Buffer.from(await fileRes.arrayBuffer());
		expect(bytes.equals(PNG_BUFFER)).toBe(true);

		const other = await loginHelper(env.app, 'priya@example.test', 'student123');
		const stolen = await env.app.request(`/api/attachments/${meta.data.id}`, {
			headers: { Cookie: other.cookie }
		});
		expect(stolen.status).toBe(403);
	});

	it('rejects double extension and malicious binary file uploads', async () => {
		const { cookie, csrfToken } = await loginHelper(env.app, 'student@example.test', 'student123');

		// Double extension test (.png.exe)
		const doubleExtForm = new FormData();
		doubleExtForm.append('file', new File([PNG_BUFFER], 'locker.png.exe', { type: 'image/png' }));
		const doubleExtRes = await env.app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie, 'X-CSRF-Token': csrfToken },
			body: doubleExtForm
		});
		expect(doubleExtRes.status).toBe(400);

		// Fake binary contents test (txt pretending to be png)
		const fakeImgForm = new FormData();
		fakeImgForm.append('file', new File(['not-an-image-binary'], 'hacked.png', { type: 'image/png' }));
		const fakeImgRes = await env.app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie, 'X-CSRF-Token': csrfToken },
			body: fakeImgForm
		});
		expect(fakeImgRes.status).toBe(400);
	});
});
