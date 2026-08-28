import type { Context } from 'hono';
import type { AppEnv } from '../env.ts';
import { GrievanceService } from '../services/GrievanceService.ts';
import { HttpError } from '../http/errors.ts';

function readString(value: unknown): string | undefined {
	return typeof value === 'string' ? value : undefined;
}

/**
 * GrievanceController Class
 * Provides static handler methods for grievance HTTP routes.
 */
export class GrievanceController {
	/**
	 * Handles GET /api/grievances
	 * Retrieves list of grievances accessible by the authenticated user.
	 * 
	 * @param c Hono Context
	 */
	static list(c: Context<AppEnv>) {
		const db = c.get('db');
		const user = c.get('user')!;
		const data = GrievanceService.listGrievances(db, user);
		return c.json({ data });
	}

	/**
	 * Handles GET /api/grievances/:id
	 * Retrieves detailed grievance record by ID.
	 * 
	 * @param c Hono Context
	 */
	static getById(c: Context<AppEnv>) {
		const db = c.get('db');
		const user = c.get('user')!;
		const id = c.req.param('id') ?? '';
		const data = GrievanceService.getGrievanceById(db, id, user);
		return c.json({ data });
	}

	/**
	 * Handles POST /api/grievances
	 * Creates a new grievance submission. Supports JSON or multipart/form-data with file attachment.
	 * 
	 * @param c Hono Context
	 */
	static async create(c: Context<AppEnv>) {
		const db = c.get('db');
		const uploadsDir = c.get('uploadsDir');
		const user = c.get('user')!;

		const contentType = c.req.header('content-type') ?? '';
		let title = '';
		let category = '';
		let description = '';
		let upload: File | undefined;

		if (contentType.includes('multipart/form-data')) {
			const body = await c.req.parseBody();
			title = readString(body.title) ?? '';
			category = readString(body.category) ?? '';
			description = readString(body.description) ?? '';
			if (body.file instanceof File) upload = body.file;
			else if (body.attachment instanceof File) upload = body.attachment;
		} else {
			let json: unknown;
			try {
				json = await c.req.json();
			} catch {
				throw new HttpError(400, 'bad_request', 'Request body must be JSON or multipart form data.');
			}
			if (!json || typeof json !== 'object') {
				throw new HttpError(400, 'bad_request', 'Request body must be JSON or multipart form data.');
			}
			title = readString('title' in json ? json.title : undefined) ?? '';
			category = readString('category' in json ? json.category : undefined) ?? '';
			description = readString('description' in json ? json.description : undefined) ?? '';
		}

		const data = await GrievanceService.createGrievance(
			db,
			uploadsDir,
			user,
			{ title, category, description },
			upload
		);
		return c.json({ data }, 201);
	}

	/**
	 * Handles PATCH /api/grievances/:id
	 * Updates a grievance according to RBAC restrictions.
	 * 
	 * @param c Hono Context
	 */
	static async update(c: Context<AppEnv>) {
		const db = c.get('db');
		const user = c.get('user')!;
		const id = c.req.param('id') ?? '';

		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
		}
		if (!body || typeof body !== 'object') {
			throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
		}

		const data = GrievanceService.updateGrievance(
			db,
			id,
			user,
			body as Record<string, unknown>
		);
		return c.json({ data });
	}

	/**
	 * Handles GET /api/grievances/:id/comments
	 * Retrieves comments for a specific grievance.
	 * 
	 * @param c Hono Context
	 */
	static listComments(c: Context<AppEnv>) {
		const db = c.get('db');
		const user = c.get('user')!;
		const grievanceId = c.req.param('id') ?? '';
		const data = GrievanceService.listComments(db, grievanceId, user);
		return c.json({ data });
	}

	/**
	 * Handles POST /api/grievances/:id/comments
	 * Adds a comment to a specific grievance.
	 * 
	 * @param c Hono Context
	 */
	static async addComment(c: Context<AppEnv>) {
		const db = c.get('db');
		const user = c.get('user')!;
		const grievanceId = c.req.param('id') ?? '';

		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			throw new HttpError(400, 'bad_request', 'JSON body is required.');
		}

		const text =
			body && typeof body === 'object' && 'body' in body && typeof body.body === 'string'
				? body.body
				: '';

		const data = GrievanceService.addComment(db, grievanceId, user, text);
		return c.json({ data }, 201);
	}

	/**
	 * Handles POST /api/grievances/:id/attachments
	 * Adds an attachment file to an existing grievance.
	 * 
	 * @param c Hono Context
	 */
	static async addAttachment(c: Context<AppEnv>) {
		const db = c.get('db');
		const uploadsDir = c.get('uploadsDir');
		const user = c.get('user')!;
		const grievanceId = c.req.param('id') ?? '';

		const body = await c.req.parseBody();
		const upload =
			body.file instanceof File
				? body.file
				: body.attachment instanceof File
				? body.attachment
				: undefined;

		if (!upload) {
			throw new HttpError(400, 'bad_request', 'A file field named file is required.');
		}

		const data = await GrievanceService.addAttachment(
			db,
			uploadsDir,
			grievanceId,
			user,
			upload
		);
		return c.json({ data }, 201);
	}
}
