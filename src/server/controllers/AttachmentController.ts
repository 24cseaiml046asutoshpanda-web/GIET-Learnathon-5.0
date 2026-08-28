import type { Context } from 'hono';
import type { AppEnv } from '../env.ts';
import { AttachmentService } from '../services/AttachmentService.ts';

/**
 * AttachmentController Class
 * Handles HTTP requests for file downloads.
 */
export class AttachmentController {
	/**
	 * Handles GET /api/attachments/:id
	 * Streams stored attachment file content after enforcing RBAC ownership checks.
	 * 
	 * @param c Hono Context
	 */
	static getAttachment(c: Context<AppEnv>) {
		const db = c.get('db');
		const uploadsDir = c.get('uploadsDir');
		const user = c.get('user')!;
		const attachmentId = c.req.param('id') ?? '';

		const { bytes, row } = AttachmentService.getAttachment(
			db,
			uploadsDir,
			attachmentId,
			user
		);

		c.header('Content-Type', row.mime_type);
		c.header('Content-Length', String(bytes.length));
		c.header(
			'Content-Disposition',
			`inline; filename="${row.original_filename.replaceAll('"', '')}"`
		);
		return c.body(new Uint8Array(bytes));
	}
}
