import type { Database } from 'better-sqlite3';
import { findAttachmentRow, requireGrievance, assertCanViewGrievance } from '../db/queries.ts';
import { readStoredFile } from '../storage/attachments.ts';
import { HttpError } from '../http/errors.ts';
import type { SessionUser, AttachmentRow } from '../types/index.ts';

/**
 * AttachmentService Class
 * Manages static attachment retrieving logic and permission checks.
 */
export class AttachmentService {
	/**
	 * Retrieves stored file buffer and metadata after checking RBAC access on the parent grievance.
	 * 
	 * @param db SQLite Database instance
	 * @param uploadsDir Upload directory path
	 * @param attachmentId Attachment ID
	 * @param user Authenticated session user
	 * @returns Object containing file buffer and attachment metadata row
	 */
	static getAttachment(
		db: Database,
		uploadsDir: string,
		attachmentId: string,
		user: SessionUser
	): { bytes: Buffer; row: AttachmentRow } {
		const row = findAttachmentRow(db, attachmentId);
		if (!row) {
			throw new HttpError(404, 'not_found', 'Attachment was not found.');
		}

		// Look up parent grievance and enforce RBAC permission
		const grievance = requireGrievance(db, row.grievance_id);
		assertCanViewGrievance(user, grievance);

		const bytes = readStoredFile(uploadsDir, row.stored_filename);
		return { bytes, row };
	}
}
