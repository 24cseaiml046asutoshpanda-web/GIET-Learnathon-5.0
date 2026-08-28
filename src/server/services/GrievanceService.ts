import type { Database } from 'better-sqlite3';
import {
	assembleGrievance,
	findUserById,
	listAllGrievanceRows,
	listCommentRows,
	listGrievanceRowsForStudent,
	nextAttachmentId,
	nextCommentId,
	nextGrievanceId,
	requireGrievance,
	touchGrievance,
	assertCanViewGrievance
} from '../db/queries.ts';
import { toPublicAttachment, toPublicComment, toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import { parseCategory, statusToDb } from '../http/status.ts';
import {
	bufferFromUpload,
	newStoredName,
	originalBasename,
	writeStoredFile
} from '../storage/attachments.ts';
import type {
	CommentRow,
	AttachmentRow,
	GrievanceStatusDb,
	PublicComment,
	PublicGrievance,
	PublicAttachment,
	SessionUser
} from '../types/index.ts';

function nowIso(): string {
	return new Date().toISOString();
}

/**
 * GrievanceService Class
 * Encapsulates static business logic and SQL transactions for grievances, comments, and grievance attachments.
 */
export class GrievanceService {
	/**
	 * Lists grievances accessible to the current user.
	 * Wardens see all grievances; Students see only their submitted grievances.
	 * 
	 * @param db SQLite Database instance
	 * @param user Authenticated session user
	 * @returns List of public grievance DTOs
	 */
	static listGrievances(db: Database, user: SessionUser): PublicGrievance[] {
		const rows =
			user.role === 'warden'
				? listAllGrievanceRows(db)
				: listGrievanceRowsForStudent(db, user.id);
		return rows.map((row) => assembleGrievance(db, row));
	}

	/**
	 * Retrieves a single grievance by ID after enforcing RBAC view permission.
	 * 
	 * @param db SQLite Database instance
	 * @param id Grievance ID
	 * @param user Authenticated session user
	 * @returns Public grievance DTO
	 */
	static getGrievanceById(db: Database, id: string, user: SessionUser): PublicGrievance {
		const row = requireGrievance(db, id);
		assertCanViewGrievance(user, row);
		return assembleGrievance(db, row);
	}

	/**
	 * Creates a new grievance submitted by a student.
	 * 
	 * @param db SQLite Database instance
	 * @param uploadsDir Upload directory path
	 * @param user Authenticated session user (must be student)
	 * @param data Grievance inputs (title, category, description)
	 * @param upload Optional uploaded file
	 * @returns Newly created public grievance DTO
	 */
	static async createGrievance(
		db: Database,
		uploadsDir: string,
		user: SessionUser,
		data: { title: string; category: string; description: string },
		upload?: File
	): Promise<PublicGrievance> {
		if (user.role !== 'student') {
			throw new HttpError(403, 'unauthorized', 'Only students can file grievances.');
		}

		const title = data.title.trim();
		const description = data.description.trim();

		if (title.length < 5) {
			throw new HttpError(400, 'bad_request', 'Title must be at least 5 characters.');
		}
		if (description.length < 20) {
			throw new HttpError(400, 'bad_request', 'Description must be at least 20 characters.');
		}

		const parsedCategory = parseCategory(data.category);
		const id = nextGrievanceId(db);
		const ts = nowIso();

		// Safe parameterized query
		db.prepare(
			`INSERT INTO grievances (id, student_id, title, category, description, status, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`
		).run(id, user.id, title, parsedCategory, description, ts, ts);

		if (upload) {
			const bytes = await bufferFromUpload(upload);
			const stored = newStoredName(upload.type);
			writeStoredFile(uploadsDir, stored, bytes);
			db.prepare(
				`INSERT INTO attachments (id, grievance_id, original_filename, stored_filename, mime_type, size_bytes, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`
			).run(
				nextAttachmentId(db),
				id,
				originalBasename(upload.name),
				stored,
				upload.type,
				bytes.byteLength,
				ts
			);
		}

		return assembleGrievance(db, requireGrievance(db, id));
	}

	/**
	 * Updates a grievance according to RBAC restrictions.
	 * - Student: Can update title/category/description of own open grievance. Cannot change status.
	 * - Warden: Can only update status of any grievance.
	 * 
	 * @param db SQLite Database instance
	 * @param id Grievance ID
	 * @param user Authenticated session user
	 * @param body Patch parameters
	 * @returns Updated public grievance DTO
	 */
	static updateGrievance(
		db: Database,
		id: string,
		user: SessionUser,
		body: Record<string, unknown>
	): PublicGrievance {
		const row = requireGrievance(db, id);

		const title = 'title' in body ? body.title : undefined;
		const description = 'description' in body ? body.description : undefined;
		const category = 'category' in body ? body.category : undefined;
		const status = 'status' in body ? body.status : undefined;

		const wantsContent = title !== undefined || description !== undefined || category !== undefined;
		const wantsStatus = status !== undefined;

		if (!wantsContent && !wantsStatus) {
			throw new HttpError(400, 'bad_request', 'No updatable fields were provided.');
		}

		switch (user.role) {
			case 'student': {
				// Verify ownership
				if (row.student_id !== user.id) {
					throw new HttpError(403, 'unauthorized', 'You cannot edit this grievance.');
				}
				// Verify status restriction for student
				if (wantsStatus) {
					throw new HttpError(403, 'unauthorized', 'Students cannot update grievance status.');
				}
				if (row.status === 'resolved') {
					throw new HttpError(409, 'conflict', 'Resolved grievances cannot be edited.');
				}

				let nextTitle = row.title;
				let nextDescription = row.description;
				let nextCategory = row.category;

				if (title !== undefined) {
					if (typeof title !== 'string' || title.trim().length < 5) {
						throw new HttpError(400, 'bad_request', 'Title must be at least 5 characters.');
					}
					nextTitle = title.trim();
				}
				if (description !== undefined) {
					if (typeof description !== 'string' || description.trim().length < 20) {
						throw new HttpError(400, 'bad_request', 'Description must be at least 20 characters.');
					}
					nextDescription = description.trim();
				}
				if (category !== undefined) {
					if (typeof category !== 'string') {
						throw new HttpError(400, 'bad_request', 'Invalid grievance category.');
					}
					nextCategory = parseCategory(category);
				}

				const ts = nowIso();
				db.prepare(
					'UPDATE grievances SET title = ?, description = ?, category = ?, updated_at = ? WHERE id = ?'
				).run(nextTitle, nextDescription, nextCategory, ts, row.id);
				break;
			}
			case 'warden': {
				if (wantsContent) {
					throw new HttpError(403, 'unauthorized', 'Wardens cannot edit grievance content.');
				}
				if (typeof status !== 'string') {
					throw new HttpError(400, 'bad_request', 'Invalid grievance status.');
				}
				const nextStatus = statusToDb(status);
				const ts = nowIso();
				db.prepare('UPDATE grievances SET status = ?, updated_at = ? WHERE id = ?').run(
					nextStatus,
					ts,
					row.id
				);
				break;
			}
		}

		return assembleGrievance(db, requireGrievance(db, row.id));
	}

	/**
	 * Lists comments for a grievance if user has view permission.
	 * 
	 * @param db SQLite Database instance
	 * @param grievanceId Grievance ID
	 * @param user Authenticated session user
	 * @returns List of public comment DTOs
	 */
	static listComments(db: Database, grievanceId: string, user: SessionUser): PublicComment[] {
		const row = requireGrievance(db, grievanceId);
		assertCanViewGrievance(user, row);

		return listCommentRows(db, row.id).map((comment) => {
			const authorRow = findUserById(db, comment.author_id);
			if (!authorRow) {
				throw new HttpError(500, 'internal', 'Internal server error.');
			}
			return toPublicComment(comment, toPublicUser(authorRow));
		});
	}

	/**
	 * Adds a comment to a grievance.
	 * 
	 * @param db SQLite Database instance
	 * @param grievanceId Grievance ID
	 * @param user Authenticated session user
	 * @param commentText Text body of comment
	 * @returns Created public comment DTO
	 */
	static addComment(
		db: Database,
		grievanceId: string,
		user: SessionUser,
		commentText: string
	): PublicComment {
		const row = requireGrievance(db, grievanceId);
		assertCanViewGrievance(user, row);

		const text = commentText.trim();
		if (!text) {
			throw new HttpError(400, 'bad_request', 'Comment cannot be empty.');
		}

		const id = nextCommentId(db);
		const ts = nowIso();
		db.prepare(
			`INSERT INTO comments (id, grievance_id, author_id, body, created_at) VALUES (?, ?, ?, ?, ?)`
		).run(id, row.id, user.id, text, ts);
		touchGrievance(db, row.id, ts);

		const author = findUserById(db, user.id);
		if (!author) {
			throw new HttpError(500, 'internal', 'Internal server error.');
		}
		const commentRow = db.prepare('SELECT * FROM comments WHERE id = ?').get(id) as CommentRow;
		return toPublicComment(commentRow, toPublicUser(author));
	}

	/**
	 * Adds an attachment upload to an existing grievance.
	 * Restricted to the student owner of an open grievance.
	 * 
	 * @param db SQLite Database instance
	 * @param uploadsDir Upload directory path
	 * @param grievanceId Grievance ID
	 * @param user Authenticated session user
	 * @param upload File upload payload
	 * @returns Saved public attachment DTO
	 */
	static async addAttachment(
		db: Database,
		uploadsDir: string,
		grievanceId: string,
		user: SessionUser,
		upload: File
	): Promise<PublicAttachment> {
		const row = requireGrievance(db, grievanceId);
		if (user.role !== 'student' || row.student_id !== user.id) {
			throw new HttpError(403, 'unauthorized', 'Only the student owner can add attachments.');
		}
		if (row.status === 'resolved') {
			throw new HttpError(409, 'conflict', 'Resolved grievances cannot be edited.');
		}

		const bytes = await bufferFromUpload(upload);
		const stored = newStoredName(upload.type, upload.name);
		const ts = nowIso();

		writeStoredFile(uploadsDir, stored, bytes);
		const id = nextAttachmentId(db);
		db.prepare(
			`INSERT INTO attachments (id, grievance_id, original_filename, stored_filename, mime_type, size_bytes, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`
		).run(id, row.id, originalBasename(upload.name), stored, upload.type, bytes.byteLength, ts);
		touchGrievance(db, row.id, ts);

		const saved = db.prepare('SELECT * FROM attachments WHERE id = ?').get(id) as AttachmentRow;
		return toPublicAttachment(saved);
	}
}
