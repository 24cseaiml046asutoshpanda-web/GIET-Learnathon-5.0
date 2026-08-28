import type { Database } from 'better-sqlite3';
import type { SessionUser } from './types/index.ts';

/**
 * Hono Application Environment Types.
 * Defines variables attached to Hono context `c.get()` and `c.set()`.
 */
export type AppEnv = {
	Variables: {
		/** SQLite Database Instance */
		db: Database;
		/** Local Directory path for file storage */
		uploadsDir: string;
		/** Current authenticated session user, if present */
		user?: SessionUser;
	};
};
