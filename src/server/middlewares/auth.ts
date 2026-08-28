import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env.ts';
import { requireUser } from '../auth/session.ts';
import { HttpError } from '../http/errors.ts';
import type { Role } from '../types/index.ts';
import { requireGrievance, assertCanViewGrievance } from '../db/queries.ts';

/**
 * AuthMiddleware Class
 * Provides static middleware functions for authentication and role-based access control (RBAC).
 */
export class AuthMiddleware {
	/**
	 * Middleware to authenticate requests.
	 * Reads session token from cookie, looks up user in database, and attaches user to context (`c.set('user', user)`).
	 * Throws HTTP 401 if unauthenticated.
	 */
	static authenticate(): MiddlewareHandler<AppEnv> {
		return async (c, next) => {
			const db = c.get('db');
			const user = requireUser(c, db);
			c.set('user', user);
			await next();
		};
	}

	/**
	 * Middleware to enforce role-based authorization (RBAC).
	 * Must be used after `AuthMiddleware.authenticate()`.
	 * Checks if the authenticated user's role is included in `allowedRoles`.
	 * Throws HTTP 403 if user lacks required role.
	 * 
	 * @param allowedRoles List of roles permitted to access the route
	 */
	static requireRole(...allowedRoles: Role[]): MiddlewareHandler<AppEnv> {
		return async (c, next) => {
			const user = c.get('user');
			if (!user) {
				throw new HttpError(401, 'unauthenticated', 'Authentication required.');
			}
			if (!allowedRoles.includes(user.role)) {
				throw new HttpError(403, 'unauthorized', 'You do not have permission to access this resource.');
			}
			await next();
		};
	}

	/**
	 * Middleware to verify user permission to view/modify a specific grievance.
	 * Checks if the user is a warden (all access) or student owner of the grievance.
	 * Throws HTTP 403 if unauthorized or HTTP 404 if grievance does not exist.
	 */
	static checkGrievanceAccess(): MiddlewareHandler<AppEnv> {
		return async (c, next) => {
			const db = c.get('db');
			const user = c.get('user');
			if (!user) {
				throw new HttpError(401, 'unauthenticated', 'Authentication required.');
			}
			const grievanceId = c.req.param('id');
			if (grievanceId) {
				const grievance = requireGrievance(db, grievanceId);
				assertCanViewGrievance(user, grievance);
			}
			await next();
		};
	}
}
