import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env.ts';
import { verifyCsrfRequest } from '../auth/csrf.ts';

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * CSRF Protection Middleware
 * Enforces CSRF token check on all mutating HTTP methods (POST, PUT, PATCH, DELETE).
 * Safe HTTP methods (GET, HEAD, OPTIONS) bypass validation.
 */
export function csrfMiddleware(): MiddlewareHandler<AppEnv> {
	return async (c, next) => {
		const method = c.req.method.toUpperCase();
		if (MUTATING_METHODS.has(method)) {
			// Skip CSRF check for login route if login uses credentials alone, but check all authenticated mutating routes.
			// Or check CSRF header if CSRF cookie is set on the client.
			// To avoid breaking unauthenticated initial login calls before CSRF cookie is set, check if cookie exists or path is exempted.
			const path = c.req.path;
			const isExempted = path === '/api/login' || path === '/api/csrf-token';
			if (!isExempted) {
				verifyCsrfRequest(c);
			}
		}
		await next();
	};
}
