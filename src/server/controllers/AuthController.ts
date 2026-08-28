import type { Context } from 'hono';
import type { AppEnv } from '../env.ts';
import { AuthService } from '../services/AuthService.ts';
import { clearSessionCookie, optionalToken, setSessionCookie } from '../auth/session.ts';
import { HttpError } from '../http/errors.ts';

/**
 * AuthController Class
 * Provides static handler methods for authentication HTTP routes.
 */
export class AuthController {
	/**
	 * Handles POST /api/login
	 * Authenticates user credentials and sets session cookie.
	 * 
	 * @param c Hono Context
	 */
	static async login(c: Context<AppEnv>) {
		const db = c.get('db');
		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
		}

		if (!body || typeof body !== 'object') {
			throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
		}

		const email = 'email' in body && typeof body.email === 'string' ? body.email : '';
		const password = 'password' in body && typeof body.password === 'string' ? body.password : '';

		const result = AuthService.login(db, email, password);
		setSessionCookie(c, result.token);

		return c.json({ user: result.user });
	}

	/**
	 * Handles POST /api/logout
	 * Invalidates active session token and clears session cookie.
	 * 
	 * @param c Hono Context
	 */
	static logout(c: Context<AppEnv>) {
		const db = c.get('db');
		const token = optionalToken(c);
		if (token) {
			AuthService.logout(db, token);
		}
		clearSessionCookie(c);
		return c.json({ ok: true });
	}

	/**
	 * Handles GET /api/me
	 * Returns current authenticated user profile.
	 * 
	 * @param c Hono Context
	 */
	static me(c: Context<AppEnv>) {
		const user = c.get('user');
		if (!user) {
			throw new HttpError(401, 'unauthenticated', 'Authentication required.');
		}
		return c.json({ user: AuthService.getCurrentUser(c.get('db'), user.id) });
	}
}
