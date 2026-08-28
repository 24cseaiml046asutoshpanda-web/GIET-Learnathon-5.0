import type { Context } from 'hono';
import type { AppEnv } from '../env.ts';
import { AuthService } from '../services/AuthService.ts';
import { clearAuthCookies, optionalToken, setAuthCookies } from '../auth/session.ts';
import { getOrCreateCsrfToken } from '../auth/csrf.ts';
import { HttpError } from '../http/errors.ts';
import { getCookie } from 'hono/cookie';
import { REFRESH_COOKIE_NAME, SESSION_COOKIE } from '../config.ts';

/**
 * AuthController Class
 * Provides static handler methods for authentication HTTP routes.
 */
export class AuthController {
	/**
	 * Handles POST /api/login
	 * Authenticates user credentials and sets secure access, refresh, and CSRF cookies.
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
		setAuthCookies(c, result.tokens);
		const csrfToken = getOrCreateCsrfToken(c);

		return c.json({ user: result.user, csrfToken });
	}

	/**
	 * Handles POST /api/refresh
	 * Refreshes access and refresh tokens.
	 */
	static refresh(c: Context<AppEnv>) {
		const db = c.get('db');
		const refreshToken =
			getCookie(c, REFRESH_COOKIE_NAME) ||
			getCookie(c, SESSION_COOKIE) ||
			optionalToken(c);

		if (!refreshToken) {
			throw new HttpError(401, 'unauthenticated', 'Refresh token is required.');
		}

		const result = AuthService.refreshTokens(db, refreshToken);
		setAuthCookies(c, result.tokens);
		const csrfToken = getOrCreateCsrfToken(c);

		return c.json({ user: result.user, csrfToken });
	}

	/**
	 * Handles GET /api/csrf-token
	 * Returns initial CSRF token and sets CSRF cookie.
	 */
	static getCsrfToken(c: Context<AppEnv>) {
		const csrfToken = getOrCreateCsrfToken(c);
		return c.json({ csrfToken });
	}

	/**
	 * Handles POST /api/logout
	 * Invalidates active refresh token and clears auth cookies.
	 */
	static logout(c: Context<AppEnv>) {
		const db = c.get('db');
		const token = optionalToken(c);
		if (token) {
			AuthService.logout(db, token);
		}
		clearAuthCookies(c);
		return c.json({ ok: true });
	}

	/**
	 * Handles GET /api/me
	 * Returns current authenticated user profile.
	 */
	static me(c: Context<AppEnv>) {
		const user = c.get('user');
		if (!user) {
			throw new HttpError(401, 'unauthenticated', 'Authentication required.');
		}
		return c.json({ user: AuthService.getCurrentUser(c.get('db'), user.id) });
	}
}
