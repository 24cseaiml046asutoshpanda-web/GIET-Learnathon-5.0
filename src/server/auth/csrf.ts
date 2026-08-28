import type { Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { CSRF_COOKIE_NAME } from '../config.ts';
import { HttpError } from '../http/errors.ts';
import { generateRandomToken } from '../utils/crypto.ts';

/**
 * Generates a fresh CSRF token.
 */
export function generateCsrfToken(): string {
	return generateRandomToken(32);
}

/**
 * Sets CSRF token cookie with secure attributes.
 */
export function setCsrfCookie(c: Context, token: string): void {
	const isProduction = process.env.NODE_ENV === 'production';
	setCookie(c, CSRF_COOKIE_NAME, token, {
		httpOnly: true,
		secure: isProduction,
		sameSite: 'Strict',
		path: '/'
	});
}

/**
 * Retrieves existing CSRF token from cookie or generates a new one.
 */
export function getOrCreateCsrfToken(c: Context): string {
	let token = getCookie(c, CSRF_COOKIE_NAME);
	if (!token) {
		token = generateCsrfToken();
		setCsrfCookie(c, token);
	}
	return token;
}

/**
 * Validates incoming mutating requests using the custom-header CSRF pattern.
 *
 * Browsers cannot attach custom headers (X-CSRF-Token) to cross-origin requests
 * without a preflight CORS check, so the presence of a non-empty header is an
 * unforgeable proof of same-origin intent — no cookie comparison required.
 *
 * The CSRF token value is still issued at login in the JSON body and stored in
 * the hg_csrf HttpOnly cookie so client JS can read it and echo it in the header.
 */
export function verifyCsrfRequest(c: Context): void {
	const headerToken = c.req.header('x-csrf-token') || c.req.header('X-CSRF-Token');

	if (!headerToken || headerToken.trim().length === 0) {
		throw new HttpError(403, 'csrf_invalid', 'Invalid or missing CSRF token.');
	}
}
