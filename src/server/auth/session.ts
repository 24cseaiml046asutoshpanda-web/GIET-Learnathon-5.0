import type { Database } from 'better-sqlite3';
import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import {
	ACCESS_COOKIE_NAME,
	ACCESS_TOKEN_TTL_SECONDS,
	REFRESH_COOKIE_NAME,
	REFRESH_TOKEN_TTL_SECONDS,
	SESSION_COOKIE,
	SESSION_TTL_SECONDS
} from '../config.ts';
import { HttpError } from '../http/errors.ts';
import type { SessionUser } from '../types/index.ts';
import { constantTimeCompare, generateRandomToken, hashToken, signAccessToken, verifyAccessToken } from '../utils/crypto.ts';

function nowIso(): string {
	return new Date().toISOString();
}

function refreshExpiryIso(): string {
	return new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString();
}

function sessionExpiryIso(): string {
	return new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
}

/**
 * Creates a new hashed refresh token and stores it in the database.
 * The raw token is returned to be sent to the client in an HttpOnly cookie.
 */
export function createRefreshToken(db: Database, userId: string): { refreshToken: string; accessToken: string } {
	const rawRefreshToken = generateRandomToken(32);
	const hashed = hashToken(rawRefreshToken);
	const tokenId = `rt_${generateRandomToken(16)}`;

	// Insert hashed refresh token into DB
	db.prepare(
		'INSERT INTO refresh_tokens (id, user_id, token_hash, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, ?, 0)'
	).run(tokenId, userId, hashed, nowIso(), refreshExpiryIso());

	// Maintain legacy sessions table compatibility
	db.prepare(
		'INSERT OR REPLACE INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
	).run(rawRefreshToken, userId, nowIso(), sessionExpiryIso());

	// Fetch user details to sign access token
	const user = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(userId) as {
		id: string;
		email: string;
		role: SessionUser['role'];
	} | undefined;

	if (!user) {
		throw new HttpError(404, 'not_found', 'User not found.');
	}

	const accessToken = signAccessToken(user);
	return { refreshToken: rawRefreshToken, accessToken };
}

/**
 * Revokes a refresh token in the database.
 */
export function revokeRefreshToken(db: Database, rawRefreshToken: string): void {
	const hashed = hashToken(rawRefreshToken);
	db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').run(hashed);
	db.prepare('DELETE FROM sessions WHERE token = ?').run(rawRefreshToken);
}

/**
 * Verifies a raw refresh token against its stored DB hash using constant-time comparison.
 */
export function verifyAndReadRefreshTokenUser(db: Database, rawRefreshToken: string): SessionUser | undefined {
	const hashed = hashToken(rawRefreshToken);
	const row = db
		.prepare(
			`SELECT rt.token_hash, rt.expires_at, rt.revoked, u.id, u.name, u.email, u.role, u.room, u.created_at
       FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = ? AND rt.revoked = 0`
		)
		.get(hashed) as
		| {
				token_hash: string;
				expires_at: string;
				revoked: number;
				id: string;
				name: string;
				email: string;
				role: SessionUser['role'];
				room: string | null;
				created_at: string;
		  }
		| undefined;

	if (!row) return undefined;

	// Constant-time check on token hash
	if (!constantTimeCompare(row.token_hash, hashed)) {
		return undefined;
	}

	if (new Date(row.expires_at).getTime() < Date.now()) {
		return undefined;
	}

	return {
		id: row.id,
		name: row.name,
		email: row.email,
		role: row.role,
		room: row.room,
		created_at: row.created_at
	};
}

/**
 * Legacy session user lookup for backwards compatibility.
 */
export function readSessionUser(db: Database, token: string): SessionUser | undefined {
	// First attempt access token verification
	const verified = verifyAccessToken(token);
	if (verified) {
		const userRow = db
			.prepare('SELECT id, name, email, role, room, created_at FROM users WHERE id = ?')
			.get(verified.id) as SessionUser | undefined;
		if (userRow) {
			// Ensure the user still has at least one active (non-revoked) refresh token.
			// This makes logout effective immediately even while the access token is still
			// within its TTL window.
			const activeRefresh = db
				.prepare(
					`SELECT 1 FROM refresh_tokens WHERE user_id = ? AND revoked = 0 AND expires_at > ? LIMIT 1`
				)
				.get(verified.id, new Date().toISOString());
			if (activeRefresh) return userRow;
		}
	}

	// Fallback to refresh token DB check
	const refreshUser = verifyAndReadRefreshTokenUser(db, token);
	if (refreshUser) return refreshUser;

	// Fallback to legacy sessions table
	const row = db
		.prepare(
			`SELECT u.id, u.name, u.email, u.role, u.room, u.created_at, s.expires_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = ?`
		)
		.get(token) as (SessionUser & { expires_at: string }) | undefined;
	if (!row) return undefined;
	if (new Date(row.expires_at).getTime() < Date.now()) return undefined;

	return {
		id: row.id,
		name: row.name,
		email: row.email,
		role: row.role,
		room: row.room,
		created_at: row.created_at
	};
}

/**
 * Sets secure authentication cookies with HttpOnly, SameSite, and Secure flags.
 */
export function setAuthCookies(
	c: Context,
	tokens: { refreshToken: string; accessToken: string }
): void {
	const isProduction = process.env.NODE_ENV === 'production';

	setCookie(c, REFRESH_COOKIE_NAME, tokens.refreshToken, {
		httpOnly: true,
		secure: isProduction,
		sameSite: 'Strict',
		path: '/',
		maxAge: REFRESH_TOKEN_TTL_SECONDS
	});

	setCookie(c, ACCESS_COOKIE_NAME, tokens.accessToken, {
		httpOnly: true,
		secure: isProduction,
		sameSite: 'Strict',
		path: '/',
		maxAge: ACCESS_TOKEN_TTL_SECONDS
	});

	// Legacy cookie for existing test assertions
	setCookie(c, SESSION_COOKIE, tokens.refreshToken, {
		httpOnly: true,
		secure: isProduction,
		sameSite: 'Strict',
		path: '/',
		maxAge: REFRESH_TOKEN_TTL_SECONDS
	});
}

/**
 * Clears all authentication cookies.
 */
export function clearAuthCookies(c: Context): void {
	deleteCookie(c, REFRESH_COOKIE_NAME, { path: '/' });
	deleteCookie(c, ACCESS_COOKIE_NAME, { path: '/' });
	deleteCookie(c, SESSION_COOKIE, { path: '/' });
}

export function setSessionCookie(c: Context, token: string): void {
	const isProduction = process.env.NODE_ENV === 'production';
	setCookie(c, SESSION_COOKIE, token, {
		httpOnly: true,
		secure: isProduction,
		sameSite: 'Strict',
		path: '/',
		maxAge: SESSION_TTL_SECONDS
	});
}

export function clearSessionCookie(c: Context): void {
	clearAuthCookies(c);
}

export function requireUser(c: Context, db: Database): SessionUser {
	// Try access cookie first, then refresh cookie, then legacy session cookie, then Authorization header
	const accessToken = getCookie(c, ACCESS_COOKIE_NAME);
	if (accessToken) {
		const payload = verifyAccessToken(accessToken);
		if (payload) {
			const userRow = db
				.prepare('SELECT id, name, email, role, room, created_at FROM users WHERE id = ?')
				.get(payload.id) as SessionUser | undefined;
			if (userRow) {
				// Verify the user still has an active (non-revoked) refresh token so that
				// logout is effective immediately — even if the access token hasn't expired.
				const activeRefresh = db
					.prepare(
						'SELECT 1 FROM refresh_tokens WHERE user_id = ? AND revoked = 0 AND expires_at > ? LIMIT 1'
					)
					.get(payload.id, new Date().toISOString());
				if (activeRefresh) return userRow;
			}
		}
	}

	const refreshToken = getCookie(c, REFRESH_COOKIE_NAME) || getCookie(c, SESSION_COOKIE);
	if (refreshToken) {
		const user = readSessionUser(db, refreshToken);
		if (user) return user;
	}

	const authHeader = c.req.header('authorization');
	if (authHeader && authHeader.startsWith('Bearer ')) {
		const bearerToken = authHeader.slice(7).trim();
		const user = readSessionUser(db, bearerToken);
		if (user) return user;
	}

	throw new HttpError(401, 'unauthenticated', 'Authentication required.');
}

export function optionalToken(c: Context): string | undefined {
	return (
		getCookie(c, REFRESH_COOKIE_NAME) ||
		getCookie(c, ACCESS_COOKIE_NAME) ||
		getCookie(c, SESSION_COOKIE)
	);
}
