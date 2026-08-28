import type { Database } from 'better-sqlite3';
import { createRefreshToken, revokeRefreshToken, verifyAndReadRefreshTokenUser } from '../auth/session.ts';
import { verifyPassword } from '../auth/passwords.ts';
import { findUserByEmail, findUserById } from '../db/queries.ts';
import { toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import type { PublicUser } from '../types/index.ts';
import { validateEmail } from '../utils/sanitizer.ts';

export interface AuthLoginResult {
	user: PublicUser;
	tokens: {
		refreshToken: string;
		accessToken: string;
	};
	token: string; // for backward compatibility with tests expecting token property
}

/**
 * AuthService Class
 * Handles business logic for user authentication, token issuance, refresh, and session revocation.
 */
export class AuthService {
	/**
	 * Authenticates user credentials, generates access & hashed refresh tokens.
	 */
	static login(db: Database, emailRaw: string, password: string): AuthLoginResult {
		const email = validateEmail(emailRaw);
		if (!password) {
			throw new HttpError(400, 'bad_request', 'Email and password are required.');
		}

		const user = findUserByEmail(db, email);
		if (!user || !verifyPassword(password, user.password_hash)) {
			throw new HttpError(401, 'unauthenticated', 'Invalid email or password.');
		}

		const tokens = createRefreshToken(db, user.id);

		return {
			user: toPublicUser(user),
			tokens,
			token: tokens.refreshToken
		};
	}

	/**
	 * Validates hashed refresh token and issues fresh access and refresh tokens.
	 */
	static refreshTokens(db: Database, rawRefreshToken: string): AuthLoginResult {
		if (!rawRefreshToken) {
			throw new HttpError(401, 'unauthenticated', 'Refresh token required.');
		}

		const sessionUser = verifyAndReadRefreshTokenUser(db, rawRefreshToken);
		if (!sessionUser) {
			throw new HttpError(401, 'unauthenticated', 'Invalid or expired refresh token.');
		}

		// Revoke old refresh token (token rotation)
		revokeRefreshToken(db, rawRefreshToken);

		// Issue new token pair
		const tokens = createRefreshToken(db, sessionUser.id);
		const userRow = findUserById(db, sessionUser.id);
		if (!userRow) {
			throw new HttpError(404, 'not_found', 'User not found.');
		}

		return {
			user: toPublicUser(userRow),
			tokens,
			token: tokens.refreshToken
		};
	}

	/**
	 * Destroys user refresh token in the database.
	 */
	static logout(db: Database, token: string): void {
		if (token) {
			revokeRefreshToken(db, token);
		}
	}

	/**
	 * Fetches current public user profile by user ID.
	 */
	static getCurrentUser(db: Database, userId: string): PublicUser {
		const user = findUserById(db, userId);
		if (!user) {
			throw new HttpError(404, 'not_found', 'User not found.');
		}
		return toPublicUser(user);
	}
}
