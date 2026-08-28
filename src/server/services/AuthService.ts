import type { Database } from 'better-sqlite3';
import { createSession, destroySession } from '../auth/session.ts';
import { verifyPassword } from '../auth/passwords.ts';
import { findUserByEmail, findUserById } from '../db/queries.ts';
import { toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import type { PublicUser } from '../types/index.ts';

/**
 * AuthService Class
 * Contains static business logic methods for authentication, login, logout, and session user retrieval.
 */
export class AuthService {
	/**
	 * Authenticates user by email and password, creating a new session token.
	 * 
	 * @param db SQLite Database instance
	 * @param email User email
	 * @param password Raw password
	 * @returns Object containing public user DTO and session token
	 */
	static login(db: Database, email: string, password: string): { user: PublicUser; token: string } {
		const cleanEmail = email.trim().toLowerCase();
		if (!cleanEmail || !password) {
			throw new HttpError(400, 'bad_request', 'Email and password are required.');
		}

		// Parameterized query execution via findUserByEmail protects against SQL injection
		const user = findUserByEmail(db, cleanEmail);
		if (!user || !verifyPassword(password, user.password_hash)) {
			throw new HttpError(401, 'unauthenticated', 'Invalid email or password.');
		}

		const token = createSession(db, user.id);
		return {
			user: toPublicUser(user),
			token
		};
	}

	/**
	 * Destroys user session token in the database.
	 * 
	 * @param db SQLite Database instance
	 * @param token Active session token
	 */
	static logout(db: Database, token: string): void {
		if (token) {
			destroySession(db, token);
		}
	}

	/**
	 * Fetches current public user profile by user ID.
	 * 
	 * @param db SQLite Database instance
	 * @param userId User unique identifier
	 * @returns Public user profile DTO
	 */
	static getCurrentUser(db: Database, userId: string): PublicUser {
		const user = findUserById(db, userId);
		if (!user) {
			throw new HttpError(404, 'not_found', 'User not found.');
		}
		return toPublicUser(user);
	}
}
