import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import { ACCESS_TOKEN_SECRET, ACCESS_TOKEN_TTL_SECONDS } from '../config.ts';
import type { Role } from '../types/index.ts';

/**
 * Perform constant-time string comparison to prevent timing attacks.
 */
export function constantTimeCompare(a: string, b: string): boolean {
	const bufA = Buffer.from(a, 'utf-8');
	const bufB = Buffer.from(b, 'utf-8');
	if (bufA.length !== bufB.length) {
		// Compare bufA with dummy buffer to maintain constant time execution path
		timingSafeEqual(bufA, bufA);
		return false;
	}
	return timingSafeEqual(bufA, bufB);
}

/**
 * Hashes a token using SHA-256 for secure DB storage.
 */
export function hashToken(token: string): string {
	const hash = createHash('sha256').update(token).digest('hex');
	return `sha256:${hash}`;
}

export interface AccessTokenPayload {
	id: string;
	email: string;
	role: Role;
	exp: number;
}

/**
 * Generate a cryptographically signed short-lived access token.
 */
export function signAccessToken(user: { id: string; email: string; role: Role }): string {
	const payload: AccessTokenPayload = {
		id: user.id,
		email: user.email,
		role: user.role,
		exp: Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000
	};
	const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
	const signature = createHmac('sha256', ACCESS_TOKEN_SECRET).update(encodedPayload).digest('base64url');
	return `${encodedPayload}.${signature}`;
}

/**
 * Verifies and decodes a signed access token. Returns undefined if invalid or expired.
 */
export function verifyAccessToken(token: string): { id: string; email: string; role: Role } | undefined {
	const parts = token.split('.');
	if (parts.length !== 2) return undefined;
	const [encodedPayload, signature] = parts;
	if (!encodedPayload || !signature) return undefined;

	const expectedSignature = createHmac('sha256', ACCESS_TOKEN_SECRET).update(encodedPayload).digest('base64url');
	if (!constantTimeCompare(signature, expectedSignature)) {
		return undefined;
	}

	try {
		const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf-8')) as AccessTokenPayload;
		if (typeof payload.exp !== 'number' || Date.now() > payload.exp) {
			return undefined;
		}
		if (!payload.id || !payload.email || !payload.role) {
			return undefined;
		}
		return {
			id: payload.id,
			email: payload.email,
			role: payload.role
		};
	} catch {
		return undefined;
	}
}

/**
 * Generates a high-entropy random token string (e.g. for refresh tokens or CSRF tokens).
 */
export function generateRandomToken(bytes: number = 32): string {
	return randomBytes(bytes).toString('base64url');
}
