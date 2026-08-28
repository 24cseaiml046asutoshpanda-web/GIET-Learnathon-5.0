import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env.ts';
import { HttpError } from '../http/errors.ts';
import { optionalToken } from '../auth/session.ts';

interface RateLimitStore {
	count: number;
	resetTime: number;
}

export interface RateLimitOptions {
	/** Window duration in milliseconds */
	windowMs: number;
	/** Maximum allowed requests per window */
	maxRequests: number;
	/** Optional custom error message */
	message?: string;
	/** Optional key generator function */
	keyGenerator?: (c: any) => string;
}

/**
 * RateLimitMiddleware Class
 * Provides intelligent rate limiting using hybrid key resolution (User ID, Auth Token, or IP+Path)
 * to prevent single IP bottlenecks on shared Wi-Fi networks.
 */
export class RateLimitMiddleware {
	private static rateLimitMap = new Map<string, RateLimitStore>();

	/**
	 * Resolves rate limiting key to differentiate users on shared NAT/Wi-Fi IPs.
	 */
	private static getRateLimitKey(c: any): string {
		const user = c.get('user');
		if (user && user.id) {
			return `user:${user.id}`;
		}

		const token = optionalToken(c);
		if (token) {
			return `token:${token.slice(0, 16)}`;
		}

		const ip =
			c.req.header('x-forwarded-for') ||
			c.req.header('cf-connecting-ip') ||
			'global_client';

		const path = c.req.path;
		return `ip:${ip}:path:${path}`;
	}

	/**
	 * Creates a rate limiter middleware for Hono context.
	 */
	static limit(options: RateLimitOptions): MiddlewareHandler<AppEnv> {
		return async (c, next) => {
			const key = options.keyGenerator
				? options.keyGenerator(c)
				: RateLimitMiddleware.getRateLimitKey(c);

			const now = Date.now();

			// Periodic cleanup of stale rate limit entries
			if (RateLimitMiddleware.rateLimitMap.size > 5000) {
				for (const [k, store] of RateLimitMiddleware.rateLimitMap.entries()) {
					if (now > store.resetTime) {
						RateLimitMiddleware.rateLimitMap.delete(k);
					}
				}
			}

			const record = RateLimitMiddleware.rateLimitMap.get(key);

			if (!record || now > record.resetTime) {
				RateLimitMiddleware.rateLimitMap.set(key, {
					count: 1,
					resetTime: now + options.windowMs
				});
			} else {
				record.count += 1;
				if (record.count > options.maxRequests) {
					const retryAfterSec = Math.ceil((record.resetTime - now) / 1000);
					c.header('Retry-After', String(retryAfterSec));
					throw new HttpError(
						429,
						'rate_limit_exceeded',
						options.message || 'Too many requests. Please try again later.'
					);
				}
			}

			await next();
		};
	}

	/**
	 * Clears the rate limit store (useful for testing).
	 */
	static reset(): void {
		RateLimitMiddleware.rateLimitMap.clear();
	}
}
