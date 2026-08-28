import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env.ts';
import { HttpError } from '../http/errors.ts';

interface RateLimitStore {
	count: number;
	resetTime: number;
}

/**
 * Options for RateLimitMiddleware
 */
export interface RateLimitOptions {
	/** Window duration in milliseconds */
	windowMs: number;
	/** Maximum allowed requests per window per IP */
	maxRequests: number;
	/** Optional custom error message */
	message?: string;
}

/**
 * RateLimitMiddleware Class
 * Provides static rate limiting middleware functions to protect endpoints against brute force and DDoS attacks.
 */
export class RateLimitMiddleware {
	private static ipMap = new Map<string, RateLimitStore>();

	/**
	 * Creates a rate limiter middleware for Hono context.
	 * Tracks client request rate by IP address within the specified time window.
	 * 
	 * @param options Configuration options for rate limiting window and limit
	 * @returns Hono middleware handler
	 */
	static limit(options: RateLimitOptions): MiddlewareHandler<AppEnv> {
		return async (c, next) => {
			const ip = c.req.header('x-forwarded-for') || c.req.header('cf-connecting-ip') || 'global_client';
			const now = Date.now();

			// Clean up expired entries periodically
			if (RateLimitMiddleware.ipMap.size > 5000) {
				for (const [key, store] of RateLimitMiddleware.ipMap.entries()) {
					if (now > store.resetTime) {
						RateLimitMiddleware.ipMap.delete(key);
					}
				}
			}

			const record = RateLimitMiddleware.ipMap.get(ip);

			if (!record || now > record.resetTime) {
				RateLimitMiddleware.ipMap.set(ip, {
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
		RateLimitMiddleware.ipMap.clear();
	}
}
