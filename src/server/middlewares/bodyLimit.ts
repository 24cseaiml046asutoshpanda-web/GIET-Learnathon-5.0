import type { MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env.ts';
import { MAX_BODY_SIZE_BYTES } from '../config.ts';
import { HttpError } from '../http/errors.ts';

/**
 * Body Size Limit Middleware
 * Rejects non-multipart request payloads exceeding MAX_BODY_SIZE_BYTES (1 MB).
 */
export function bodyLimitMiddleware(maxBytes: number = MAX_BODY_SIZE_BYTES): MiddlewareHandler<AppEnv> {
	return async (c, next) => {
		const contentLength = c.req.header('content-length');
		if (contentLength) {
			const bytes = Number.parseInt(contentLength, 10);
			if (!Number.isNaN(bytes) && bytes > maxBytes) {
				const contentType = c.req.header('content-type') ?? '';
				// Multipart form data uploads are handled separately by attachment validation
				if (!contentType.includes('multipart/form-data')) {
					throw new HttpError(413, 'payload_too_large', 'Request payload exceeds maximum allowed size.');
				}
			}
		}
		await next();
	};
}
