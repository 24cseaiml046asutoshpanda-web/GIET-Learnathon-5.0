import { Hono } from 'hono';
import { pinoLogger } from 'hono-pino';
import type { Database } from 'better-sqlite3';
import type { AppEnv } from './env.ts';
import { handleError, HttpError } from './http/errors.ts';
import { authRoutes } from './routes/auth.ts';
import { grievanceRoutes } from './routes/grievances.ts';
import { attachmentRoutes } from './routes/attachments.ts';
import { cors } from 'hono/cors';
import { RateLimitMiddleware } from './middlewares/rateLimiter.ts';
import { ALLOWED_CORS_ORIGINS } from './config.ts';
import { bodyLimitMiddleware } from './middlewares/bodyLimit.ts';
import { csrfMiddleware } from './middlewares/csrf.ts';

export type CreateAppOptions = {
	db: Database;
	uploadsDir: string;
};

/**
 * Creates and configures the Hono application server instance with middleware, security headers, and routes.
 * 
 * @param options Database and uploads directory dependencies
 * @returns Configured Hono app
 */
export function createApp(options: CreateAppOptions) {
	const app = new Hono<AppEnv>();

	// Concise console logger via hono-pino (strip headers, cookies, and user-agent)
	app.use(
		pinoLogger({
			pino: {
				level: 'info'
			},
			http: {
				reqId: false,
				onReqBindings: () => ({}),
				onResBindings: () => ({}),
				onResMessage: (c) => {
					const resTime = (c.var as any)?.responseTime;
					const duration = typeof resTime === 'number' ? ` (${Math.round(resTime)}ms)` : '';
					return `${c.req.method} ${c.req.path} → ${c.res.status}${duration}`;
				}
			}
		})
	);

	// Inject dependency context variables
	app.use('*', async (c, next) => {
		c.set('db', options.db);
		c.set('uploadsDir', options.uploadsDir);
		await next();
	});

	// Security Headers Middleware
	app.use('*', async (c, next) => {
		c.header('X-Content-Type-Options', 'nosniff');
		c.header('X-Frame-Options', 'DENY');
		c.header('X-XSS-Protection', '1; mode=block');
		c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
		await next();
	});

	// CORS Whitelist Configuration
	app.use(
		'/api/*',
		cors({
			origin: (origin) => {
				if (!origin) return ALLOWED_CORS_ORIGINS[0];
				return ALLOWED_CORS_ORIGINS.includes(origin) ? origin : null;
			},
			credentials: true
		})
	);

	// Body Size Limit Middleware (1 MB for standard JSON payloads)
	app.use('/api/*', bodyLimitMiddleware());

	// CSRF Protection Middleware on Mutating Endpoints
	app.use('/api/*', csrfMiddleware());

	// Global API Rate Limiting (max 200 requests per 15 min window)
	app.use(
		'/api/*',
		RateLimitMiddleware.limit({ windowMs: 15 * 60 * 1000, maxRequests: 200 })
	);

	// Error Handler
	app.onError((err, c) => handleError(err, c));

	// Not Found Handler
	app.notFound((c) => c.json({ error: 'Not found.', code: 'not_found' }, 404));

	// Route Registrations
	app.get('/api/health', (c) => c.json({ ok: true }));
	app.route('/api', authRoutes);
	app.route('/api/grievances', grievanceRoutes);
	app.route('/api/attachments', attachmentRoutes);

	app.all('/api/*', () => {
		throw new HttpError(404, 'not_found', 'Not found.');
	});

	return app;
}
