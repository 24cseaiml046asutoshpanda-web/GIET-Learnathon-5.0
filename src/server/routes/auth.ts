import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { AuthController } from '../controllers/AuthController.ts';
import { AuthMiddleware } from '../middlewares/auth.ts';
import { RateLimitMiddleware } from '../middlewares/rateLimiter.ts';

export const authRoutes = new Hono<AppEnv>();

// Endpoint to obtain CSRF token
authRoutes.get('/csrf-token', AuthController.getCsrfToken);

// Login endpoint protected with strict rate limiting (max 15 attempts per 15 minutes)
authRoutes.post(
	'/login',
	RateLimitMiddleware.limit({ windowMs: 15 * 60 * 1000, maxRequests: 15 }),
	AuthController.login
);

// Token refresh endpoint
authRoutes.post(
	'/refresh',
	RateLimitMiddleware.limit({ windowMs: 15 * 60 * 1000, maxRequests: 30 }),
	AuthController.refresh
);

// Logout endpoint
authRoutes.post('/logout', AuthController.logout);

// Profile endpoint requiring active user session
authRoutes.get('/me', AuthMiddleware.authenticate(), AuthController.me);
