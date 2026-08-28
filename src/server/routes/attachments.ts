import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { AttachmentController } from '../controllers/AttachmentController.ts';
import { AuthMiddleware } from '../middlewares/auth.ts';

export const attachmentRoutes = new Hono<AppEnv>();

// Stream attachment file by ID (Requires user authentication & RBAC check on parent grievance)
attachmentRoutes.get('/:id', AuthMiddleware.authenticate(), AttachmentController.getAttachment);
