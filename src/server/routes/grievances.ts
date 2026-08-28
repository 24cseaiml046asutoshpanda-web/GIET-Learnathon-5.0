import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { GrievanceController } from '../controllers/GrievanceController.ts';
import { AuthMiddleware } from '../middlewares/auth.ts';

export const grievanceRoutes = new Hono<AppEnv>();

// Apply authentication middleware to all grievance routes
grievanceRoutes.use('*', AuthMiddleware.authenticate());

// List grievances accessible to authenticated user (Students see own; Wardens see all)
grievanceRoutes.get('/', GrievanceController.list);

// Create new grievance (Student role only)
grievanceRoutes.post('/', AuthMiddleware.requireRole('student'), GrievanceController.create);

// Get single grievance details by ID (Owner or Warden)
grievanceRoutes.get('/:id', GrievanceController.getById);

// Update grievance (Owner student or Warden status update)
grievanceRoutes.patch('/:id', GrievanceController.update);

// List comments on grievance
grievanceRoutes.get('/:id/comments', GrievanceController.listComments);

// Add comment to grievance
grievanceRoutes.post('/:id/comments', GrievanceController.addComment);

// Add attachment upload to grievance
grievanceRoutes.post(
	'/:id/attachments',
	AuthMiddleware.requireRole('student'),
	GrievanceController.addAttachment
);
