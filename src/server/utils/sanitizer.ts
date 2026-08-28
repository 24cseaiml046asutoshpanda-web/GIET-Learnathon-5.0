import { HttpError } from '../http/errors.ts';

/**
 * Sanitizes input strings by stripping dangerous HTML tags, null bytes, control characters, and trimming whitespace.
 */
export function sanitizeString(input: unknown): string {
	if (typeof input !== 'string') return '';
	return input
		.replace(/[\0\x00-\x08\x0B\x0C\x0E-\x1F]/g, '') // remove control chars & null bytes
		.replace(/<[^>]*>/g, '') // strip HTML/XML tags
		.replace(/javascript:/gi, '') // strip inline javascript protocol
		.trim();
}

/**
 * Validates and sanitizes email address.
 */
export function validateEmail(emailRaw: unknown): string {
	const email = sanitizeString(emailRaw);
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	if (!email || email.length > 255 || !emailRegex.test(email)) {
		throw new HttpError(400, 'bad_request', 'A valid email address is required.');
	}
	return email.toLowerCase();
}

/**
 * Validates and sanitizes grievance title.
 */
export function validateTitle(titleRaw: unknown): string {
	const title = sanitizeString(titleRaw);
	if (!title || title.length < 3 || title.length > 200) {
		throw new HttpError(400, 'bad_request', 'Title must be between 3 and 200 characters.');
	}
	return title;
}

/**
 * Validates and sanitizes grievance category.
 */
export function validateCategory(categoryRaw: unknown): string {
	const category = sanitizeString(categoryRaw);
	const ALLOWED_CATEGORIES = ['Room', 'Water', 'Electricity', 'Mess', 'Other'];
	if (!category || !ALLOWED_CATEGORIES.includes(category)) {
		throw new HttpError(
			400,
			'bad_request',
			`Category must be one of: ${ALLOWED_CATEGORIES.join(', ')}.`
		);
	}
	return category;
}

/**
 * Validates and sanitizes grievance description.
 */
export function validateDescription(descRaw: unknown): string {
	const desc = sanitizeString(descRaw);
	if (!desc || desc.length < 10 || desc.length > 5000) {
		throw new HttpError(
			400,
			'bad_request',
			'Description must be between 10 and 5000 characters.'
		);
	}
	return desc;
}

/**
 * Validates and sanitizes comment body.
 */
export function validateCommentBody(bodyRaw: unknown): string {
	const body = sanitizeString(bodyRaw);
	if (!body || body.length < 1 || body.length > 2000) {
		throw new HttpError(400, 'bad_request', 'Comment body must be between 1 and 2000 characters.');
	}
	return body;
}

/**
 * Validates grievance status.
 */
export function validateStatus(statusRaw: unknown): 'open' | 'in_progress' | 'resolved' {
	const status = sanitizeString(statusRaw).toLowerCase();
	const map: Record<string, 'open' | 'in_progress' | 'resolved'> = {
		open: 'open',
		'in progress': 'in_progress',
		in_progress: 'in_progress',
		resolved: 'resolved'
	};
	if (!map[status]) {
		throw new HttpError(
			400,
			'bad_request',
			'Status must be Open, In Progress, or Resolved.'
		);
	}
	return map[status];
}
