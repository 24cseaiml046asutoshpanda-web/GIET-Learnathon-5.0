import { mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ALLOWED_ATTACHMENT_TYPES, MAX_ATTACHMENT_BYTES } from '../config.ts';
import { HttpError } from '../http/errors.ts';

const MIME_EXTENSION: Record<string, string> = {
	'image/jpeg': '.jpg',
	'image/png': '.png',
	'image/gif': '.gif',
	'image/webp': '.webp'
};

const DANGEROUS_EXTENSIONS = new Set([
	'exe', 'php', 'js', 'bat', 'sh', 'cmd', 'vbs', 'py', 'pl',
	'html', 'htm', 'cgi', 'dll', 'sys', 'com', 'scr', 'phtml',
	'php3', 'php4', 'php5', 'phps', 'asp', 'aspx', 'jsp', 'jar'
]);

const ALLOWED_EXTENSIONS = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp']);

export function ensureUploadsDir(dir: string): void {
	mkdirSync(dir, { recursive: true });
}

export function resetUploadsDir(dir: string): void {
	if (existsSync(dir)) {
		rmSync(dir, { recursive: true, force: true });
	}
	mkdirSync(dir, { recursive: true });
}

/**
 * Validates original filename against double-extension tricks (e.g. .png.exe, .jpeg.php)
 * and strips control characters.
 */
export function originalBasename(filename: string): string {
	const base = filename.replace(/\\/g, '/').split('/').pop() ?? 'upload';
	const cleaned = base.replace(/[\0\r\n]/g, '').trim();

	// Check double extension attacks (e.g. image.png.exe)
	const parts = cleaned.split('.').filter(Boolean);
	if (parts.length > 1) {
		const ext = parts[parts.length - 1].toLowerCase();
		// If last extension is dangerous or not in allowed image extensions
		if (DANGEROUS_EXTENSIONS.has(ext) || !ALLOWED_EXTENSIONS.has(ext)) {
			throw new HttpError(400, 'bad_request', 'Invalid file extension.');
		}
		// Check intermediate extensions for executable tricks (e.g. payload.exe.png)
		for (let i = 0; i < parts.length - 1; i++) {
			const subExt = parts[i].toLowerCase();
			if (DANGEROUS_EXTENSIONS.has(subExt)) {
				throw new HttpError(400, 'bad_request', 'Double extension or suspicious filename detected.');
			}
		}
	}

	return cleaned.length > 0 ? cleaned.slice(0, 255) : 'upload';
}

export function extensionForMime(mime: string): string {
	return MIME_EXTENSION[mime] ?? '.bin';
}

export function newStoredName(mime: string, originalName?: string): string {
	return originalName ?? `${randomBytes(16).toString('hex')}${extensionForMime(mime)}`;
}

/**
 * Validates binary signature (magic numbers) of uploaded image buffer.
 */
export function verifyImageMagicBytes(bytes: Buffer): string {
	if (bytes.length < 4) {
		throw new HttpError(400, 'bad_request', 'File buffer is too small to be a valid image.');
	}

	// PNG: 89 50 4E 47
	if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
		return 'image/png';
	}

	// JPEG: FF D8 FF
	if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
		return 'image/jpeg';
	}

	// GIF: 47 49 46 (GIF87a / GIF89a)
	if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
		return 'image/gif';
	}

	// WebP: RIFF ... WEBP
	if (
		bytes.length >= 12 &&
		bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
		bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
	) {
		return 'image/webp';
	}

	throw new HttpError(400, 'bad_request', 'Invalid file format or corrupted image binary signature.');
}

/**
 * Enforces size limits, permitted MIME types, filename sanity, and magic byte binary checks.
 */
export function assertPermittedAttachment(mime: string, size: number, filename?: string): void {
	if (!ALLOWED_ATTACHMENT_TYPES.has(mime)) {
		throw new HttpError(400, 'bad_request', 'Attachments must be JPEG, PNG, GIF, or WebP images.');
	}
	if (size <= 0) {
		throw new HttpError(400, 'bad_request', 'Attachment file is empty.');
	}
	if (size > MAX_ATTACHMENT_BYTES) {
		throw new HttpError(400, 'bad_request', 'Attachment must be 2 MB or smaller.');
	}
	if (filename) {
		originalBasename(filename);
	}
}

export async function bufferFromUpload(file: File): Promise<Buffer> {
	assertPermittedAttachment(file.type, file.size, file.name);
	const bytes = Buffer.from(await file.arrayBuffer());
	// Verify binary signature magic bytes
	const detectedMime = verifyImageMagicBytes(bytes);
	if (file.type && file.type !== detectedMime) {
		// Normalize jpeg vs jpg MIME alias
		if (
			!(file.type === 'image/jpeg' && detectedMime === 'image/jpeg') &&
			!(file.type === 'image/jpg' && detectedMime === 'image/jpeg')
		) {
			throw new HttpError(400, 'bad_request', 'MIME type mismatch with binary image contents.');
		}
	}
	return bytes;
}

export function writeStoredFile(uploadsDir: string, storedName: string, bytes: Buffer): void {
	ensureUploadsDir(uploadsDir);
	writeFileSync(join(uploadsDir, storedName), bytes);
}

export function readStoredFile(uploadsDir: string, storedName: string): Buffer {
	if (storedName.includes('/') || storedName.includes('\\') || storedName.includes('..')) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	const root = resolve(uploadsDir);
	const full = resolve(join(uploadsDir, storedName));
	if (full !== root && !full.startsWith(root + sep)) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	if (!existsSync(full)) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	return readFileSync(full);
}

export function listStoredNames(uploadsDir: string): string[] {
	if (!existsSync(uploadsDir)) return [];
	return readdirSync(uploadsDir).filter((name) => name !== '.gitkeep');
}
