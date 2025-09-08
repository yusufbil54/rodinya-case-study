import { promises as fs } from 'fs';
import { join, normalize, resolve } from 'path';
import { v4 as uuidv4 } from 'uuid';

export class FileUtil {
  /**
   * Ensure directory exists, create if not
   */
  static async ensureDir(dirPath: string): Promise<void> {
    try {
      await fs.access(dirPath);
    } catch {
      await fs.mkdir(dirPath, { recursive: true });
    }
  }

  /**
   * Safe join under upload directory to prevent path traversal
   */
  static safeJoin(uploadDir: string, ...paths: string[]): string {
    const basePath = resolve(uploadDir);
    const targetPath = resolve(join(basePath, ...paths));
    
    if (!targetPath.startsWith(basePath)) {
      throw new Error('Path traversal detected');
    }
    
    return targetPath;
  }

  /**
   * Sanitize filename by removing dangerous characters
   */
  static sanitizeFilename(filename: string): string {
    return filename
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .replace(/_{2,}/g, '_')
      .replace(/^_+|_+$/g, '')
      .substring(0, 255);
  }

  /**
   * Generate unique filename with UUID
   */
  static generateUniqueFilename(originalName: string): string {
    const extension = this.getFileExtension(originalName);
    const uuid = uuidv4();
    return extension ? `${uuid}.${extension}` : uuid;
  }

  /**
   * Get file extension from filename
   */
  static getFileExtension(filename: string): string {
    const lastDotIndex = filename.lastIndexOf('.');
    return lastDotIndex !== -1 ? filename.substring(lastDotIndex + 1).toLowerCase() : '';
  }

  /**
   * Get MIME type from file extension
   */
  static getMimeTypeFromExtension(extension: string): string {
    const mimeTypes: Record<string, string> = {
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
    };
    
    return mimeTypes[extension.toLowerCase()] || 'application/octet-stream';
  }

  /**
   * Validate file size
   */
  static validateFileSize(size: number, maxSize: number): boolean {
    return size > 0 && size <= maxSize;
  }

  /**
   * Delete file safely
   */
  static async deleteFile(filePath: string): Promise<void> {
    try {
      await fs.unlink(filePath);
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }

  /**
   * Check if file exists
   */
  static async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}
