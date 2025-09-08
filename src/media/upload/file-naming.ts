import { v4 as uuidv4 } from 'uuid';
import { extname } from 'path';

export class FileNaming {
  /**
   * Generate safe UUID-based filename
   */
  static generateSafeFilename(originalName: string): string {
    const extension = this.extractExtension(originalName);
    const uuid = uuidv4();
    
    return extension ? `${uuid}.${extension}` : uuid;
  }

  /**
   * Extract file extension safely
   */
  static extractExtension(filename: string): string {
    const ext = extname(filename).toLowerCase();
    return ext.startsWith('.') ? ext.substring(1) : ext;
  }

  /**
   * Validate filename characters
   */
  static isValidFilename(filename: string): boolean {
    // Allow alphanumeric, dots, hyphens, underscores
    const validPattern = /^[a-zA-Z0-9._-]+$/;
    return validPattern.test(filename) && filename.length <= 255;
  }

  /**
   * Sanitize original filename for storage reference
   */
  static sanitizeOriginalName(filename: string): string {
    return filename
      .replace(/[^\w\s.-]/gi, '_') // Replace special chars with underscore
      .replace(/\s+/g, '_') // Replace spaces with underscore
      .replace(/_+/g, '_') // Replace multiple underscores with single
      .replace(/^_+|_+$/g, '') // Remove leading/trailing underscores
      .substring(0, 255); // Limit length
  }

  /**
   * Check if file extension is allowed
   */
  static isAllowedExtension(filename: string): boolean {
    const allowedExtensions = ['jpg', 'jpeg'];
    const extension = this.extractExtension(filename);
    return allowedExtensions.includes(extension);
  }
}
