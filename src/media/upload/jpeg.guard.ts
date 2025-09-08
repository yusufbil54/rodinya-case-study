import { Injectable, CanActivate, ExecutionContext, BadRequestException } from '@nestjs/common';
import * as fs from 'fs';

@Injectable()
export class JpegValidationGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const file = request.file;
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }

    try {
      // Read the file content
      const buffer = await fs.promises.readFile(file.path);
      
      // Dynamic import for file-type
      const { fileTypeFromBuffer } = await import('file-type');
      
      // Verify magic number
      const fileType = await fileTypeFromBuffer(buffer);
      
      if (!fileType || fileType.mime !== 'image/jpeg') {
        // Clean up invalid file
        await fs.promises.unlink(file.path).catch(() => {});
        throw new BadRequestException('File is not a valid JPEG image');
      }

      // Additional JPEG header validation
      if (!this.isValidJpegHeader(buffer)) {
        await fs.promises.unlink(file.path).catch(() => {});
        throw new BadRequestException('Invalid JPEG file structure');
      }

      return true;
    } catch (error) {
      // Clean up file on any error
      if (file.path) {
        await fs.promises.unlink(file.path).catch(() => {});
      }
      
      if (error instanceof BadRequestException) {
        throw error;
      }
      
      throw new BadRequestException('File validation failed');
    }
  }

  private isValidJpegHeader(buffer: Buffer): boolean {
    // JPEG files start with FF D8 and end with FF D9
    if (buffer.length < 4) {
      return false;
    }

    // Check JPEG magic number (SOI - Start of Image)
    const startsWithJpegMagic = buffer[0] === 0xFF && buffer[1] === 0xD8;
    
    // Check for JFIF or Exif markers
    const hasValidMarker = 
      (buffer[6] === 0x4A && buffer[7] === 0x46 && buffer[8] === 0x49 && buffer[9] === 0x46) || // JFIF
      (buffer[6] === 0x45 && buffer[7] === 0x78 && buffer[8] === 0x69 && buffer[9] === 0x66); // Exif

    return startsWithJpegMagic && hasValidMarker;
  }   
}
