import { 
  Injectable, 
  NotFoundException, 
  ForbiddenException, 
  BadRequestException,
  Logger 
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import * as fs from 'fs';
import * as path from 'path';
import { ConfigService } from '@nestjs/config';
import { Media, MediaDocument } from './schemas/media.schema';
import { RequestUser } from '../common/types/jwt-payload';
import { UsersService } from '../users/users.service';
import { FileUtil } from '../common/utils/file.util';

export interface MediaUploadResult {
  id: string;
  fileName: string;
  storedName: string;
  size: number;
  mimeType: string;
  createdAt: Date;
}

export interface MediaListResult {
  media: MediaDocument[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

@Injectable()
export class MediaService {
  private readonly logger = new Logger(MediaService.name);
  private readonly uploadDir: string;

  constructor(
    @InjectModel(Media.name) private mediaModel: Model<MediaDocument>,
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    this.uploadDir = this.configService.getOrThrow('UPLOAD_DIR');
  }

  async uploadMedia(file: Express.Multer.File, user: RequestUser): Promise<MediaUploadResult> {
    try {
      // Validate JPEG file
      await this.validateJpegFile(file);
      
      let storedName: string;
      let filePath: string;
      
      // Check if file is already on disk (disk storage) or in memory (memory storage)
      if (file.path && file.filename) {
        // File is already on disk, just use its path
        storedName = file.filename;
        filePath = file.path;
      } else if (file.buffer) {
        // If file is in memory (buffer), save it to disk
        storedName = FileUtil.generateUniqueFilename(file.originalname);
        filePath = path.join(this.uploadDir, storedName);
        
        // Ensure upload directory exists
        await FileUtil.ensureDir(this.uploadDir);
        
        // Save file to disk
        await fs.promises.writeFile(filePath, file.buffer);
      } else {
        // If neither path nor buffer is available
        throw new BadRequestException('Invalid file upload');
      }
      
      // Create media document
      const media = new this.mediaModel({
        ownerId: new Types.ObjectId(user.id),
        fileName: FileUtil.sanitizeFilename(file.originalname),
        storedName: storedName,
        filePath: filePath,
        mimeType: 'image/jpeg',
        size: file.size,
        allowedUserIds: [],
      });
      
      const savedMedia = await media.save();
      
      this.logger.log(`Media uploaded: ${savedMedia.storedName} by user ${user.id}`);
      
      return {
        id: (savedMedia as any)._id.toString(),
        fileName: savedMedia.fileName,
        storedName: savedMedia.storedName,
        size: savedMedia.size,
        mimeType: savedMedia.mimeType,
        createdAt: savedMedia.createdAt,
      };
    } catch (error) {
      // Clean up file on any error
      if (file.path) {
        await fs.promises.unlink(file.path).catch(() => {});
      }
      
      this.logger.error(`Media upload failed: ${(error as Error).message}`);
      throw new BadRequestException('Failed to upload media');
    }
  }

  async getMyMedia(
    user: RequestUser,
    page = 1,
    limit = 10,
  ): Promise<MediaListResult> {
    const skip = (page - 1) * limit;

    const query = {
      ownerId: new Types.ObjectId(user.id)
    };

    const [media, total] = await Promise.all([
      this.mediaModel
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .exec(),
      this.mediaModel.countDocuments(query),
    ]);

    const totalPages = Math.ceil(total / limit);

    return {
      media,
      total,
      page,
      limit,
      totalPages,
    };
  }

  async getMediaById(id: string, user: RequestUser): Promise<MediaDocument> {
    const media = await this.mediaModel.findById(id).exec();

    if (!media) {
      throw new NotFoundException('Media not found');
    }

    if (!this.canAccessMedia(media, user)) {
      throw new ForbiddenException('You do not have permission to access this media');
    }

    return media;
  }

  async downloadMedia(id: string, user: RequestUser): Promise<{
    file: string;
    fileName: string;
    mimeType: string;
  }> {
    const media = await this.getMediaById(id, user);

    return {
      file: media.filePath,
      fileName: media.fileName,
      mimeType: media.mimeType,
    };
  }
  
  async getMediaStream(id: string, user: RequestUser): Promise<{
    stream: fs.ReadStream;
    media: MediaDocument;
  }> {
    const media = await this.getMediaById(id, user);
    
    // Check if file exists
    const fileExists = await FileUtil.fileExists(media.filePath);
    if (!fileExists) {
      throw new NotFoundException('Media file not found on disk');
    }
    
    // Create read stream
    const stream = fs.createReadStream(media.filePath);
    
    return { stream, media };
  }

  async deleteMedia(id: string, user: RequestUser): Promise<void> {
    const media = await this.mediaModel.findById(id).exec();

    if (!media) {
      throw new NotFoundException('Media not found');
    }

    // Only the owner or admin can delete media
    const isOwner = media.ownerId.toString() === user.id;
    const isAdmin = user.role === 'admin';
    
    if (!isOwner && !isAdmin) {
      throw new ForbiddenException('You do not have permission to delete this media');
    }

    // Delete file from disk
    await fs.promises.unlink(media.filePath).catch((error) => {
      this.logger.error(`Failed to delete file from disk: ${(error as Error).message}`);
    });

    // Delete from database
    await this.mediaModel.findByIdAndDelete(id).exec();
    
    this.logger.log(`Media ${id} deleted by ${isAdmin ? 'admin' : 'owner'} user ${user.id}`);
  }

  async getMediaPermissions(id: string, user: RequestUser): Promise<string[]> {
    const media = await this.getMediaById(id, user);

    // Only owner or admin can view permissions
    const isOwner = media.ownerId.toString() === user.id;
    const isAdmin = user.role === 'admin';
    
    if (!isOwner && !isAdmin) {
      throw new ForbiddenException('You do not have permission to view this media\'s permissions');
    }

    return media.allowedUserIds.map((id) => id.toString());
  }

  async addUserPermission(
    id: string,
    userId: string,
    user: RequestUser,
  ): Promise<void> {
    const media = await this.mediaModel.findById(id).exec();

    if (!media) {
      throw new NotFoundException('Media not found');
    }

    // Only owner or admin can add permissions
    const isOwner = media.ownerId.toString() === user.id;
    const isAdmin = user.role === 'admin';
    
    if (!isOwner && !isAdmin) {
      throw new ForbiddenException('You do not have permission to manage this media\'s permissions');
    }

    // Validate user ID
    const targetUser = await this.usersService.findById(userId);
    if (!targetUser) {
      throw new BadRequestException(`User with ID ${userId} does not exist`);
    }

    // Check if user already has access
    const userObjectId = new Types.ObjectId(userId);
    const alreadyHasAccess = media.allowedUserIds.some((id) => id.toString() === userId);
    
    if (alreadyHasAccess) {
      throw new BadRequestException('User already has access to this media');
    }

    // Add user to permissions
    media.allowedUserIds.push(userObjectId);
    await media.save();
    
    this.logger.log(`User ${userId} granted access to media ${id} by ${isAdmin ? 'admin' : 'owner'} user ${user.id}`);
  }
  

  canAccessMedia(media: MediaDocument, user: RequestUser): boolean {
    // Owner always has access
    if (media.ownerId.toString() === user.id) {
      return true;
    }

    // Admin always has access
    if (user.role === 'admin') {
      return true;
    }

    // Check if user is in allowed users
    return media.allowedUserIds.some((id) => id.toString() === user.id);
  }

  async getUserMediaStats(user: RequestUser): Promise<{
    totalMedia: number;
    totalSize: number;
  }> {
    const result = await this.mediaModel.aggregate([
      { $match: { ownerId: new Types.ObjectId(user.id) } },
      {
        $group: {
          _id: null,
          totalMedia: { $sum: 1 },
          totalSize: { $sum: '$size' },
        },
      },
    ]);

    return result[0] || { totalMedia: 0, totalSize: 0 };
  }

  private async validateJpegFile(file: Express.Multer.File): Promise<void> {
    try {
      // Get file buffer (multer might use memory storage)
      const buffer = file.buffer || await fs.promises.readFile(file.path);
      
      // Dynamic import for file-type
      const { fileTypeFromBuffer } = await import('file-type');
      
      // Verify magic number
      const fileType = await fileTypeFromBuffer(buffer);
      
      if (!fileType || fileType.mime !== 'image/jpeg') {
        // Clean up invalid file if it has a path
        if (file.path) {
          await fs.promises.unlink(file.path).catch(() => {});
        }
        throw new BadRequestException('File is not a valid JPEG image');
      }

      // Additional JPEG header validation
      const isValidHeader = this.isValidJpegHeader(buffer);
      
      if (!isValidHeader) {
        if (file.path) {
          await fs.promises.unlink(file.path).catch(() => {});
        }
        throw new BadRequestException('Invalid JPEG file structure');
      }
    } catch (error) {
      // Clean up file on any error if it has a path
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
    // JPEG files start with FF D8 (SOI - Start of Image)
    if (buffer.length < 2) {
      return false;
    }

    // Check JPEG magic number (SOI - Start of Image)
    const startsWithJpegMagic = buffer[0] === 0xFF && buffer[1] === 0xD8;
    
    if (!startsWithJpegMagic) {
      return false;
    }

    // Check for common JPEG markers (JFIF, Exif, or other valid markers)
    if (buffer.length >= 10) {
      // JFIF marker
      const hasJfifMarker = 
        buffer[6] === 0x4A && buffer[7] === 0x46 && buffer[8] === 0x49 && buffer[9] === 0x46;
      
      // Exif marker
      const hasExifMarker = 
        buffer[6] === 0x45 && buffer[7] === 0x78 && buffer[8] === 0x69 && buffer[9] === 0x66;
      
      // If it has JFIF or Exif marker, it's valid
      if (hasJfifMarker || hasExifMarker) {
        return true;
      }
    }

    // If no specific markers found but starts with JPEG magic, still consider valid
    // (some JPEG files might not have JFIF/Exif markers)
    return true;
  }

}