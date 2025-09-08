import {
  Controller,
  Post,
  Get,
  Delete,
  Param,
  Body,
  Query,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  Res,
  HttpCode,
  HttpStatus,
  ParseIntPipe,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import type { Response } from 'express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiConsumes,
  ApiBody,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { MediaService } from './media.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { User } from '../common/decorators/user.decorator';
import type { RequestUser } from '../common/types/jwt-payload';
import { ParseObjectIdPipe } from '../common/pipes/parse-objectid.pipe';
import { AddUserPermissionDto } from './dtos/permission.dto';
import { createMulterOptions } from './upload/multer.options';

@ApiTags('media')
@Controller('media')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class MediaController {
  constructor(
    private readonly mediaService: MediaService,
    private readonly configService: ConfigService,
  ) { }

  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Upload media file',
    description: 'Upload a JPEG image file. File is validated for JPEG format using magic numbers.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
          description: 'JPEG image file to upload (max 5MB)',
        },
      },
      required: ['file'],
    },
  })
  @ApiResponse({
    status: 201,
    description: 'File uploaded successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            id: { type: 'string', example: '507f1f77bcf86cd799439011' },
            fileName: { type: 'string', example: 'photo.jpg' },
            storedName: { type: 'string', example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890.jpg' },
            size: { type: 'number', example: 1048576 },
            mimeType: { type: 'string', example: 'image/jpeg' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/media/upload' },
        method: { type: 'string', example: 'POST' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid file format or validation failed',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid JWT token',
  })
  @ApiResponse({
    status: 413,
    description: 'Payload too large - File exceeds size limit',
  })
  async uploadFile(
    @UploadedFile() file: Express.Multer.File,
    @User() user: RequestUser,
  ) {
    if (!file) {
      throw new BadRequestException('No file uploaded');
    }
    return this.mediaService.uploadMedia(file, user);
  }

  @Get('my')
  @ApiOperation({
    summary: 'Get my media files',
    description: 'Retrieve paginated list of media files owned by the authenticated user',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default: 1)',
    example: 1,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page (default: 10, max: 50)',
    example: 10,
  })
  @ApiResponse({
    status: 200,
    description: 'Media list retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            media: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string', example: '507f1f77bcf86cd799439011' },
                  fileName: { type: 'string', example: 'photo.jpg' },
                  storedName: { type: 'string', example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890.jpg' },
                  size: { type: 'number', example: 1048576 },
                  mimeType: { type: 'string', example: 'image/jpeg' },
                  allowedUserIds: { type: 'array', items: { type: 'string' } },
                  createdAt: { type: 'string', format: 'date-time' },
                  updatedAt: { type: 'string', format: 'date-time' },
                },
              },
            },
            total: { type: 'number', example: 25 },
            page: { type: 'number', example: 1 },
            limit: { type: 'number', example: 10 },
            totalPages: { type: 'number', example: 3 },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/media/my' },
        method: { type: 'string', example: 'GET' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid JWT token',
  })
  async getMyMedia(
    @User() user: RequestUser,
    @Query('page', new ParseIntPipe({ optional: true })) page = 1,
    @Query('limit', new ParseIntPipe({ optional: true })) limit = 10,
  ) {
    // Limit max items per page
    const maxLimit = Math.min(limit, 50);
    return this.mediaService.getMyMedia(user, page, maxLimit);
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get media metadata',
    description: 'Retrieve metadata for a specific media file (if user has access)',
  })
  @ApiParam({
    name: 'id',
    description: 'Media file ID',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiResponse({
    status: 200,
    description: 'Media metadata retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            id: { type: 'string', example: '507f1f77bcf86cd799439011' },
            ownerId: { type: 'string', example: '507f1f77bcf86cd799439012' },
            fileName: { type: 'string', example: 'photo.jpg' },
            storedName: { type: 'string', example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890.jpg' },
            filePath: { type: 'string', example: './uploads/a1b2c3d4-e5f6-7890-abcd-ef1234567890.jpg' },
            size: { type: 'number', example: 1048576 },
            mimeType: { type: 'string', example: 'image/jpeg' },
            allowedUserIds: { type: 'array', items: { type: 'string' } },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/media/507f1f77bcf86cd799439011' },
        method: { type: 'string', example: 'GET' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - No access to this media file',
  })
  @ApiResponse({
    status: 404,
    description: 'Media not found',
  })
  async getMediaById(
    @Param('id', ParseObjectIdPipe) id: string,
    @User() user: RequestUser,
  ) {
    return this.mediaService.getMediaById(id, user);
  }

  @Get(':id/download')
  @ApiOperation({
    summary: 'Download media file',
    description: 'Download the actual media file (if user has access). Returns file stream with proper headers.',
  })
  @ApiParam({
    name: 'id',
    description: 'Media file ID',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiResponse({
    status: 200,
    description: 'File downloaded successfully',
    headers: {
      'Content-Type': {
        description: 'MIME type of the file',
        schema: { type: 'string', example: 'image/jpeg' },
      },
      'Content-Disposition': {
        description: 'File download information',
        schema: { type: 'string', example: 'attachment; filename="photo.jpg"' },
      },
      'Content-Length': {
        description: 'File size in bytes',
        schema: { type: 'string', example: '1048576' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - No access to this media file',
  })
  @ApiResponse({
    status: 404,
    description: 'Media not found',
  })
  async downloadMedia(
    @Param('id', ParseObjectIdPipe) id: string,
    @User() user: RequestUser,
    @Res() res: Response,
  ) {
    const { stream, media } = await this.mediaService.getMediaStream(id, user);

    res.set({
      'Content-Type': media.mimeType,
      'Content-Disposition': `attachment; filename="${media.fileName}"`,
      'Content-Length': media.size.toString(),
      'Cache-Control': 'private, max-age=3600', // 1 hour cache
    });

    stream.pipe(res);
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Delete media file',
    description: 'Delete a media file (owner or admin only). Removes both database record and file from storage.',
  })
  @ApiParam({
    name: 'id',
    description: 'Media file ID',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiResponse({
    status: 200,
    description: 'Media deleted successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            message: { type: 'string', example: 'Media deleted successfully' },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/media/507f1f77bcf86cd799439011' },
        method: { type: 'string', example: 'DELETE' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Only owner or admin can delete',
  })
  @ApiResponse({
    status: 404,
    description: 'Media not found',
  })
  async deleteMedia(
    @Param('id', ParseObjectIdPipe) id: string,
    @User() user: RequestUser,
  ) {
    return this.mediaService.deleteMedia(id, user);
  }

  @Get(':id/permissions')
  @ApiOperation({
    summary: 'Get media permissions',
    description: 'Get list of users who have access to the media file (owner or admin only)',
  })
  @ApiParam({
    name: 'id',
    description: 'Media file ID',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiResponse({
    status: 200,
    description: 'Media permissions retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            allowedUsers: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string', example: '507f1f77bcf86cd799439013' },
                  email: { type: 'string', example: 'user@example.com' },
                  role: { type: 'string', enum: ['user', 'admin'], example: 'user' },
                },
              },
            },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/media/507f1f77bcf86cd799439011/permissions' },
        method: { type: 'string', example: 'GET' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Only owner or admin can view permissions',
  })
  @ApiResponse({
    status: 404,
    description: 'Media not found',
  })
  async getMediaPermissions(
    @Param('id', ParseObjectIdPipe) id: string,
    @User() user: RequestUser,
  ) {
    return this.mediaService.getMediaPermissions(id, user);
  }

  @Post(':id/permissions')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Add user permission to media',
    description: 'Grant access to a specific user for a media file. Only owner or admin can manage permissions.',
  })
  @ApiParam({
    name: 'id',
    description: 'Media file ID',
    example: '507f1f77bcf86cd799439011',
  })
  @ApiBody({
    type: AddUserPermissionDto,
    description: 'User ID to grant access to this media file',
    examples: {
      example1: {
        summary: 'Grant access to user',
        description: 'Grant access to a specific user for the media file',
        value: {
          userId: '507f1f77bcf86cd799439011'
        }
      }
    }
  })
  @ApiResponse({
    status: 200,
    description: 'User permission added successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            message: { type: 'string', example: 'User access granted successfully' },
            userId: { type: 'string', example: '507f1f77bcf86cd799439011' },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/media/507f1f77bcf86cd799439011/permissions' },
        method: { type: 'string', example: 'POST' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid user ID or user already has access',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid JWT token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Not the owner or admin of the media',
  })
  @ApiResponse({
    status: 404,
    description: 'Media or user not found',
  })
  async addUserPermission(
    @Param('id', ParseObjectIdPipe) id: string,
    @Body() addUserPermissionDto: AddUserPermissionDto,
    @User() user: RequestUser,
  ) {
    await this.mediaService.addUserPermission(
      id,
      addUserPermissionDto.userId,
      user,
    );

    return {
      success: true,
      data: {
        message: 'User access granted successfully',
        userId: addUserPermissionDto.userId,
      },
      timestamp: new Date().toISOString(),
      path: `/media/${id}/permissions`,
      method: 'POST',
    };
  }

}
