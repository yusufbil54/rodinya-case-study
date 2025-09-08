import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Model, Types } from 'mongoose';
import { MediaService } from './media.service';
import { Media, MediaDocument } from './schemas/media.schema';
import { UsersService } from '../users/users.service';
import { RequestUser } from '../common/types/jwt-payload';

describe('MediaService', () => {
  let mediaService: MediaService;
  let mediaModel: jest.Mocked<Model<MediaDocument>>;
  let usersService: jest.Mocked<UsersService>;

  const mockUser: RequestUser = {
    id: '507f1f77bcf86cd799439011',
    role: 'user',
    tokenVersion: 0,
  };

  const mockAdminUser: RequestUser = {
    id: '507f1f77bcf86cd799439012',
    role: 'admin',
    tokenVersion: 0,
  };

  const mockMedia = {
    _id: new Types.ObjectId('507f1f77bcf86cd799439013'),
    ownerId: new Types.ObjectId(mockUser.id),
    fileName: 'test.jpg',
    storedName: 'uuid-test.jpg',
    filePath: 'uploads/uuid-test.jpg',
    mimeType: 'image/jpeg',
    size: 1024,
    allowedUserIds: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MediaService,
        {
          provide: getModelToken(Media.name),
          useValue: {
            find: jest.fn(),
            findById: jest.fn(),
            findByIdAndDelete: jest.fn(),
            countDocuments: jest.fn(),
            aggregate: jest.fn(),
            prototype: {
              save: jest.fn(),
            },
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('uploads'),
          },
        },
        {
          provide: UsersService,
          useValue: {
            findById: jest.fn(),
          },
        },
      ],
    }).compile();

    mediaService = module.get<MediaService>(MediaService);
    mediaModel = module.get(getModelToken(Media.name));
    usersService = module.get(UsersService);
  });

  describe('canAccessMedia', () => {
    it('should allow admin to access any media', () => {
      const result = mediaService.canAccessMedia(mockAdminUser, mockMedia as any);
      expect(result).toBe(true);
    });

    it('should allow owner to access their media', () => {
      const result = mediaService.canAccessMedia(mockUser, mockMedia as any);
      expect(result).toBe(true);
    });

    it('should allow user in allowedUserIds to access media', () => {
      const mediaWithPermission = {
        ...mockMedia,
        ownerId: new Types.ObjectId('507f1f77bcf86cd799439099'),
        allowedUserIds: [new Types.ObjectId(mockUser.id)],
      };

      const result = mediaService.canAccessMedia(mockUser, mediaWithPermission as any);
      expect(result).toBe(true);
    });

    it('should deny access to user not in allowedUserIds and not owner', () => {
      const mediaWithoutPermission = {
        ...mockMedia,
        ownerId: new Types.ObjectId('507f1f77bcf86cd799439099'),
        allowedUserIds: [],
      };

      const result = mediaService.canAccessMedia(mockUser, mediaWithoutPermission as any);
      expect(result).toBe(false);
    });
  });

  describe('getMediaById', () => {
    it('should return media if user has access', async () => {
      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mockMedia),
      } as any);

      const result = await mediaService.getMediaById(mockMedia._id.toString(), mockUser);
      expect(result).toEqual(mockMedia);
    });

    it('should throw NotFoundException if media does not exist', async () => {
      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(null),
      } as any);

      await expect(
        mediaService.getMediaById(mockMedia._id.toString(), mockUser),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException if user has no access', async () => {
      const mediaWithoutPermission = {
        ...mockMedia,
        ownerId: new Types.ObjectId('507f1f77bcf86cd799439099'),
        allowedUserIds: [],
      };

      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mediaWithoutPermission),
      } as any);

      await expect(
        mediaService.getMediaById(mockMedia._id.toString(), mockUser),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('manageMediaPermission', () => {
    const targetUserId = '507f1f77bcf86cd799439014';
    const mockTargetUser = { _id: targetUserId };

    beforeEach(() => {
      usersService.findById.mockResolvedValue(mockTargetUser as any);
    });

    it('should add user to allowedUserIds', async () => {
      const mediaMock = {
        ...mockMedia,
        allowedUserIds: [],
        save: jest.fn().mockResolvedValue(mockMedia),
      };

      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mediaMock),
      } as any);

      const result = await mediaService.manageMediaPermission(
        mockMedia._id.toString(),
        targetUserId,
        'add',
        mockUser,
      );

      expect(result).toEqual({ message: 'Access granted successfully' });
      expect(mediaMock.allowedUserIds).toContainEqual(new Types.ObjectId(targetUserId));
      expect(mediaMock.save).toHaveBeenCalled();
    });

    it('should remove user from allowedUserIds', async () => {
      const mediaMock = {
        ...mockMedia,
        allowedUserIds: [new Types.ObjectId(targetUserId)],
        save: jest.fn().mockResolvedValue(mockMedia),
      };

      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mediaMock),
      } as any);

      const result = await mediaService.manageMediaPermission(
        mockMedia._id.toString(),
        targetUserId,
        'remove',
        mockUser,
      );

      expect(result).toEqual({ message: 'Access revoked successfully' });
      expect(mediaMock.allowedUserIds).not.toContainEqual(new Types.ObjectId(targetUserId));
      expect(mediaMock.save).toHaveBeenCalled();
    });

    it('should throw ForbiddenException if not owner or admin', async () => {
      const mediaWithoutPermission = {
        ...mockMedia,
        ownerId: new Types.ObjectId('507f1f77bcf86cd799439099'),
      };

      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mediaWithoutPermission),
      } as any);

      await expect(
        mediaService.manageMediaPermission(
          mockMedia._id.toString(),
          targetUserId,
          'add',
          mockUser,
        ),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw NotFoundException if target user does not exist', async () => {
      usersService.findById.mockResolvedValue(null);
      
      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mockMedia),
      } as any);

      await expect(
        mediaService.manageMediaPermission(
          mockMedia._id.toString(),
          targetUserId,
          'add',
          mockUser,
        ),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteMedia', () => {
    it('should allow owner to delete media', async () => {
      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mockMedia),
      } as any);
      
      mediaModel.findByIdAndDelete.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mockMedia),
      } as any);

      // Mock file deletion
      jest.spyOn(require('../common/utils/file.util'), 'FileUtil').mockImplementation(() => ({
        deleteFile: jest.fn().mockResolvedValue(undefined),
      }));

      const result = await mediaService.deleteMedia(mockMedia._id.toString(), mockUser);
      expect(result).toEqual({ message: 'Media deleted successfully' });
    });

    it('should allow admin to delete any media', async () => {
      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mockMedia),
      } as any);
      
      mediaModel.findByIdAndDelete.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mockMedia),
      } as any);

      const result = await mediaService.deleteMedia(mockMedia._id.toString(), mockAdminUser);
      expect(result).toEqual({ message: 'Media deleted successfully' });
    });

    it('should throw ForbiddenException if not owner or admin', async () => {
      const mediaWithoutPermission = {
        ...mockMedia,
        ownerId: new Types.ObjectId('507f1f77bcf86cd799439099'),
      };

      mediaModel.findById.mockReturnValue({
        exec: jest.fn().mockResolvedValue(mediaWithoutPermission),
      } as any);

      await expect(
        mediaService.deleteMedia(mockMedia._id.toString(), mockUser),
      ).rejects.toThrow(ForbiddenException);
    });
  });
});
