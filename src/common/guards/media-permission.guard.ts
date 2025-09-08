import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  NotFoundException,
  Inject,
} from '@nestjs/common';
import { REQUEST } from '@nestjs/core';
import { RequestUser } from '../types/jwt-payload';

export interface MediaDocument {
  _id: any;
  ownerId: any;
  allowedUserIds: any[];
}

export interface MediaPermissionRequest extends Request {
  user: RequestUser;
  media?: MediaDocument;
}

@Injectable()
export class MediaPermissionGuard implements CanActivate {
  constructor(@Inject(REQUEST) private request: MediaPermissionRequest) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<MediaPermissionRequest>();
    const { user, media } = request;

    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    if (!media) {
      throw new NotFoundException('Media not found');
    }

    return this.canAccessMedia(user, media);
  }

  private canAccessMedia(user: RequestUser, media: MediaDocument): boolean {
    // Admin has access to everything
    if (user.role === 'admin') {
      return true;
    }

    // Owner has access
    if (media.ownerId.toString() === user.id) {
      return true;
    }

    // User in allowed list has access
    const isAllowed = media.allowedUserIds.some(
      (allowedId) => allowedId.toString() === user.id,
    );

    if (!isAllowed) {
      throw new ForbiddenException('Access denied to this media file');
    }

    return true;
  }
}
