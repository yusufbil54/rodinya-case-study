import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getWelcome() {
    return {
      message: 'Welcome to Media Library API!',
      version: '1.0.0',
      documentation: '/docs',
      endpoints: {
        health: '/health',
        auth: '/auth',
        users: '/users',
        media: '/media',
      },
    };
  }
}
