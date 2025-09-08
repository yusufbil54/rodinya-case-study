import { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface';
import { ConfigService } from '@nestjs/config';

export const getCorsConfig = (configService: ConfigService): CorsOptions => {
  const origins = '';
  
  return {
    origin: origins.split(',').map(origin => origin.trim()).filter(Boolean),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Accept',
      'Accept-Version',
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-Forwarded-For',
      'X-Real-IP',
    ],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
    maxAge: 86400, // 24 hours
  };
};
