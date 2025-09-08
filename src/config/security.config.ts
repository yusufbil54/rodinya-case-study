import { ConfigService } from '@nestjs/config';

export interface HelmetConfig {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: string[];
      styleSrc: string[];
      scriptSrc: string[];
      imgSrc: string[];
      fontSrc: string[];
      connectSrc: string[];
      objectSrc: string[];
      frameSrc: string[];
    };
  };
  crossOriginEmbedderPolicy: boolean;
  hsts: {
    maxAge: number;
    includeSubDomains: boolean;
    preload: boolean;
  };
  noSniff: boolean;
  frameguard: {
    action: string;
  };
  xssFilter: boolean;
  referrerPolicy: {
    policy: string;
  };
}

export const getHelmetConfig = (configService: ConfigService) => ({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Required for Swagger
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  frameguard: {
    action: 'deny',
  },
  xssFilter: true,
  referrerPolicy: 'same-origin',

});

export interface SecurityConfig {
  maxFileSize: number;
  uploadDir: string;
  jwtAccessSecret: string;
  jwtRefreshSecret: string;
  accessExpiresIn: string;
  refreshExpiresIn: string;
  aesRefreshKey: string;
  ipBanThreshold: number;
  ipBanMinutes: number;
  trustProxy: boolean;
}

export const getSecurityConfig = (configService: ConfigService): SecurityConfig => ({
  maxFileSize: parseInt(configService.getOrThrow('MAX_FILE_SIZE'), 10),
  uploadDir: configService.getOrThrow('UPLOAD_DIR'),
  jwtAccessSecret: configService.getOrThrow('JWT_ACCESS_SECRET'),
  jwtRefreshSecret: configService.getOrThrow('JWT_REFRESH_SECRET'),
  accessExpiresIn: configService.getOrThrow('ACCESS_EXPIRES_IN'),
  refreshExpiresIn: configService.getOrThrow('REFRESH_EXPIRES_IN'),
  aesRefreshKey: configService.getOrThrow('AES_REFRESH_KEY'),
  ipBanThreshold: parseInt(configService.getOrThrow('IP_BAN_THRESHOLD'), 10),
  ipBanMinutes: parseInt(configService.getOrThrow('IP_BAN_MINUTES'), 10),
  trustProxy: configService.getOrThrow('TRUST_PROXY'),
});
