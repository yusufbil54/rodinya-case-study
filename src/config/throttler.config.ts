import { ThrottlerModuleOptions } from '@nestjs/throttler';
import { ConfigService } from '@nestjs/config';

export const getThrottlerConfig = (configService: ConfigService): ThrottlerModuleOptions => ({
  throttlers: [
    {
      name: 'default',
      ttl: parseInt(configService.getOrThrow('THROTTLE_TTL'), 10), // milliseconds
      limit: parseInt(configService.getOrThrow('THROTTLE_LIMIT'), 10), // requests per ttl
    }
  ]
});
