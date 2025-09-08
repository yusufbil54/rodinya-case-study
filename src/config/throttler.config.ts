import { ThrottlerModuleOptions } from '@nestjs/throttler';

export const getThrottlerConfig = (): ThrottlerModuleOptions => ({
  throttlers: [
    {
      name: 'default',
      ttl: 60000, // 60 seconds
      limit: 30,  // 30 requests per minute
    }
  ]
});
