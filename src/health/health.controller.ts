import { Controller, Get } from '@nestjs/common';
import {
  HealthCheckService,
  MongooseHealthIndicator,
  HealthCheck,
  DiskHealthIndicator,
  MemoryHealthIndicator,
} from '@nestjs/terminus';
import { ConfigService } from '@nestjs/config';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Public } from '../common/decorators/public.decorator';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private mongoose: MongooseHealthIndicator,
    private disk: DiskHealthIndicator,
    private memory: MemoryHealthIndicator,
    private configService: ConfigService,
  ) {}

  @Get()
  @Public()
  @HealthCheck()
  @ApiOperation({
    summary: 'Health check',
    description: 'Check the health status of the application and its dependencies',
  })
  @ApiResponse({
    status: 200,
    description: 'Health check passed',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'ok' },
        info: {
          type: 'object',
          properties: {
            mongodb: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'up' },
              },
            },
            disk: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'up' },
                free: { type: 'number', example: 1073741824 },
                total: { type: 'number', example: 10737418240 },
                percentage: { type: 'number', example: 10 },
              },
            },
            memory: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'up' },
                used: { type: 'number', example: 134217728 },
                total: { type: 'number', example: 1073741824 },
                percentage: { type: 'number', example: 12.5 },
              },
            },
          },
        },
        error: { type: 'object' },
        details: {
          type: 'object',
          properties: {
            mongodb: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'up' },
              },
            },
            disk: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'up' },
                free: { type: 'number', example: 1073741824 },
                total: { type: 'number', example: 10737418240 },
                percentage: { type: 'number', example: 10 },
              },
            },
            memory: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'up' },
                used: { type: 'number', example: 134217728 },
                total: { type: 'number', example: 1073741824 },
                percentage: { type: 'number', example: 12.5 },
              },
            },
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 503,
    description: 'Health check failed',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'error' },
        info: { type: 'object' },
        error: {
          type: 'object',
          properties: {
            mongodb: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'down' },
                message: { type: 'string', example: 'Connection failed' },
              },
            },
          },
        },
        details: { type: 'object' },
      },
    },
  })
  check() {
    return this.health.check([
      // MongoDB health check
      () => this.mongoose.pingCheck('mongodb'),
      
      // Disk space health check (uploads directory)
      () => this.disk.checkStorage('disk', {
        path: this.configService.getOrThrow('UPLOAD_DIR'),
        thresholdPercent: 0.9, // 90% threshold
      }),
      
      // Memory health check
      () => this.memory.checkHeap('memory', 150 * 1024 * 1024), // 150MB threshold
    ]);
  }

}
