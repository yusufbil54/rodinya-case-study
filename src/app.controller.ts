import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';
import { Public } from './common/decorators/public.decorator';

@ApiTags('root')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Public()
  @ApiOperation({
    summary: 'Welcome message',
    description: 'Returns a welcome message for the API',
  })
  @ApiResponse({
    status: 200,
    description: 'Welcome message',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            message: { type: 'string', example: 'Welcome to Media Library API!' },
            version: { type: 'string', example: '1.0.0' },
            documentation: { type: 'string', example: '/docs' },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/' },
        method: { type: 'string', example: 'GET' },
      },
    },
  })
  getWelcome() {
    return this.appService.getWelcome();
  }
}
