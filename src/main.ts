import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import hpp from 'hpp';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { setupSwagger } from './config/swagger.config';
import { getCorsConfig } from './config/cors.config';
import { getHelmetConfig } from './config/security.config';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  const configService = app.get(ConfigService);

  // Trust proxy settings
  const trustProxy = configService.getOrThrow('TRUST_PROXY');
  if (trustProxy) {
    (app as any).set('trust proxy', 1);
    logger.log('Trust proxy enabled');
  }

  // Security headers with Helmet
  app.use(helmet());
  logger.log('Helmet security headers configured');

  // HTTP Parameter Pollution protection
  app.use(hpp());
  logger.log('HPP protection enabled');

  // Cookie parser
  app.use(cookieParser());
  logger.log('Cookie parser enabled');

  // CORS configuration
  const corsConfig = getCorsConfig(configService);
  app.enableCors(corsConfig);
  logger.log('CORS configured');

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      disableErrorMessages: process.env.NODE_ENV === 'production',
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );
  logger.log('Global validation pipe configured');

  // Global exception filter
  app.useGlobalFilters(new HttpExceptionFilter());
  logger.log('Global exception filter configured');

  // Global interceptors
  app.useGlobalInterceptors(
    new LoggingInterceptor(),
    new ResponseInterceptor(),
  );
  logger.log('Global interceptors configured');

  // Swagger documentation
  if (process.env.NODE_ENV !== 'production') {
    setupSwagger(app);
    logger.log('Swagger documentation enabled at /docs');
  }

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    logger.log('SIGTERM signal received: closing HTTP server');
    await app.close();
  });

  process.on('SIGINT', async () => {
    logger.log('SIGINT signal received: closing HTTP server');
    await app.close();
  });

  const port = configService.getOrThrow('PORT');
  await app.listen(port);
  
  logger.log(`🚀 Application is running on port ${port}`);
  
  if (process.env.NODE_ENV !== 'production') {
    logger.log(`📚 Swagger documentation: http://localhost:${port}/docs`);
  }
}

bootstrap().catch((error) => {
  console.error('Failed to start application:', error);
  process.exit(1);
});
