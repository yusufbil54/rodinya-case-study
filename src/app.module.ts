import { Module, Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { MediaModule } from './media/media.module';
import { HealthModule } from './health/health.module';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { RolesGuard } from './common/guards/roles.guard';
import { getThrottlerConfig } from './config/throttler.config';

@Module({
  imports: [
    // Configuration module
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env'],
      validationOptions: {
        allowUnknown: true,
        abortEarly: true,
      },
    }),

    // MongoDB connection
    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        const logger = new Logger('MongoDB');
        const uri = configService.getOrThrow<string>('MONGO_URI');
        return {
          uri,
          retryWrites: true,
          w: 'majority',
          maxPoolSize: 10,
          serverSelectionTimeoutMS: 5000,
          socketTimeoutMS: 45000,
          connectionFactory: (connection) => {
            connection.on('connected', () => {
              logger.log('✅ MongoDB connection established successfully');
            });
            connection.on('error', (error: Error) => {
              logger.error('❌ MongoDB connection error:', error);
            });
            connection.on('disconnected', () => {
              logger.warn('⚠️ MongoDB disconnected');
            });
            return connection;
          },
        };
      },
    }),

    // Throttler module
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: getThrottlerConfig,
    }),

    // Feature modules
    AuthModule,
    UsersModule,
    MediaModule,
    HealthModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    // Global guards
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AppModule {}
