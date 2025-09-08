import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { MulterModule } from '@nestjs/platform-express';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MediaController } from './media.controller';
import { MediaService } from './media.service';
import { Media, MediaSchema } from './schemas/media.schema';
import { UsersModule } from '../users/users.module';
import { createMulterOptions } from './upload/multer.options';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Media.name, schema: MediaSchema }]),
    MulterModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => createMulterOptions(configService),
      inject: [ConfigService],
    }),
    UsersModule,
  ],
  controllers: [MediaController],
  providers: [MediaService],
  exports: [MediaService],
})
export class MediaModule {}
