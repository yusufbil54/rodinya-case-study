import { MulterOptions } from '@nestjs/platform-express/multer/interfaces/multer-options.interface';
import { diskStorage } from 'multer';
import { ConfigService } from '@nestjs/config';
import { BadRequestException } from '@nestjs/common';
import { FileUtil } from '../../common/utils/file.util';

export const createMulterOptions = (configService: ConfigService): MulterOptions => {
  const uploadDir = configService.getOrThrow('UPLOAD_DIR');
  const maxFileSize = parseInt(configService.getOrThrow('MAX_FILE_SIZE'), 10);

  return {
    storage: diskStorage({
      destination: async (req, file, cb) => {
        try {
          await FileUtil.ensureDir(uploadDir);
          cb(null, uploadDir);
        } catch (error) {
          cb(error as Error, '');
        }
      },
      filename: (req, file, cb) => {
        try {
          const uniqueFileName = FileUtil.generateUniqueFilename(file.originalname);
          cb(null, uniqueFileName);
        } catch (error) {
          cb(error as Error, '');
        }
      },
    }),
    limits: {
      fileSize: maxFileSize,
      files: 1,
    },
    fileFilter: (req, file, cb) => {
      // Basic MIME type check (will be verified again with magic numbers)
      if (file.mimetype !== 'image/jpeg') {
        return cb(new BadRequestException('Only JPEG images are allowed'), false);
      }

      // Basic filename validation
      if (!file.originalname || file.originalname.trim() === '') {
        return cb(new BadRequestException('Invalid filename'), false);
      }

      cb(null, true);
    },
  };
};
