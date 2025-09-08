import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class AddUserPermissionDto {
  @ApiProperty({
    description: 'User ID to grant access to this media',
    example: '507f1f77bcf86cd799439011',
  })
  @IsString()
  @IsNotEmpty({ message: 'User ID is required' })
  userId!: string;
}
