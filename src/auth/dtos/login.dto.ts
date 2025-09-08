import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    format: 'email',
  })
  @IsEmail({}, { message: 'Please enter a valid email address' })
  email!: string;

  @ApiProperty({
    description: 'User password',
    example: 'SecurePass123',
  })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  password!: string;
}
