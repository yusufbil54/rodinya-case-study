import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength, MaxLength, Matches } from 'class-validator';

export class RegisterDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    format: 'email',
  })
  @IsEmail({}, { message: 'Please enter a valid email address' })
  email!: string;

  @ApiProperty({
    description: 'User password (8-50 characters, must include uppercase, lowercase, number)',
    example: 'SecurePass123',
    minLength: 8,
    maxLength: 50,
  })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(50, { message: 'Password must not exceed 50 characters' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]/,
    {
      message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number',
    },
  )
  password!: string;
}
