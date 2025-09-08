import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { Public } from '../common/decorators/public.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { User } from '../common/decorators/user.decorator';
import type { RequestUser } from '../common/types/jwt-payload';
import { IpUtil } from '../common/utils/ip.util';
import { ConfigService } from '@nestjs/config';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly ipUtil: IpUtil,
    private readonly configService: ConfigService,
  ) {}

  @Post('register')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new user',
    description: 'Creates a new user account with email and password',
  })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully. Refresh token is set as HttpOnly cookie.',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            user: {
              type: 'object',
              properties: {
                id: { type: 'string', example: '507f1f77bcf86cd799439011' },
                email: { type: 'string', example: 'user@example.com' },
                role: { type: 'string', enum: ['user', 'admin'], example: 'user' },
              },
            },
            tokens: {
              type: 'object',
              properties: {
                accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
              },
            },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/register' },
        method: { type: 'string', example: 'POST' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Validation failed',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 400 },
        message: { 
          type: 'array',
          items: { type: 'string' },
          example: ['Please enter a valid email address', 'Password must be at least 8 characters long']
        },
        error: { type: 'string', example: 'Bad Request' },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/register' },
        method: { type: 'string', example: 'POST' },
        correlationId: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: 409,
    description: 'User already exists',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 409 },
        message: { type: 'string', example: 'User with this email already exists' },
        error: { type: 'string', example: 'Conflict' },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/register' },
        method: { type: 'string', example: 'POST' },
        correlationId: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 429 },
        message: { type: 'string', example: 'ThrottlerException: Too Many Requests' },
        error: { type: 'string', example: 'Too Many Requests' },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/register' },
        method: { type: 'string', example: 'POST' },
        correlationId: { type: 'string' },
      },
    },
  })
  async register(@Body() registerDto: RegisterDto, @Req() req: Request, @Res() res: Response) {
    const ip = this.ipUtil.extractRealIp(req);
    const userAgent = req.get('User-Agent');
    const result = await this.authService.register(registerDto, ip, userAgent);
    
    // Set HttpOnly cookie for refresh token
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: this.configService.getOrThrow<string>('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });
    
    // Return only access token in response body
    return res.status(201).json({
      success: true,
      data: {
        user: result.user,
        tokens: {
          accessToken: result.tokens.accessToken,
        },
      },
      timestamp: new Date().toISOString(),
      path: '/auth/register',
      method: 'POST',
    });
  }

  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login user',
    description: 'Authenticates user and returns access and refresh tokens',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful. Refresh token is set as HttpOnly cookie.',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            user: {
              type: 'object',
              properties: {
                id: { type: 'string', example: '507f1f77bcf86cd799439011' },
                email: { type: 'string', example: 'user@example.com' },
                role: { type: 'string', enum: ['user', 'admin'], example: 'user' },
              },
            },
            tokens: {
              type: 'object',
              properties: {
                accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
              },
            },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/login' },
        method: { type: 'string', example: 'POST' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid credentials or IP banned',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 401 },
        message: { type: 'string', example: 'Invalid credentials' },
        error: { type: 'string', example: 'Unauthorized' },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/login' },
        method: { type: 'string', example: 'POST' },
        correlationId: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
  })
  async login(@Body() loginDto: LoginDto, @Req() req: Request, @Res() res: Response) {
    const ip = this.ipUtil.extractRealIp(req);
    const userAgent = req.get('User-Agent');
    const result = await this.authService.login(loginDto, ip, userAgent);
    
    // Set HttpOnly cookie for refresh token
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });
    
    // Return only access token in response body
    return res.json({
      success: true,
      data: {
        user: result.user,
        tokens: {
          accessToken: result.tokens.accessToken,
        },
      },
      timestamp: new Date().toISOString(),
      path: '/auth/login',
      method: 'POST',
    });
  }

  @Post('refresh')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token',
    description: 'Exchanges a valid refresh token (from HttpOnly cookie) for new access and refresh tokens. No request body needed.',
  })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            tokens: {
              type: 'object',
              properties: {
                accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
              },
            },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/refresh' },
        method: { type: 'string', example: 'POST' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid refresh token or token reuse detected',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 401 },
        message: { type: 'string', example: 'Token reuse detected' },
        error: { type: 'string', example: 'Unauthorized' },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/auth/refresh' },
        method: { type: 'string', example: 'POST' },
        correlationId: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
  })
  async refresh(@Req() req: Request, @Res() res: Response) {
    const ip = this.ipUtil.extractRealIp(req);
    const userAgent = req.get('User-Agent');
    
    // Get refresh token from cookie
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({
        statusCode: 401,
        message: 'Refresh token not found',
        error: 'Unauthorized',
        timestamp: new Date().toISOString(),
        path: '/auth/refresh',
        method: 'POST',
      });
    }
    
    const result = await this.authService.refresh(refreshToken, ip, userAgent);
    
    // Set new HttpOnly cookie for new refresh token
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });
    
    // Return only access token in response body
    return res.json({
      success: true,
      data: {
        tokens: {
          accessToken: result.tokens.accessToken,
        },
      },
      timestamp: new Date().toISOString(),
      path: '/auth/refresh',
      method: 'POST',
    });
  }

}
