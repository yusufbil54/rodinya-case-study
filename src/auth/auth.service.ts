import { Injectable, UnauthorizedException, ConflictException, Logger } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { TokenService } from './token/token.service';
import { IpUtil } from '../common/utils/ip.util';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';

export interface AuthResponse {
  user: {
    id: string;
    email: string;
    role: 'user' | 'admin';
  };
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly ipUtil: IpUtil,
  ) {}

  async register(registerDto: RegisterDto, ip: string, userAgent?: string): Promise<AuthResponse> {
    try {
      const user = await this.usersService.create(
        registerDto.email,
        registerDto.password,
      );

      const tokens = await this.tokenService.issueTokens(user, userAgent, ip);

      this.logger.log(`New user registered: ${user.email} from IP: ${ip}`);

      return {
        user: {
          id: (user as any)._id.toString(),
          email: user.email,
          role: user.role,
        },
        tokens,
      };
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      this.logger.error(`Registration failed for ${registerDto.email}: ${(error as Error).message}`);
      throw new Error('Registration failed');
    }
  }

  async login(loginDto: LoginDto, ip: string, userAgent?: string): Promise<AuthResponse> {
    // Check if IP is banned
    if (this.ipUtil.isBanned(ip)) {
      const banStatus = this.ipUtil.getBanStatus(ip);
      throw new UnauthorizedException(
        `IP banned until ${banStatus.banUntil?.toISOString()} due to too many failed attempts`,
      );
    }

    try {
      const user = await this.usersService.findByEmail(loginDto.email);
      if (!user) {
        this.ipUtil.incFailure(ip);
        throw new UnauthorizedException('Invalid credentials');
      }

      const isPasswordValid = await this.usersService.validatePassword(
        user,
        loginDto.password,
      );
      if (!isPasswordValid) {
        this.ipUtil.incFailure(ip);
        this.logger.warn(`Failed login attempt for ${loginDto.email} from IP: ${ip}`);
        throw new UnauthorizedException('Invalid credentials');
      }

      const tokens = await this.tokenService.issueTokens(user, userAgent, ip);
      this.logger.log(`Successful login for ${user.email} from IP: ${ip}`);

      return {
        user: {
          id: (user as any)._id.toString(),
          email: user.email,
          role: user.role,
        },
        tokens,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      this.logger.error(`Login failed for ${loginDto.email}: ${(error as Error).message}`);
      throw new UnauthorizedException('Login failed');
    }
  }

  async refresh(refreshToken: string, ip: string, userAgent?: string): Promise<{ tokens: { accessToken: string; refreshToken: string } }> {
    // Check if IP is banned
    if (this.ipUtil.isBanned(ip)) {
      const banStatus = this.ipUtil.getBanStatus(ip);
      throw new UnauthorizedException(
        `IP banned until ${banStatus.banUntil?.toISOString()} due to too many failed attempts`,
      );
    }

    try {
      const tokens = await this.tokenService.rotateRefreshToken(refreshToken, userAgent, ip);
      
      this.logger.log(`Token refreshed from IP: ${ip}`);
      
      return { tokens };
    } catch (error) {
      this.ipUtil.incFailure(ip);
      this.logger.warn(`Failed refresh attempt from IP: ${ip} - ${(error as Error).message}`);
      throw new UnauthorizedException('Token refresh failed');
    }
  }

}
