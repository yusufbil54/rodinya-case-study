import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { TokenService } from './token/token.service';
import { IpUtil } from '../common/utils/ip.util';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';

describe('AuthService', () => {
  let authService: AuthService;
  let usersService: jest.Mocked<UsersService>;
  let tokenService: jest.Mocked<TokenService>;
  let ipUtil: jest.Mocked<IpUtil>;

  const mockUser = {
    _id: '507f1f77bcf86cd799439011',
    email: 'test@example.com',
    role: 'user' as const,
    passwordHash: 'hashedpassword',
    tokenVersion: 0,
    refresh: {
      rt_hash: null,
      rt_ciphertext: null,
      rt_iv: null,
      rt_tag: null,
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTokens = {
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: {
            create: jest.fn(),
            findByEmail: jest.fn(),
            validatePassword: jest.fn(),
          },
        },
        {
          provide: TokenService,
          useValue: {
            issueTokens: jest.fn(),
            rotateRefreshToken: jest.fn(),
            invalidateRefreshToken: jest.fn(),
            invalidateAllTokens: jest.fn(),
          },
        },
        {
          provide: IpUtil,
          useValue: {
            isBanned: jest.fn(),
            incFailure: jest.fn(),
            getBanStatus: jest.fn(),
          },
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    usersService = module.get(UsersService);
    tokenService = module.get(TokenService);
    ipUtil = module.get(IpUtil);
  });

  describe('register', () => {
    const registerDto: RegisterDto = {
      email: 'test@example.com',
      password: 'Password123',
    };

    it('should register a new user successfully', async () => {
      usersService.create.mockResolvedValue(mockUser as any);
      tokenService.issueTokens.mockResolvedValue(mockTokens);

      const result = await authService.register(registerDto, '127.0.0.1');

      expect(result).toEqual({
        user: {
          id: mockUser._id,
          email: mockUser.email,
          role: mockUser.role,
        },
        tokens: mockTokens,
      });
      expect(usersService.create).toHaveBeenCalledWith(
        registerDto.email,
        registerDto.password,
      );
      expect(tokenService.issueTokens).toHaveBeenCalledWith(mockUser);
    });

    it('should throw ConflictException if user already exists', async () => {
      usersService.create.mockRejectedValue(new ConflictException('User exists'));

      await expect(authService.register(registerDto, '127.0.0.1')).rejects.toThrow(
        ConflictException,
      );
    });
  });

  describe('login', () => {
    const loginDto: LoginDto = {
      email: 'test@example.com',
      password: 'Password123',
    };

    it('should login successfully with valid credentials', async () => {
      ipUtil.isBanned.mockReturnValue(false);
      usersService.findByEmail.mockResolvedValue(mockUser as any);
      usersService.validatePassword.mockResolvedValue(true);
      tokenService.issueTokens.mockResolvedValue(mockTokens);

      const result = await authService.login(loginDto, '127.0.0.1');

      expect(result).toEqual({
        user: {
          id: mockUser._id,
          email: mockUser.email,
          role: mockUser.role,
        },
        tokens: mockTokens,
      });
    });

    it('should throw UnauthorizedException if IP is banned', async () => {
      ipUtil.isBanned.mockReturnValue(true);
      ipUtil.getBanStatus.mockReturnValue({
        isBanned: true,
        banUntil: new Date(Date.now() + 60000),
        failCount: 10,
      });

      await expect(authService.login(loginDto, '127.0.0.1')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should increment failure count for invalid credentials', async () => {
      ipUtil.isBanned.mockReturnValue(false);
      usersService.findByEmail.mockResolvedValue(null);

      await expect(authService.login(loginDto, '127.0.0.1')).rejects.toThrow(
        UnauthorizedException,
      );
      expect(ipUtil.incFailure).toHaveBeenCalledWith('127.0.0.1');
    });

    it('should increment failure count for wrong password', async () => {
      ipUtil.isBanned.mockReturnValue(false);
      usersService.findByEmail.mockResolvedValue(mockUser as any);
      usersService.validatePassword.mockResolvedValue(false);

      await expect(authService.login(loginDto, '127.0.0.1')).rejects.toThrow(
        UnauthorizedException,
      );
      expect(ipUtil.incFailure).toHaveBeenCalledWith('127.0.0.1');
    });
  });

  describe('refresh', () => {
    const refreshToken = 'refresh-token';

    it('should refresh tokens successfully', async () => {
      ipUtil.isBanned.mockReturnValue(false);
      tokenService.rotateRefreshToken.mockResolvedValue(mockTokens);

      const result = await authService.refresh(refreshToken, '127.0.0.1');

      expect(result).toEqual({ tokens: mockTokens });
      expect(tokenService.rotateRefreshToken).toHaveBeenCalledWith(refreshToken);
    });

    it('should throw UnauthorizedException if IP is banned', async () => {
      ipUtil.isBanned.mockReturnValue(true);

      await expect(
        authService.refresh(refreshToken, '127.0.0.1'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should increment failure count on token rotation error', async () => {
      ipUtil.isBanned.mockReturnValue(false);
      tokenService.rotateRefreshToken.mockRejectedValue(new Error('Invalid token'));

      await expect(
        authService.refresh(refreshToken, '127.0.0.1'),
      ).rejects.toThrow(UnauthorizedException);
      expect(ipUtil.incFailure).toHaveBeenCalledWith('127.0.0.1');
    });
  });
});
