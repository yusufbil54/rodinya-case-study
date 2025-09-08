import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';
import * as argon2 from 'argon2';
import { UsersService } from '../../users/users.service';
import { UserDocument } from '../../users/schemas/user.schema';
import { CryptoUtil } from '../../common/utils/crypto.util';
import { JwtAccessPayload } from '../../common/types/jwt-payload';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);
  private readonly jwtAccessSecret: string;
  private readonly jwtRefreshSecret: string;
  private readonly accessExpiresIn: string;
  private readonly refreshExpiresIn: string;
  private readonly aesRefreshKey: string;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    this.jwtAccessSecret = this.configService.getOrThrow('JWT_ACCESS_SECRET');
    this.jwtRefreshSecret = this.configService.getOrThrow('JWT_REFRESH_SECRET');
    this.accessExpiresIn = this.configService.getOrThrow('ACCESS_EXPIRES_IN');
    this.refreshExpiresIn = this.configService.getOrThrow('REFRESH_EXPIRES_IN');
    this.aesRefreshKey = this.configService.getOrThrow('AES_REFRESH_KEY');
  }

  /**
   * Issue new access and refresh tokens
   */
  async issueTokens(
    user: UserDocument, 
    userAgent?: string, 
    ip?: string
  ): Promise<TokenPair> {
    const accessPayload: JwtAccessPayload = {
      sub: (user as any)._id.toString(),
      role: user.role,
      tokenVersion: user.tokenVersion,
    };

    const accessToken = this.jwtService.sign(accessPayload, {
      secret: this.jwtAccessSecret,
      expiresIn: this.accessExpiresIn,
    });

    // Generate opaque random refresh token (not JWT)
    const refreshToken = CryptoUtil.secureRandomString(64);

    // Store refresh token securely with device info
    await this.storeRefreshToken(
      (user as any)._id.toString(), 
      refreshToken,
      userAgent,
      ip
    );

    return { accessToken, refreshToken };
  }

  /**
   * Verify and rotate refresh token
   */
  async rotateRefreshToken(
    refreshToken: string, 
    userAgent?: string, 
    ip?: string
  ): Promise<TokenPair> {
    let user: UserDocument | null = null;
    
    try {
      // Find user by refresh token hash
      user = await this.findUserByRefreshToken(refreshToken);
      if (!user) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Verify refresh token against stored hash
      const isValid = await this.verifyStoredRefreshToken(user, refreshToken);
      if (!isValid) {
        this.logger.warn(`Refresh token reuse detected for user ${user.email}`);
        await this.invalidateAllTokens((user as any)._id.toString());
        throw new UnauthorizedException('Token reuse detected');
      }

      // Check if token is expired
      if (user.refresh.deviceInfo.expiresAt && user.refresh.deviceInfo.expiresAt < new Date()) {
        await this.invalidateAllTokens((user as any)._id.toString());
        throw new UnauthorizedException('Refresh token expired');
      }

      // CRITICAL: Invalidate old tokens immediately after verification
      // This prevents both refresh token reuse and old access token usage
      await this.usersService.incrementTokenVersion((user as any)._id.toString());
      await this.usersService.clearRefreshToken((user as any)._id.toString());
      
      // Get updated user with new tokenVersion
      const updatedUser = await this.usersService.findById((user as any)._id.toString());
      if (!updatedUser) {
        throw new UnauthorizedException('User not found after token rotation');
      }
       
      // Issue new tokens with updated user data
      return this.issueTokens(updatedUser, userAgent, ip);
    } catch (error) {
      // If we found a user but verification failed, invalidate all their tokens
      if (user && error instanceof UnauthorizedException) {
        await this.invalidateAllTokens((user as any)._id.toString());
      }
      
      this.logger.error(`Refresh token verification failed: ${(error as Error).message}`);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Verify access token and return payload
   */
  async verifyAccessToken(token: string): Promise<JwtAccessPayload> {
    try {
      return this.jwtService.verify<JwtAccessPayload>(token, {
        secret: this.jwtAccessSecret,
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid access token');
    }
  }

  /**
   * Invalidate user's refresh token
   */
  async invalidateRefreshToken(userId: string, refreshToken: string): Promise<void> {
    try {
      const user = await this.usersService.findById(userId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Verify the refresh token belongs to this user
      const isValid = await this.verifyStoredRefreshToken(user, refreshToken);
      if (!isValid) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      await this.usersService.clearRefreshToken(userId);
    } catch (error) {
      this.logger.error(`Failed to invalidate refresh token: ${(error as Error).message}`);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Invalidate all user tokens by incrementing token version
   */
  async invalidateAllTokens(userId: string): Promise<void> {
    await this.usersService.incrementTokenVersion(userId);
    await this.usersService.clearRefreshToken(userId);
    this.logger.log(`All tokens invalidated for user ${userId}`);
  }

  /**
   * Store refresh token securely in database
   */
  private async storeRefreshToken(
    userId: string, 
    refreshToken: string, 
    userAgent?: string, 
    ip?: string
  ): Promise<void> {
    // Hash the refresh token
    const rt_hash = await argon2.hash(refreshToken);

    // Encrypt the refresh token with AES-GCM
    const encrypted = CryptoUtil.aesGcmEncrypt(refreshToken, this.aesRefreshKey);

    // Calculate expiration date (refresh token expires in 7 days by default)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.usersService.updateRefreshToken(userId, {
      rt_hash,
      rt_ciphertext: encrypted.ciphertextBase64,
      rt_iv: encrypted.ivBase64,
      rt_tag: encrypted.tagBase64,
      deviceInfo: {
        userAgent: userAgent || null,
        ip: ip || null,
        createdAt: new Date(),
        expiresAt,
      },
    });
  }

  /**
   * Find user by refresh token hash
   * Note: This method is intentionally inefficient for security reasons
   * We can't index hashed tokens, so we must check all users
   */
  private async findUserByRefreshToken(refreshToken: string): Promise<UserDocument | null> {
    try {
      // We need to check all users since we can't query by hash directly
      // This is not efficient for large user bases, but necessary for security
      const users = await this.usersService.findAll();
      
      for (const user of users) {
        if (user.refresh?.rt_hash) {
          try {
            const isValid = await argon2.verify(user.refresh.rt_hash, refreshToken);
            if (isValid) {
              return user;
            }
          } catch (error) {
            // Continue checking other users if hash verification fails
            continue;
          }
        }
      }
      
      return null;
    } catch (error) {
      this.logger.error(`Failed to find user by refresh token: ${(error as Error).message}`);
      return null;
    }
  }

  /**
   * Verify refresh token against stored data
   */
  private async verifyStoredRefreshToken(user: UserDocument, refreshToken: string): Promise<boolean> {
    try {
      if (!user.refresh?.rt_hash) {
        return false;
      }

      // Verify against argon2 hash
      const isHashValid = await argon2.verify(user.refresh.rt_hash, refreshToken);
      if (!isHashValid) {
        return false;
      }

      // Verify against encrypted version (additional security layer)
      if (user.refresh.rt_ciphertext && user.refresh.rt_iv && user.refresh.rt_tag) {
        const decryptedToken = CryptoUtil.aesGcmDecrypt(
          user.refresh.rt_ciphertext,
          user.refresh.rt_iv,
          user.refresh.rt_tag,
          this.aesRefreshKey,
        );
        
        return decryptedToken === refreshToken;
      }

      return true;
    } catch (error) {
      this.logger.error(`Refresh token verification failed: ${(error as Error).message}`);
      return false;
    }
  }
}
