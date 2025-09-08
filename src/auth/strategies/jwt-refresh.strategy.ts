import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { Request } from 'express';
import { TokenService } from '../token/token.service';
import { JwtRefreshPayload } from '../../common/types/jwt-payload';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(private readonly tokenService: TokenService) {
    super();
  }

  async validate(req: Request): Promise<JwtRefreshPayload> {
    const refreshToken = req.body?.refreshToken;
    
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is required');
    }

    try {
      // This will verify the token and extract the payload
      const payload = await this.tokenService.verifyAccessToken(refreshToken);
      return payload as any; // Cast for compatibility
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
