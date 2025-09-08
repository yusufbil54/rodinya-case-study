import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { JwtAccessPayload, RequestUser } from '../../common/types/jwt-payload';

@Injectable()
export class JwtAccessStrategy extends PassportStrategy(Strategy, 'jwt-access') {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow('JWT_ACCESS_SECRET'),
    });
  }

  async validate(payload: JwtAccessPayload): Promise<RequestUser> {
    const user = await this.usersService.findById(payload.sub);
    
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Check if token version matches
    if (payload.tokenVersion !== user.tokenVersion) {
      throw new UnauthorizedException('Token has been invalidated');
    }

    return {
      id: (user as any)._id.toString(),
      role: user.role,
      tokenVersion: user.tokenVersion,
    };
  }
}
