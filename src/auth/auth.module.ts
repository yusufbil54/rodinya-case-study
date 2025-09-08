import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { TokenService } from './token/token.service';
import { JwtAccessStrategy } from './strategies/jwt-access.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { UsersModule } from '../users/users.module';
import { IpUtil } from '../common/utils/ip.util';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({}), // Config handled in strategies
    UsersModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    TokenService,
    JwtAccessStrategy,
    JwtRefreshStrategy,
    IpUtil,
  ],
  exports: [AuthService, TokenService],
})
export class AuthModule {}
