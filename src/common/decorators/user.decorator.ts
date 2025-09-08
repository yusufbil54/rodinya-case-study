import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { RequestUser } from '../types/jwt-payload';

export const User = createParamDecorator(
  (data: keyof RequestUser | undefined, ctx: ExecutionContext): RequestUser | any => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as RequestUser;

    return data ? user?.[data] : user;
  },
);
