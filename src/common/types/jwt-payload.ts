export interface JwtAccessPayload {
  sub: string; // user id
  role: 'user' | 'admin';
  tokenVersion: number;
  iat?: number;
  exp?: number;
}

export interface JwtRefreshPayload {
  sub: string; // user id
  ver: number; // token version
  jti: string; // unique token id
  iat?: number;
  exp?: number;
}

export interface RequestUser {
  id: string;
  role: 'user' | 'admin';
  tokenVersion: number;
}
