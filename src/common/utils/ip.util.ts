import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

interface IpBanRecord {
  failCount: number;
  banUntil?: Date;
  firstFailure: Date;
}

@Injectable()
export class IpUtil {
  private readonly logger = new Logger(IpUtil.name);
  private readonly ipRecords = new Map<string, IpBanRecord>();
  private readonly banThreshold: number;
  private readonly banMinutes: number;
  private readonly windowMinutes = 60; // Rolling window for failures

  constructor(private readonly configService: ConfigService) {
    this.banThreshold = parseInt(
      this.configService.getOrThrow('IP_BAN_THRESHOLD'),
      10,
    );
    this.banMinutes = parseInt(
      this.configService.getOrThrow('IP_BAN_MINUTES'),
      10,
    );

    // Cleanup expired records every 5 minutes
    setInterval(() => this.cleanupExpiredRecords(), 5 * 60 * 1000);
  }

  /**
   * Record a failed attempt for an IP
   */
  incFailure(ip: string): void {
    const now = new Date();
    const record = this.ipRecords.get(ip);

    if (!record) {
      this.ipRecords.set(ip, {
        failCount: 1,
        firstFailure: now,
      });
      return;
    }

    // Reset counter if window has expired
    const windowExpired = 
      now.getTime() - record.firstFailure.getTime() > this.windowMinutes * 60 * 1000;
    
    if (windowExpired) {
      record.failCount = 1;
      record.firstFailure = now;
      delete record.banUntil;
    } else {
      record.failCount++;
    }

    // Ban if threshold exceeded
    if (record.failCount >= this.banThreshold) {
      record.banUntil = new Date(now.getTime() + this.banMinutes * 60 * 1000);
      this.logger.warn(`IP ${ip} banned for ${this.banMinutes} minutes after ${record.failCount} failed attempts`);
    }

    this.ipRecords.set(ip, record);
  }

  /**
   * Check if an IP is currently banned
   */
  isBanned(ip: string): boolean {
    const record = this.ipRecords.get(ip);
    
    if (!record?.banUntil) {
      return false;
    }

    const now = new Date();
    const isBanned = now < record.banUntil;

    // Clean up expired ban
    if (!isBanned) {
      delete record.banUntil;
      record.failCount = 0;
      this.ipRecords.set(ip, record);
    }

    return isBanned;
  }

  /**
   * Manually unban an IP
   */
  unban(ip: string): void {
    const record = this.ipRecords.get(ip);
    if (record) {
      delete record.banUntil;
      record.failCount = 0;
      this.ipRecords.set(ip, record);
      this.logger.log(`IP ${ip} manually unbanned`);
    }
  }

  /**
   * Get ban status for an IP
   */
  getBanStatus(ip: string): { isBanned: boolean; banUntil?: Date; failCount: number } {
    const record = this.ipRecords.get(ip);
    
    if (!record) {
      return { isBanned: false, failCount: 0 };
    }

    return {
      isBanned: this.isBanned(ip),
      banUntil: record.banUntil,
      failCount: record.failCount,
    };
  }

  /**
   * Get all banned IPs
   */
  getBannedIps(): string[] {
    const now = new Date();
    const bannedIps: string[] = [];

    for (const [ip, record] of this.ipRecords) {
      if (record.banUntil && now < record.banUntil) {
        bannedIps.push(ip);
      }
    }

    return bannedIps;
  }

  /**
   * Extract real IP from request considering proxy headers
   */
  extractRealIp(request: any): string {
    const trustProxy = this.configService.getOrThrow('TRUST_PROXY');
    
    if (trustProxy) {
      // Check X-Forwarded-For header (first IP is the original client)
      const forwardedFor = request.headers['x-forwarded-for'];
      if (forwardedFor) {
        const ips = forwardedFor.split(',').map((ip: string) => ip.trim());
        return ips[0];
      }

      // Check X-Real-IP header
      const realIp = request.headers['x-real-ip'];
      if (realIp) {
        return realIp;
      }
    }

    // Fallback to connection remote address
    return request.connection?.remoteAddress || 
           request.socket?.remoteAddress || 
           request.ip || 
           'unknown';
  }

  /**
   * Clean up expired records
   */
  private cleanupExpiredRecords(): void {
    const now = new Date();
    const expiredIps: string[] = [];

    for (const [ip, record] of this.ipRecords) {
      // Remove records older than 24 hours with no active ban
      const isOld = now.getTime() - record.firstFailure.getTime() > 24 * 60 * 60 * 1000;
      const hasActiveBan = record.banUntil && now < record.banUntil;
      
      if (isOld && !hasActiveBan) {
        expiredIps.push(ip);
      }
    }

    expiredIps.forEach(ip => this.ipRecords.delete(ip));
    
    if (expiredIps.length > 0) {
      this.logger.log(`Cleaned up ${expiredIps.length} expired IP records`);
    }
  }
}
