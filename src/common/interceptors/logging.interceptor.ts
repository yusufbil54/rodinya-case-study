import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Request, Response } from 'express';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const startTime = Date.now();
    const ctx = context.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();
    
    const { method, url, ip } = request;
    const userAgent = request.get('User-Agent') || '';
    
    // Log the incoming request
    this.logger.log(`${method} ${url} - ${ip} - ${userAgent}`);

    return next.handle().pipe(
      tap({
        next: () => {
          const duration = Date.now() - startTime;
          const { statusCode } = response;
          
          this.logger.log(
            `${method} ${url} - ${statusCode} - ${duration}ms - ${ip}`,
          );
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          const statusCode = error?.status || 500;
          
          this.logger.error(
            `${method} ${url} - ${statusCode} - ${duration}ms - ${ip} - Error: ${error?.message}`,
          );
        },
      }),
    );
  }
}
