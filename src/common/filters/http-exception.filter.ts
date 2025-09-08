import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

interface ErrorResponse {
  statusCode: number;
  timestamp: string;
  path: string;
  method: string;
  message: string | string[];
  error?: string;
  correlationId?: string;
}

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status: number;
    let message: string | string[];
    let error: string | undefined;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();
      
      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
      } else {
        const responseObj = exceptionResponse as any;
        message = responseObj.message || responseObj.error || exception.message;
        error = responseObj.error;
      }
    } else {
      // Unhandled exceptions
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = 'Internal server error';
      error = 'Internal Server Error';
      
      // Log the full error for debugging
      this.logger.error(
        `Unhandled exception: ${exception}`,
        exception instanceof Error ? exception.stack : undefined,
        `${request.method} ${request.url}`,
      );
    }

    const correlationId = this.generateCorrelationId();
    
    const errorResponse: ErrorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message,
      ...(error && { error }),
      correlationId,
    };

    // Log error details (except for client errors like 4xx)
    if (status >= 500) {
      this.logger.error(
        `HTTP ${status} Error`,
        JSON.stringify(errorResponse, null, 2),
        `${request.method} ${request.url}`,
      );
    } else if (status >= 400 && status < 500) {
      this.logger.warn(
        `HTTP ${status} Client Error`,
        JSON.stringify({ path: request.url, method: request.method, message }),
      );
    }

    response.status(status).json(errorResponse);
  }

  private generateCorrelationId(): string {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }
}
