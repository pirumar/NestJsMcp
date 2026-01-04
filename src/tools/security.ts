// NestJS Security Audit Tools

export interface SecurityIssue {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  location?: string;
  recommendation: string;
  cweId?: string;
}

export interface SecurityAuditResult {
  score: number;
  grade: string;
  issues: SecurityIssue[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recommendations: string[];
}

// Audit NestJS code for security issues
export function auditCode(code: string, filename?: string): SecurityIssue[] {
  const issues: SecurityIssue[] = [];

  // SQL Injection checks
  if (code.includes('query(') && (code.includes('${') || code.includes("' +"))) {
    issues.push({
      severity: 'critical',
      category: 'Injection',
      title: 'Potential SQL Injection',
      description: 'String concatenation or template literals used in SQL query',
      location: filename,
      recommendation: 'Use parameterized queries or TypeORM query builder with parameters',
      cweId: 'CWE-89',
    });
  }

  // Raw query without parameters
  if (code.match(/\.query\s*\(\s*['"`][^'"`]*\$\{/)) {
    issues.push({
      severity: 'critical',
      category: 'Injection',
      title: 'Raw SQL Query with Interpolation',
      description: 'Using raw SQL queries with string interpolation is dangerous',
      location: filename,
      recommendation: 'Use query parameters: query("SELECT * FROM users WHERE id = $1", [id])',
      cweId: 'CWE-89',
    });
  }

  // Command Injection
  if (code.includes('exec(') || code.includes('execSync(') || code.includes('spawn(')) {
    if (code.includes('${') || code.includes("' +") || code.includes('req.')) {
      issues.push({
        severity: 'critical',
        category: 'Injection',
        title: 'Potential Command Injection',
        description: 'User input may be passed to system command execution',
        location: filename,
        recommendation: 'Sanitize all inputs, use allowlists, avoid shell execution when possible',
        cweId: 'CWE-78',
      });
    }
  }

  // Hardcoded secrets
  const secretPatterns = [
    /password\s*[:=]\s*['"][^'"]+['"]/gi,
    /secret\s*[:=]\s*['"][^'"]+['"]/gi,
    /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi,
    /token\s*[:=]\s*['"][^'"]+['"]/gi,
    /private[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi,
  ];

  for (const pattern of secretPatterns) {
    if (pattern.test(code) && !code.includes('process.env') && !code.includes('configService')) {
      issues.push({
        severity: 'high',
        category: 'Sensitive Data',
        title: 'Hardcoded Secret Detected',
        description: 'Secrets should not be hardcoded in source code',
        location: filename,
        recommendation: 'Use environment variables or a secrets manager (ConfigService)',
        cweId: 'CWE-798',
      });
      break;
    }
  }

  // Weak JWT secret
  if (code.includes("secret: '") && code.includes('JwtModule')) {
    const secretMatch = code.match(/secret:\s*['"]([^'"]+)['"]/);
    if (secretMatch && secretMatch[1].length < 32) {
      issues.push({
        severity: 'high',
        category: 'Authentication',
        title: 'Weak JWT Secret',
        description: 'JWT secret is too short or hardcoded',
        location: filename,
        recommendation: 'Use a strong, randomly generated secret from environment variables (min 256 bits)',
        cweId: 'CWE-326',
      });
    }
  }

  // Missing authentication
  if (code.includes('@Controller') && !code.includes('@UseGuards') && !code.includes('AuthGuard')) {
    if (!code.includes('@Public()') && !code.includes("'health'") && !code.includes("'public'")) {
      issues.push({
        severity: 'medium',
        category: 'Authentication',
        title: 'Missing Authentication Guard',
        description: 'Controller has no authentication guard applied',
        location: filename,
        recommendation: 'Apply @UseGuards(JwtAuthGuard) or use global guard with @Public() decorator for public routes',
        cweId: 'CWE-306',
      });
    }
  }

  // Missing validation
  if (code.includes('@Body()') && !code.includes('ValidationPipe') && !code.includes('Dto')) {
    issues.push({
      severity: 'medium',
      category: 'Input Validation',
      title: 'Missing Input Validation',
      description: 'Request body is not validated with DTOs',
      location: filename,
      recommendation: 'Use DTOs with class-validator decorators and ValidationPipe',
      cweId: 'CWE-20',
    });
  }

  // CORS wildcard
  if (code.includes("origin: '*'") || code.includes('enableCors()')) {
    issues.push({
      severity: 'medium',
      category: 'CORS',
      title: 'Permissive CORS Configuration',
      description: 'CORS allows all origins which may expose API to cross-origin attacks',
      location: filename,
      recommendation: 'Configure specific allowed origins in production',
      cweId: 'CWE-346',
    });
  }

  // No rate limiting
  if (code.includes('@Controller') && !code.includes('ThrottlerGuard') && !code.includes('@SkipThrottle')) {
    issues.push({
      severity: 'medium',
      category: 'DoS Prevention',
      title: 'Missing Rate Limiting',
      description: 'No rate limiting detected which may allow abuse',
      location: filename,
      recommendation: 'Implement @nestjs/throttler for rate limiting',
      cweId: 'CWE-770',
    });
  }

  // Logging sensitive data
  if (code.includes('console.log') || code.includes('Logger.log')) {
    if (code.includes('password') || code.includes('token') || code.includes('secret')) {
      issues.push({
        severity: 'medium',
        category: 'Information Exposure',
        title: 'Potentially Logging Sensitive Data',
        description: 'Sensitive data may be logged',
        location: filename,
        recommendation: 'Never log passwords, tokens, or other sensitive information',
        cweId: 'CWE-532',
      });
    }
  }

  // Unsafe redirect
  if (code.includes('@Redirect') && code.includes('req.query')) {
    issues.push({
      severity: 'high',
      category: 'Open Redirect',
      title: 'Potential Open Redirect',
      description: 'Redirect URL may come from user input',
      location: filename,
      recommendation: 'Validate redirect URLs against an allowlist of trusted domains',
      cweId: 'CWE-601',
    });
  }

  // Synchronize in production
  if (code.includes('synchronize: true') && !code.includes("NODE_ENV") && !code.includes('development')) {
    issues.push({
      severity: 'high',
      category: 'Database',
      title: 'Database Synchronize Enabled',
      description: 'TypeORM synchronize can cause data loss in production',
      location: filename,
      recommendation: "Disable synchronize in production: synchronize: process.env.NODE_ENV !== 'production'",
      cweId: 'CWE-1188',
    });
  }

  // No helmet
  if (code.includes('bootstrap') && code.includes('NestFactory.create') && !code.includes('helmet')) {
    issues.push({
      severity: 'low',
      category: 'Security Headers',
      title: 'Missing Helmet Middleware',
      description: 'Security headers are not configured',
      location: filename,
      recommendation: 'Use helmet middleware for security headers: app.use(helmet())',
      cweId: 'CWE-693',
    });
  }

  // Password hashing check
  if (code.includes('password') && code.includes('save') && !code.includes('bcrypt') && !code.includes('argon2') && !code.includes('hash')) {
    issues.push({
      severity: 'high',
      category: 'Authentication',
      title: 'Password May Not Be Hashed',
      description: 'Password is being saved but no hashing is visible',
      location: filename,
      recommendation: 'Always hash passwords using bcrypt or argon2 before storing',
      cweId: 'CWE-256',
    });
  }

  // Debug mode in production
  if (code.includes('debug: true') || code.includes('DEBUG=')) {
    issues.push({
      severity: 'low',
      category: 'Information Exposure',
      title: 'Debug Mode May Be Enabled',
      description: 'Debug mode can expose sensitive information',
      location: filename,
      recommendation: 'Disable debug mode in production environments',
      cweId: 'CWE-215',
    });
  }

  // Missing error handling
  if (code.includes('async') && code.includes('await') && !code.includes('try') && !code.includes('catch')) {
    if (!code.includes('ExceptionFilter') && !code.includes('UseFilters')) {
      issues.push({
        severity: 'low',
        category: 'Error Handling',
        title: 'Missing Error Handling',
        description: 'Async operations without try-catch blocks',
        location: filename,
        recommendation: 'Use try-catch or implement global exception filters',
        cweId: 'CWE-755',
      });
    }
  }

  // Eval usage
  if (code.includes('eval(') || code.includes('new Function(')) {
    issues.push({
      severity: 'critical',
      category: 'Injection',
      title: 'Dangerous Code Execution',
      description: 'eval() or Function constructor can execute arbitrary code',
      location: filename,
      recommendation: 'Never use eval() or new Function() with user input',
      cweId: 'CWE-95',
    });
  }

  // File path traversal
  if (code.includes('createReadStream') || code.includes('readFileSync') || code.includes('writeFileSync')) {
    if (code.includes('req.params') || code.includes('req.query') || code.includes('req.body')) {
      issues.push({
        severity: 'high',
        category: 'Path Traversal',
        title: 'Potential Path Traversal',
        description: 'File operations may use unsanitized user input',
        location: filename,
        recommendation: 'Validate and sanitize file paths, use path.resolve() and check against base directory',
        cweId: 'CWE-22',
      });
    }
  }

  return issues;
}

// Generate security score and grade
export function calculateSecurityScore(issues: SecurityIssue[]): { score: number; grade: string } {
  let deductions = 0;

  for (const issue of issues) {
    switch (issue.severity) {
      case 'critical':
        deductions += 25;
        break;
      case 'high':
        deductions += 15;
        break;
      case 'medium':
        deductions += 8;
        break;
      case 'low':
        deductions += 3;
        break;
      case 'info':
        deductions += 1;
        break;
    }
  }

  const score = Math.max(0, 100 - deductions);

  let grade: string;
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';

  return { score, grade };
}

// Full security audit
export function performSecurityAudit(codeFiles: { filename: string; content: string }[]): SecurityAuditResult {
  const allIssues: SecurityIssue[] = [];

  for (const file of codeFiles) {
    const issues = auditCode(file.content, file.filename);
    allIssues.push(...issues);
  }

  const summary = {
    critical: allIssues.filter(i => i.severity === 'critical').length,
    high: allIssues.filter(i => i.severity === 'high').length,
    medium: allIssues.filter(i => i.severity === 'medium').length,
    low: allIssues.filter(i => i.severity === 'low').length,
    info: allIssues.filter(i => i.severity === 'info').length,
  };

  const { score, grade } = calculateSecurityScore(allIssues);

  const recommendations = generateSecurityRecommendations(allIssues);

  return {
    score,
    grade,
    issues: allIssues,
    summary,
    recommendations,
  };
}

// Generate security recommendations
function generateSecurityRecommendations(issues: SecurityIssue[]): string[] {
  const recommendations = new Set<string>();

  if (issues.some(i => i.category === 'Injection')) {
    recommendations.add('Implement parameterized queries and input sanitization across all data access layers');
  }

  if (issues.some(i => i.category === 'Authentication')) {
    recommendations.add('Review authentication implementation: use strong JWT secrets, proper password hashing, and secure session management');
  }

  if (issues.some(i => i.category === 'Sensitive Data')) {
    recommendations.add('Move all secrets to environment variables and use a secrets management service');
  }

  if (issues.some(i => i.category === 'Input Validation')) {
    recommendations.add('Enable global ValidationPipe and use DTOs with class-validator for all endpoints');
  }

  if (issues.some(i => i.category === 'CORS')) {
    recommendations.add('Configure CORS with specific allowed origins for production');
  }

  if (issues.some(i => i.category === 'DoS Prevention')) {
    recommendations.add('Implement rate limiting with @nestjs/throttler');
  }

  if (issues.some(i => i.category === 'Security Headers')) {
    recommendations.add('Add helmet middleware for security headers');
  }

  if (issues.some(i => i.category === 'Error Handling')) {
    recommendations.add('Implement global exception filters to handle errors consistently');
  }

  // Always add these recommendations
  recommendations.add('Regularly update dependencies to patch security vulnerabilities');
  recommendations.add('Implement security logging and monitoring');
  recommendations.add('Conduct regular security reviews and penetration testing');

  return Array.from(recommendations);
}

// Security best practices checklist
export function getSecurityChecklist(): { category: string; items: { item: string; description: string; priority: 'required' | 'recommended' | 'optional' }[] }[] {
  return [
    {
      category: 'Authentication & Authorization',
      items: [
        { item: 'Use JWT with strong secrets', description: 'JWT secret should be at least 256 bits and from environment', priority: 'required' },
        { item: 'Implement password hashing', description: 'Use bcrypt or argon2 with appropriate cost factor', priority: 'required' },
        { item: 'Use guards for protected routes', description: 'Apply AuthGuard to all protected endpoints', priority: 'required' },
        { item: 'Implement role-based access control', description: 'Use RolesGuard for authorization', priority: 'recommended' },
        { item: 'Add refresh token rotation', description: 'Implement secure refresh token mechanism', priority: 'recommended' },
        { item: 'Session timeout', description: 'Set appropriate JWT expiration times', priority: 'recommended' },
      ],
    },
    {
      category: 'Input Validation',
      items: [
        { item: 'Enable ValidationPipe globally', description: 'Validate all incoming data', priority: 'required' },
        { item: 'Use DTOs with decorators', description: 'Define validation rules with class-validator', priority: 'required' },
        { item: 'Whitelist properties', description: 'Enable whitelist option to strip unknown properties', priority: 'required' },
        { item: 'Sanitize user input', description: 'Remove potentially dangerous content', priority: 'recommended' },
        { item: 'Validate file uploads', description: 'Check file types, sizes, and content', priority: 'recommended' },
      ],
    },
    {
      category: 'Data Protection',
      items: [
        { item: 'Use HTTPS', description: 'Encrypt all traffic in production', priority: 'required' },
        { item: 'Environment variables for secrets', description: 'Never hardcode sensitive data', priority: 'required' },
        { item: 'Parameterized queries', description: 'Prevent SQL injection', priority: 'required' },
        { item: 'Encrypt sensitive data', description: 'Encrypt PII and sensitive fields', priority: 'recommended' },
        { item: 'Implement data masking', description: 'Mask sensitive data in logs and responses', priority: 'recommended' },
      ],
    },
    {
      category: 'API Security',
      items: [
        { item: 'Enable CORS properly', description: 'Configure specific allowed origins', priority: 'required' },
        { item: 'Implement rate limiting', description: 'Use @nestjs/throttler', priority: 'required' },
        { item: 'Use Helmet', description: 'Add security headers', priority: 'required' },
        { item: 'Disable X-Powered-By', description: 'Hide server information', priority: 'recommended' },
        { item: 'API versioning', description: 'Version your APIs', priority: 'optional' },
      ],
    },
    {
      category: 'Error Handling',
      items: [
        { item: 'Global exception filter', description: 'Handle all exceptions consistently', priority: 'required' },
        { item: 'Don\'t expose stack traces', description: 'Hide internal errors in production', priority: 'required' },
        { item: 'Log errors securely', description: 'Log errors without sensitive data', priority: 'required' },
        { item: 'Custom error responses', description: 'Return safe error messages', priority: 'recommended' },
      ],
    },
    {
      category: 'Monitoring & Logging',
      items: [
        { item: 'Security event logging', description: 'Log authentication and authorization events', priority: 'required' },
        { item: 'Request logging', description: 'Log all requests with correlation IDs', priority: 'recommended' },
        { item: 'Health checks', description: 'Implement /health endpoint', priority: 'recommended' },
        { item: 'Alerting', description: 'Set up alerts for security events', priority: 'recommended' },
      ],
    },
  ];
}

// Generate secure configuration template
export function generateSecureMainTs(): string {
  return `import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log'],
  });

  const configService = app.get(ConfigService);

  // Security: Helmet for security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: 'same-site' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
    },
  }));

  // Security: CORS
  const allowedOrigins = configService.get<string>('CORS_ORIGINS')?.split(',') || [];
  app.enableCors({
    origin: allowedOrigins.length > 0 ? allowedOrigins : false,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
  });

  // Security: Global validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
      disableErrorMessages: configService.get('NODE_ENV') === 'production',
    }),
  );

  // Security: Global prefix
  app.setGlobalPrefix('api', {
    exclude: ['health'],
  });

  // Graceful shutdown
  app.enableShutdownHooks();

  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);

  logger.log(\`Application running on port \${port}\`);
  logger.log(\`Environment: \${configService.get('NODE_ENV')}\`);
}
bootstrap();
`;
}
