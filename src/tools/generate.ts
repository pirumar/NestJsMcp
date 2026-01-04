// NestJS Code Generation Tools
import { coreConcepts, techniques, schematics } from '../data/nestjs-docs.js';

export interface GenerateResult {
  code: string;
  filename: string;
  description: string;
  additionalFiles?: { filename: string; code: string }[];
}

// Generate Controller
export function generateController(name: string, options: {
  crud?: boolean;
  prefix?: string;
  methods?: string[];
}): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);
  const prefix = options.prefix || fileName;

  let code: string;

  if (options.crud) {
    code = `import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Body,
  Query,
  ParseIntPipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ${className}Service } from './${fileName}.service';
import { Create${className}Dto } from './dto/create-${fileName}.dto';
import { Update${className}Dto } from './dto/update-${fileName}.dto';

@Controller('${prefix}')
export class ${className}Controller {
  constructor(private readonly ${toCamelCase(name)}Service: ${className}Service) {}

  @Post()
  create(@Body() create${className}Dto: Create${className}Dto) {
    return this.${toCamelCase(name)}Service.create(create${className}Dto);
  }

  @Get()
  findAll(@Query('page') page?: number, @Query('limit') limit?: number) {
    return this.${toCamelCase(name)}Service.findAll({ page, limit });
  }

  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.${toCamelCase(name)}Service.findOne(id);
  }

  @Put(':id')
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body() update${className}Dto: Update${className}Dto,
  ) {
    return this.${toCamelCase(name)}Service.update(id, update${className}Dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.${toCamelCase(name)}Service.remove(id);
  }
}
`;
  } else {
    const methods = options.methods || ['findAll'];
    const methodCode = methods.map(m => generateControllerMethod(m, className)).join('\n\n');

    code = `import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Body,
} from '@nestjs/common';
import { ${className}Service } from './${fileName}.service';

@Controller('${prefix}')
export class ${className}Controller {
  constructor(private readonly ${toCamelCase(name)}Service: ${className}Service) {}

${methodCode}
}
`;
  }

  return {
    code,
    filename: `${fileName}.controller.ts`,
    description: `Controller for ${className} with ${options.crud ? 'CRUD operations' : 'custom methods'}`,
  };
}

// Generate Service
export function generateService(name: string, options: {
  crud?: boolean;
  withRepository?: boolean;
}): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  let imports = `import { Injectable, NotFoundException } from '@nestjs/common';`;
  let constructor = '';
  let methods = '';

  if (options.withRepository) {
    imports += `
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ${className} } from './entities/${fileName}.entity';
import { Create${className}Dto } from './dto/create-${fileName}.dto';
import { Update${className}Dto } from './dto/update-${fileName}.dto';`;

    constructor = `
  constructor(
    @InjectRepository(${className})
    private readonly ${toCamelCase(name)}Repository: Repository<${className}>,
  ) {}`;

    if (options.crud) {
      methods = `
  async create(create${className}Dto: Create${className}Dto): Promise<${className}> {
    const ${toCamelCase(name)} = this.${toCamelCase(name)}Repository.create(create${className}Dto);
    return this.${toCamelCase(name)}Repository.save(${toCamelCase(name)});
  }

  async findAll(options?: { page?: number; limit?: number }): Promise<${className}[]> {
    const { page = 1, limit = 10 } = options || {};
    return this.${toCamelCase(name)}Repository.find({
      skip: (page - 1) * limit,
      take: limit,
    });
  }

  async findOne(id: number): Promise<${className}> {
    const ${toCamelCase(name)} = await this.${toCamelCase(name)}Repository.findOne({ where: { id } });
    if (!${toCamelCase(name)}) {
      throw new NotFoundException(\`${className} #\${id} not found\`);
    }
    return ${toCamelCase(name)};
  }

  async update(id: number, update${className}Dto: Update${className}Dto): Promise<${className}> {
    const ${toCamelCase(name)} = await this.findOne(id);
    Object.assign(${toCamelCase(name)}, update${className}Dto);
    return this.${toCamelCase(name)}Repository.save(${toCamelCase(name)});
  }

  async remove(id: number): Promise<void> {
    const ${toCamelCase(name)} = await this.findOne(id);
    await this.${toCamelCase(name)}Repository.remove(${toCamelCase(name)});
  }`;
    }
  } else {
    methods = `
  // Add your service methods here`;
  }

  const code = `${imports}

@Injectable()
export class ${className}Service {${constructor}
${methods}
}
`;

  return {
    code,
    filename: `${fileName}.service.ts`,
    description: `Service for ${className}${options.withRepository ? ' with TypeORM repository' : ''}`,
  };
}

// Generate Module
export function generateModule(name: string, options: {
  withController?: boolean;
  withService?: boolean;
  imports?: string[];
  exports?: string[];
}): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  const moduleImports: string[] = [];
  const providers: string[] = [];
  const controllers: string[] = [];
  const exports: string[] = [];

  let importStatements = `import { Module } from '@nestjs/common';\n`;

  if (options.withController) {
    importStatements += `import { ${className}Controller } from './${fileName}.controller';\n`;
    controllers.push(`${className}Controller`);
  }

  if (options.withService) {
    importStatements += `import { ${className}Service } from './${fileName}.service';\n`;
    providers.push(`${className}Service`);
    if (options.exports?.includes('service')) {
      exports.push(`${className}Service`);
    }
  }

  const code = `${importStatements}
@Module({${moduleImports.length ? `
  imports: [${moduleImports.join(', ')}],` : ''}${controllers.length ? `
  controllers: [${controllers.join(', ')}],` : ''}${providers.length ? `
  providers: [${providers.join(', ')}],` : ''}${exports.length ? `
  exports: [${exports.join(', ')}],` : ''}
})
export class ${className}Module {}
`;

  return {
    code,
    filename: `${fileName}.module.ts`,
    description: `Module for ${className}`,
  };
}

// Generate DTO
export function generateDto(name: string, type: 'create' | 'update', fields: {
  name: string;
  type: string;
  required?: boolean;
  validators?: string[];
}[]): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);
  const dtoType = type === 'create' ? 'Create' : 'Update';

  const validatorImports = new Set<string>();
  const transformerImports = new Set<string>();

  fields.forEach(field => {
    field.validators?.forEach(v => {
      if (v.startsWith('Is') || v.startsWith('Min') || v.startsWith('Max') || v.startsWith('Length')) {
        validatorImports.add(v);
      }
    });
    if (!field.required || type === 'update') {
      validatorImports.add('IsOptional');
    }
  });

  const imports = validatorImports.size > 0
    ? `import { ${Array.from(validatorImports).join(', ')} } from 'class-validator';\n`
    : '';

  const fieldCode = fields.map(field => {
    const decorators: string[] = [];

    if (!field.required || type === 'update') {
      decorators.push('@IsOptional()');
    }

    field.validators?.forEach(v => {
      decorators.push(`@${v}()`);
    });

    const optional = !field.required || type === 'update' ? '?' : '';

    return `  ${decorators.join('\n  ')}\n  ${field.name}${optional}: ${field.type};`;
  }).join('\n\n');

  const code = `${imports}
export class ${dtoType}${className}Dto {
${fieldCode}
}
`;

  return {
    code,
    filename: `${type}-${fileName}.dto.ts`,
    description: `${dtoType} DTO for ${className}`,
  };
}

// Generate Entity
export function generateEntity(name: string, fields: {
  name: string;
  type: string;
  primary?: boolean;
  unique?: boolean;
  nullable?: boolean;
  default?: string;
}[]): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  const fieldCode = fields.map(field => {
    const decorators: string[] = [];

    if (field.primary) {
      decorators.push('@PrimaryGeneratedColumn()');
    } else {
      const columnOptions: string[] = [];
      if (field.unique) columnOptions.push('unique: true');
      if (field.nullable) columnOptions.push('nullable: true');
      if (field.default) columnOptions.push(`default: ${field.default}`);

      const optionsStr = columnOptions.length > 0 ? `{ ${columnOptions.join(', ')} }` : '';
      decorators.push(`@Column(${optionsStr})`);
    }

    return `  ${decorators.join('\n  ')}\n  ${field.name}: ${field.type};`;
  }).join('\n\n');

  const code = `import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('${toSnakeCase(name)}s')
export class ${className} {
${fieldCode}

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
`;

  return {
    code,
    filename: `${fileName}.entity.ts`,
    description: `TypeORM entity for ${className}`,
  };
}

// Generate Guard
export function generateGuard(name: string, type: 'auth' | 'roles' | 'custom'): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  let code: string;

  switch (type) {
    case 'auth':
      code = `import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class ${className}Guard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      const payload = await this.jwtService.verifyAsync(token);
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException('Invalid token');
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
`;
      break;

    case 'roles':
      code = `import {
  Injectable,
  CanActivate,
  ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);

@Injectable()
export class ${className}Guard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();

    if (!user || !user.roles) {
      return false;
    }

    return requiredRoles.some((role) => user.roles.includes(role));
  }
}
`;
      break;

    default:
      code = `import {
  Injectable,
  CanActivate,
  ExecutionContext,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class ${className}Guard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();

    // Add your guard logic here
    return true;
  }
}
`;
  }

  return {
    code,
    filename: `${fileName}.guard.ts`,
    description: `${type} guard: ${className}Guard`,
  };
}

// Generate Interceptor
export function generateInterceptor(name: string, type: 'logging' | 'transform' | 'cache' | 'timeout' | 'custom'): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  let code: string;

  switch (type) {
    case 'logging':
      code = `import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class ${className}Interceptor implements NestInterceptor {
  private readonly logger = new Logger(${className}Interceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    const now = Date.now();

    this.logger.log(\`Incoming: \${method} \${url}\`);

    return next.handle().pipe(
      tap(() => {
        this.logger.log(\`Outgoing: \${method} \${url} - \${Date.now() - now}ms\`);
      }),
    );
  }
}
`;
      break;

    case 'transform':
      code = `import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
  success: boolean;
  data: T;
  timestamp: string;
}

@Injectable()
export class ${className}Interceptor<T> implements NestInterceptor<T, Response<T>> {
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    return next.handle().pipe(
      map((data) => ({
        success: true,
        data,
        timestamp: new Date().toISOString(),
      })),
    );
  }
}
`;
      break;

    case 'timeout':
      code = `import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  RequestTimeoutException,
} from '@nestjs/common';
import { Observable, throwError, TimeoutError } from 'rxjs';
import { catchError, timeout } from 'rxjs/operators';

@Injectable()
export class ${className}Interceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError) {
          return throwError(() => new RequestTimeoutException());
        }
        return throwError(() => err);
      }),
    );
  }
}
`;
      break;

    default:
      code = `import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class ${className}Interceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // Before handler execution
    console.log('Before...');

    return next.handle().pipe(
      // After handler execution
    );
  }
}
`;
  }

  return {
    code,
    filename: `${fileName}.interceptor.ts`,
    description: `${type} interceptor: ${className}Interceptor`,
  };
}

// Generate Pipe
export function generatePipe(name: string, type: 'validation' | 'transform' | 'custom'): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  let code: string;

  switch (type) {
    case 'validation':
      code = `import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';

@Injectable()
export class ${className}Pipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    if (!value) {
      throw new BadRequestException('Value is required');
    }

    // Add your validation logic here

    return value;
  }
}
`;
      break;

    case 'transform':
      code = `import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
} from '@nestjs/common';

@Injectable()
export class ${className}Pipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    // Transform the value
    if (typeof value === 'string') {
      return value.trim().toLowerCase();
    }

    return value;
  }
}
`;
      break;

    default:
      code = `import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
} from '@nestjs/common';

@Injectable()
export class ${className}Pipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    // Add your pipe logic here
    return value;
  }
}
`;
  }

  return {
    code,
    filename: `${fileName}.pipe.ts`,
    description: `${type} pipe: ${className}Pipe`,
  };
}

// Generate Exception Filter
export function generateFilter(name: string, exceptionType: string = 'HttpException'): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  const code = `import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  ${exceptionType},
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(${exceptionType})
export class ${className}Filter implements ExceptionFilter {
  private readonly logger = new Logger(${className}Filter.name);

  catch(exception: ${exceptionType}, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof ${exceptionType}
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof ${exceptionType}
        ? exception.message
        : 'Internal server error';

    this.logger.error(
      \`\${request.method} \${request.url} - \${status}: \${message}\`,
      exception.stack,
    );

    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
    });
  }
}
`;

  return {
    code,
    filename: `${fileName}.filter.ts`,
    description: `Exception filter for ${exceptionType}`,
  };
}

// Generate Middleware
export function generateMiddleware(name: string): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  const code = `import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class ${className}Middleware implements NestMiddleware {
  private readonly logger = new Logger(${className}Middleware.name);

  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl, ip } = req;

    this.logger.log(\`[\${ip}] \${method} \${originalUrl}\`);

    // Add your middleware logic here

    next();
  }
}
`;

  return {
    code,
    filename: `${fileName}.middleware.ts`,
    description: `Middleware: ${className}Middleware`,
  };
}

// Generate complete resource (CRUD)
export function generateResource(name: string): GenerateResult {
  const className = toPascalCase(name);
  const fileName = toKebabCase(name);

  const controller = generateController(name, { crud: true });
  const service = generateService(name, { crud: true, withRepository: true });
  const module = generateModule(name, { withController: true, withService: true });

  const entity = generateEntity(name, [
    { name: 'id', type: 'number', primary: true },
    { name: 'name', type: 'string' },
    { name: 'description', type: 'string', nullable: true },
    { name: 'isActive', type: 'boolean', default: 'true' },
  ]);

  const createDto = generateDto(name, 'create', [
    { name: 'name', type: 'string', required: true, validators: ['IsString', 'IsNotEmpty'] },
    { name: 'description', type: 'string', required: false, validators: ['IsString'] },
    { name: 'isActive', type: 'boolean', required: false, validators: ['IsBoolean'] },
  ]);

  const updateDto = generateDto(name, 'update', [
    { name: 'name', type: 'string', required: false, validators: ['IsString'] },
    { name: 'description', type: 'string', required: false, validators: ['IsString'] },
    { name: 'isActive', type: 'boolean', required: false, validators: ['IsBoolean'] },
  ]);

  return {
    code: module.code,
    filename: `${fileName}/${module.filename}`,
    description: `Complete CRUD resource for ${className}`,
    additionalFiles: [
      { filename: `${fileName}/${controller.filename}`, code: controller.code },
      { filename: `${fileName}/${service.filename}`, code: service.code },
      { filename: `${fileName}/entities/${entity.filename}`, code: entity.code },
      { filename: `${fileName}/dto/${createDto.filename}`, code: createDto.code },
      { filename: `${fileName}/dto/${updateDto.filename}`, code: updateDto.code },
    ],
  };
}

// Helper functions
function generateControllerMethod(method: string, className: string): string {
  const methodLower = method.toLowerCase();
  const camelName = toCamelCase(className);

  switch (methodLower) {
    case 'findall':
      return `  @Get()
  findAll() {
    return this.${camelName}Service.findAll();
  }`;
    case 'findone':
      return `  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.${camelName}Service.findOne(+id);
  }`;
    case 'create':
      return `  @Post()
  create(@Body() createDto: any) {
    return this.${camelName}Service.create(createDto);
  }`;
    case 'update':
      return `  @Put(':id')
  update(@Param('id') id: string, @Body() updateDto: any) {
    return this.${camelName}Service.update(+id, updateDto);
  }`;
    case 'remove':
    case 'delete':
      return `  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.${camelName}Service.remove(+id);
  }`;
    default:
      return `  @Get('${methodLower}')
  ${methodLower}() {
    return this.${camelName}Service.${methodLower}();
  }`;
  }
}

function toPascalCase(str: string): string {
  return str
    .replace(/[-_](.)/g, (_, c) => c.toUpperCase())
    .replace(/^(.)/, (_, c) => c.toUpperCase());
}

function toCamelCase(str: string): string {
  return str
    .replace(/[-_](.)/g, (_, c) => c.toUpperCase())
    .replace(/^(.)/, (_, c) => c.toLowerCase());
}

function toKebabCase(str: string): string {
  return str
    .replace(/([a-z])([A-Z])/g, '$1-$2')
    .replace(/[_\s]+/g, '-')
    .toLowerCase();
}

function toSnakeCase(str: string): string {
  return str
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[-\s]+/g, '_')
    .toLowerCase();
}
