// NestJS Project Scaffolding Tools

export interface ScaffoldResult {
  files: { path: string; content: string }[];
  instructions: string[];
  dependencies: string[];
  devDependencies: string[];
}

// Generate complete project scaffold
export function scaffoldProject(name: string, options: {
  database?: 'postgres' | 'mysql' | 'mongodb' | 'sqlite';
  auth?: boolean;
  swagger?: boolean;
  docker?: boolean;
  testing?: boolean;
  websockets?: boolean;
}): ScaffoldResult {
  const files: { path: string; content: string }[] = [];
  const dependencies: string[] = [
    '@nestjs/common',
    '@nestjs/core',
    '@nestjs/platform-express',
    'reflect-metadata',
    'rxjs',
  ];
  const devDependencies: string[] = [
    '@nestjs/cli',
    '@nestjs/schematics',
    '@types/node',
    'typescript',
    'ts-node',
  ];
  const instructions: string[] = [];

  // Main.ts
  files.push({
    path: 'src/main.ts',
    content: generateMainTs(options),
  });

  // App Module
  files.push({
    path: 'src/app.module.ts',
    content: generateAppModule(options),
  });

  // App Controller
  files.push({
    path: 'src/app.controller.ts',
    content: `import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('health')
  health() {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }
}
`,
  });

  // App Service
  files.push({
    path: 'src/app.service.ts',
    content: `import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }
}
`,
  });

  // Config
  files.push({
    path: 'src/config/configuration.ts',
    content: generateConfiguration(options),
  });
  dependencies.push('@nestjs/config');

  // Database setup
  if (options.database) {
    const dbFiles = generateDatabaseFiles(options.database);
    files.push(...dbFiles.files);
    dependencies.push(...dbFiles.dependencies);
    devDependencies.push(...dbFiles.devDependencies);
    instructions.push(...dbFiles.instructions);
  }

  // Auth setup
  if (options.auth) {
    const authFiles = generateAuthFiles();
    files.push(...authFiles.files);
    dependencies.push(...authFiles.dependencies);
    instructions.push('Configure JWT_SECRET in .env file');
  }

  // Swagger setup
  if (options.swagger) {
    dependencies.push('@nestjs/swagger');
    instructions.push('Swagger available at /api endpoint');
  }

  // Docker setup
  if (options.docker) {
    files.push(
      { path: 'Dockerfile', content: generateDockerfile() },
      { path: 'docker-compose.yml', content: generateDockerCompose(options) },
      { path: '.dockerignore', content: generateDockerIgnore() },
    );
    instructions.push('Run with: docker-compose up');
  }

  // WebSockets setup
  if (options.websockets) {
    const wsFiles = generateWebSocketFiles();
    files.push(...wsFiles.files);
    dependencies.push('@nestjs/websockets', '@nestjs/platform-socket.io', 'socket.io');
    devDependencies.push('@types/socket.io');
  }

  // Testing setup
  if (options.testing) {
    devDependencies.push(
      '@nestjs/testing',
      'jest',
      '@types/jest',
      'ts-jest',
      'supertest',
      '@types/supertest'
    );
    files.push({
      path: 'jest.config.js',
      content: generateJestConfig(),
    });
    files.push({
      path: 'test/app.e2e-spec.ts',
      content: generateE2ETest(),
    });
  }

  // Common files
  files.push(
    { path: '.env.example', content: generateEnvExample(options) },
    { path: '.gitignore', content: generateGitIgnore() },
    { path: 'tsconfig.json', content: generateTsConfig() },
    { path: 'package.json', content: generatePackageJson(name, dependencies, devDependencies, options) },
    { path: 'nest-cli.json', content: generateNestCliJson() },
  );

  // Common module
  files.push(...generateCommonModule());

  return { files, instructions, dependencies, devDependencies };
}

function generateMainTs(options: any): string {
  let imports = `import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';`;

  let setup = '';

  if (options.swagger) {
    imports += `\nimport { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';`;
    setup += `
  // Swagger setup
  const config = new DocumentBuilder()
    .setTitle('API Documentation')
    .setDescription('API endpoints documentation')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
`;
  }

  return `${imports}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Global validation pipe
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    transformOptions: {
      enableImplicitConversion: true,
    },
  }));

  // CORS
  app.enableCors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  });

  // Global prefix
  app.setGlobalPrefix('api', {
    exclude: ['health'],
  });
${setup}
  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(\`Application running on: http://localhost:\${port}\`);
}
bootstrap();
`;
}

function generateAppModule(options: any): string {
  const imports: string[] = ['ConfigModule.forRoot({ isGlobal: true, load: [configuration] })'];
  const moduleImports: string[] = [`import { Module } from '@nestjs/common';`, `import configuration from './config/configuration';`, `import { ConfigModule } from '@nestjs/config';`];
  const providers: string[] = ['AppService'];
  const controllers: string[] = ['AppController'];

  moduleImports.push(`import { AppController } from './app.controller';`);
  moduleImports.push(`import { AppService } from './app.service';`);

  if (options.database === 'postgres' || options.database === 'mysql' || options.database === 'sqlite') {
    moduleImports.push(`import { TypeOrmModule } from '@nestjs/typeorm';`);
    moduleImports.push(`import { ConfigService } from '@nestjs/config';`);
    imports.push(`TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: '${options.database}',
        host: configService.get('database.host'),
        port: configService.get('database.port'),
        username: configService.get('database.username'),
        password: configService.get('database.password'),
        database: configService.get('database.name'),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: configService.get('NODE_ENV') !== 'production',
      }),
      inject: [ConfigService],
    })`);
  }

  if (options.database === 'mongodb') {
    moduleImports.push(`import { MongooseModule } from '@nestjs/mongoose';`);
    moduleImports.push(`import { ConfigService } from '@nestjs/config';`);
    imports.push(`MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        uri: configService.get('database.uri'),
      }),
      inject: [ConfigService],
    })`);
  }

  if (options.auth) {
    moduleImports.push(`import { AuthModule } from './auth/auth.module';`);
    imports.push('AuthModule');
  }

  if (options.websockets) {
    moduleImports.push(`import { EventsModule } from './events/events.module';`);
    imports.push('EventsModule');
  }

  return `${moduleImports.join('\n')}

@Module({
  imports: [
    ${imports.join(',\n    ')},
  ],
  controllers: [${controllers.join(', ')}],
  providers: [${providers.join(', ')}],
})
export class AppModule {}
`;
}

function generateConfiguration(options: any): string {
  let dbConfig = '';

  if (options.database === 'postgres' || options.database === 'mysql' || options.database === 'sqlite') {
    dbConfig = `
  database: {
    type: '${options.database}',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || ${options.database === 'postgres' ? 5432 : 3306},
    username: process.env.DB_USERNAME || 'root',
    password: process.env.DB_PASSWORD || '',
    name: process.env.DB_NAME || '${options.database === 'sqlite' ? 'database.sqlite' : 'app'}',
  },`;
  }

  if (options.database === 'mongodb') {
    dbConfig = `
  database: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/app',
  },`;
  }

  return `export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',${dbConfig}
  jwt: {
    secret: process.env.JWT_SECRET || 'super-secret-key-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
  },
});
`;
}

function generateDatabaseFiles(db: string): { files: any[]; dependencies: string[]; devDependencies: string[]; instructions: string[] } {
  const files: any[] = [];
  const dependencies: string[] = [];
  const devDependencies: string[] = [];
  const instructions: string[] = [];

  if (db === 'postgres' || db === 'mysql' || db === 'sqlite') {
    dependencies.push('@nestjs/typeorm', 'typeorm');
    if (db === 'postgres') {
      dependencies.push('pg');
      instructions.push('Configure PostgreSQL connection in .env');
    } else if (db === 'mysql') {
      dependencies.push('mysql2');
      instructions.push('Configure MySQL connection in .env');
    } else {
      dependencies.push('better-sqlite3');
      devDependencies.push('@types/better-sqlite3');
    }

    // Base entity
    files.push({
      path: 'src/common/entities/base.entity.ts',
      content: `import {
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

export abstract class BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
`,
    });
  }

  if (db === 'mongodb') {
    dependencies.push('@nestjs/mongoose', 'mongoose');
    instructions.push('Configure MongoDB connection in .env');

    // Base schema
    files.push({
      path: 'src/common/schemas/base.schema.ts',
      content: `import { Prop, Schema } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class BaseSchema extends Document {
  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}
`,
    });
  }

  return { files, dependencies, devDependencies, instructions };
}

function generateAuthFiles(): { files: any[]; dependencies: string[] } {
  const files: any[] = [];
  const dependencies = ['@nestjs/passport', '@nestjs/jwt', 'passport', 'passport-jwt', 'passport-local', 'bcrypt'];

  files.push({
    path: 'src/auth/auth.module.ts',
    content: `import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('jwt.secret'),
        signOptions: { expiresIn: configService.get('jwt.expiresIn') },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, LocalStrategy],
  exports: [AuthService],
})
export class AuthModule {}
`,
  });

  files.push({
    path: 'src/auth/auth.service.ts',
    content: `import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private jwtService: JwtService) {}

  async validateUser(email: string, password: string): Promise<any> {
    // TODO: Replace with actual user lookup
    const user = { id: '1', email, password: await bcrypt.hash('password', 10) };

    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id };
    return {
      accessToken: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
      },
    };
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }
}
`,
  });

  files.push({
    path: 'src/auth/auth.controller.ts',
    content: `import { Controller, Post, UseGuards, Body, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { Public } from './decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @Post('logout')
  async logout() {
    return { message: 'Logged out successfully' };
  }
}
`,
  });

  files.push({
    path: 'src/auth/strategies/jwt.strategy.ts',
    content: `import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt.secret'),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
`,
  });

  files.push({
    path: 'src/auth/strategies/local.strategy.ts',
    content: `import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }
}
`,
  });

  files.push({
    path: 'src/auth/guards/jwt-auth.guard.ts',
    content: `import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    return super.canActivate(context);
  }
}
`,
  });

  files.push({
    path: 'src/auth/guards/local-auth.guard.ts',
    content: `import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
`,
  });

  files.push({
    path: 'src/auth/decorators/public.decorator.ts',
    content: `import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
`,
  });

  files.push({
    path: 'src/auth/decorators/current-user.decorator.ts',
    content: `import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUser = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    return data ? user?.[data] : user;
  },
);
`,
  });

  files.push({
    path: 'src/auth/dto/login.dto.ts',
    content: `import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;
}
`,
  });

  return { files, dependencies };
}

function generateWebSocketFiles(): { files: any[] } {
  const files: any[] = [];

  files.push({
    path: 'src/events/events.module.ts',
    content: `import { Module } from '@nestjs/common';
import { EventsGateway } from './events.gateway';

@Module({
  providers: [EventsGateway],
  exports: [EventsGateway],
})
export class EventsModule {}
`,
  });

  files.push({
    path: 'src/events/events.gateway.ts',
    content: `import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';

@WebSocketGateway({
  cors: { origin: '*' },
  namespace: 'events',
})
export class EventsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(EventsGateway.name);

  handleConnection(client: Socket) {
    this.logger.log(\`Client connected: \${client.id}\`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(\`Client disconnected: \${client.id}\`);
  }

  @SubscribeMessage('message')
  handleMessage(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { room: string; message: string },
  ) {
    this.server.to(data.room).emit('message', {
      sender: client.id,
      message: data.message,
      timestamp: new Date(),
    });
  }

  @SubscribeMessage('join')
  handleJoin(
    @ConnectedSocket() client: Socket,
    @MessageBody() room: string,
  ) {
    client.join(room);
    this.server.to(room).emit('userJoined', { id: client.id });
    return { event: 'joined', room };
  }

  @SubscribeMessage('leave')
  handleLeave(
    @ConnectedSocket() client: Socket,
    @MessageBody() room: string,
  ) {
    client.leave(room);
    this.server.to(room).emit('userLeft', { id: client.id });
    return { event: 'left', room };
  }

  // Broadcast to all clients
  broadcast(event: string, data: any) {
    this.server.emit(event, data);
  }

  // Send to specific room
  sendToRoom(room: string, event: string, data: any) {
    this.server.to(room).emit(event, data);
  }
}
`,
  });

  return { files };
}

function generateDockerfile(): string {
  return `# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY --from=builder /app/dist ./dist

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001
USER nestjs

EXPOSE 3000

CMD ["node", "dist/main"]
`;
}

function generateDockerCompose(options: any): string {
  let services = `version: '3.8'

services:
  app:
    build: .
    ports:
      - "\${PORT:-3000}:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000`;

  if (options.database === 'postgres') {
    services += `
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USERNAME=\${DB_USERNAME:-postgres}
      - DB_PASSWORD=\${DB_PASSWORD:-postgres}
      - DB_NAME=\${DB_NAME:-app}
    depends_on:
      - postgres

  postgres:
    image: postgres:15-alpine
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=\${DB_USERNAME:-postgres}
      - POSTGRES_PASSWORD=\${DB_PASSWORD:-postgres}
      - POSTGRES_DB=\${DB_NAME:-app}
    volumes:
      - postgres_data:/var/lib/postgresql/data`;
  }

  if (options.database === 'mysql') {
    services += `
      - DB_HOST=mysql
      - DB_PORT=3306
      - DB_USERNAME=\${DB_USERNAME:-root}
      - DB_PASSWORD=\${DB_PASSWORD:-root}
      - DB_NAME=\${DB_NAME:-app}
    depends_on:
      - mysql

  mysql:
    image: mysql:8
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=\${DB_PASSWORD:-root}
      - MYSQL_DATABASE=\${DB_NAME:-app}
    volumes:
      - mysql_data:/var/lib/mysql`;
  }

  if (options.database === 'mongodb') {
    services += `
      - MONGODB_URI=mongodb://mongodb:27017/app
    depends_on:
      - mongodb

  mongodb:
    image: mongo:6
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db`;
  }

  services += `

volumes:`;

  if (options.database === 'postgres') services += `\n  postgres_data:`;
  if (options.database === 'mysql') services += `\n  mysql_data:`;
  if (options.database === 'mongodb') services += `\n  mongodb_data:`;

  return services;
}

function generateDockerIgnore(): string {
  return `node_modules
dist
.git
.gitignore
.env
.env.*
*.md
.docker
Dockerfile*
docker-compose*
.dockerignore
.eslintrc.js
.prettierrc
jest.config.js
test
coverage
`;
}

function generateJestConfig(): string {
  return `module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: ['**/*.(t|j)s'],
  coverageDirectory: '../coverage',
  testEnvironment: 'node',
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/$1',
  },
};
`;
}

function generateE2ETest(): string {
  return `import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });

  it('/health (GET)', () => {
    return request(app.getHttpServer())
      .get('/health')
      .expect(200)
      .expect((res) => {
        expect(res.body.status).toBe('ok');
        expect(res.body.timestamp).toBeDefined();
      });
  });
});
`;
}

function generateEnvExample(options: any): string {
  let env = `# Application
NODE_ENV=development
PORT=3000
CORS_ORIGIN=http://localhost:3000
`;

  if (options.database === 'postgres' || options.database === 'mysql') {
    env += `
# Database
DB_HOST=localhost
DB_PORT=${options.database === 'postgres' ? 5432 : 3306}
DB_USERNAME=
DB_PASSWORD=
DB_NAME=app
`;
  }

  if (options.database === 'mongodb') {
    env += `
# MongoDB
MONGODB_URI=mongodb://localhost:27017/app
`;
  }

  if (options.auth) {
    env += `
# JWT
JWT_SECRET=your-super-secret-key-change-in-production
JWT_EXPIRES_IN=1d
`;
  }

  env += `
# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
`;

  return env;
}

function generateGitIgnore(): string {
  return `# Dependencies
node_modules/

# Build
dist/

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Environment
.env
.env.local
.env.*.local

# Test
coverage/

# Cache
.npm
.cache
.turbo

# Docker
.docker/
`;
}

function generateTsConfig(): string {
  return `{
  "compilerOptions": {
    "module": "commonjs",
    "declaration": true,
    "removeComments": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "allowSyntheticDefaultImports": true,
    "target": "ES2021",
    "sourceMap": true,
    "outDir": "./dist",
    "baseUrl": "./",
    "incremental": true,
    "skipLibCheck": true,
    "strictNullChecks": true,
    "noImplicitAny": true,
    "strictBindCallApply": true,
    "forceConsistentCasingInFileNames": true,
    "noFallthroughCasesInSwitch": true,
    "paths": {
      "@/*": ["src/*"]
    }
  }
}
`;
}

function generatePackageJson(name: string, deps: string[], devDeps: string[], options: any): string {
  const pkg = {
    name,
    version: '0.0.1',
    description: '',
    author: '',
    license: 'MIT',
    scripts: {
      build: 'nest build',
      format: 'prettier --write "src/**/*.ts" "test/**/*.ts"',
      start: 'nest start',
      'start:dev': 'nest start --watch',
      'start:debug': 'nest start --debug --watch',
      'start:prod': 'node dist/main',
      lint: 'eslint "{src,apps,libs,test}/**/*.ts" --fix',
      test: 'jest',
      'test:watch': 'jest --watch',
      'test:cov': 'jest --coverage',
      'test:debug': 'node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand',
      'test:e2e': 'jest --config ./test/jest-e2e.json',
    },
    dependencies: {} as Record<string, string>,
    devDependencies: {} as Record<string, string>,
  };

  // Add versions
  deps.forEach((d) => {
    pkg.dependencies[d] = 'latest';
  });
  devDeps.forEach((d) => {
    pkg.devDependencies[d] = 'latest';
  });

  // Add class-validator and class-transformer
  pkg.dependencies['class-validator'] = 'latest';
  pkg.dependencies['class-transformer'] = 'latest';

  return JSON.stringify(pkg, null, 2);
}

function generateNestCliJson(): string {
  return `{
  "$schema": "https://json.schemastore.org/nest-cli",
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true
  }
}
`;
}

function generateCommonModule(): { path: string; content: string }[] {
  return [
    {
      path: 'src/common/filters/http-exception.filter.ts',
      content: `import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof HttpException
        ? exception.message
        : 'Internal server error';

    const errorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message,
    };

    this.logger.error(
      \`\${request.method} \${request.url} \${status}\`,
      exception instanceof Error ? exception.stack : '',
    );

    response.status(status).json(errorResponse);
  }
}
`,
    },
    {
      path: 'src/common/interceptors/logging.interceptor.ts',
      content: `import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    const now = Date.now();

    return next.handle().pipe(
      tap(() => {
        const response = context.switchToHttp().getResponse();
        this.logger.log(
          \`\${method} \${url} \${response.statusCode} - \${Date.now() - now}ms\`,
        );
      }),
    );
  }
}
`,
    },
    {
      path: 'src/common/interceptors/transform.interceptor.ts',
      content: `import {
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
export class TransformInterceptor<T>
  implements NestInterceptor<T, Response<T>>
{
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
`,
    },
    {
      path: 'src/common/dto/pagination.dto.ts',
      content: `import { IsOptional, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class PaginationDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 10;

  get skip(): number {
    return (this.page - 1) * this.limit;
  }
}

export class PaginatedResponse<T> {
  data: T[];
  meta: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };

  constructor(data: T[], total: number, pagination: PaginationDto) {
    this.data = data;
    this.meta = {
      page: pagination.page,
      limit: pagination.limit,
      total,
      totalPages: Math.ceil(total / pagination.limit),
    };
  }
}
`,
    },
  ];
}
