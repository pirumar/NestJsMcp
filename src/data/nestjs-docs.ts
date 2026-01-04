// NestJS Documentation Data
// Comprehensive reference for NestJS concepts, patterns, and best practices

export interface DocSection {
  title: string;
  description: string;
  content: string;
  examples?: string[];
  relatedTopics?: string[];
}

export interface CLICommand {
  command: string;
  alias?: string;
  description: string;
  options?: { flag: string; description: string }[];
  examples?: string[];
}

export interface Decorator {
  name: string;
  type: "class" | "method" | "parameter" | "property";
  description: string;
  usage: string;
  parameters?: string[];
}

// ============================================
// CORE CONCEPTS
// ============================================

export const coreConcepts: Record<string, DocSection> = {
  modules: {
    title: "Modules",
    description: "Modules are the fundamental building blocks of NestJS applications",
    content: `Modules are classes annotated with @Module() decorator. They organize the application structure by grouping related components.

Every NestJS application has at least one module - the root module (AppModule). Modules encapsulate providers, controllers, imports, and exports.

Key properties of @Module() decorator:
- providers: Services that will be instantiated by the Nest injector
- controllers: Controllers that should be instantiated
- imports: List of imported modules that export providers required in this module
- exports: Providers that should be available to other modules

Best Practices:
- Create a module per feature (UserModule, AuthModule, ProductModule)
- Use shared modules for common functionality
- Keep modules focused and cohesive`,
    examples: [
      `@Module({
  imports: [DatabaseModule, ConfigModule],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService]
})
export class UserModule {}`,
      `// Dynamic module example
@Module({})
export class ConfigModule {
  static forRoot(options: ConfigOptions): DynamicModule {
    return {
      module: ConfigModule,
      providers: [
        { provide: CONFIG_OPTIONS, useValue: options },
        ConfigService
      ],
      exports: [ConfigService]
    };
  }
}`
    ],
    relatedTopics: ["providers", "controllers", "dependency-injection"]
  },

  controllers: {
    title: "Controllers",
    description: "Controllers handle incoming requests and return responses",
    content: `Controllers are responsible for handling incoming HTTP requests and returning responses to the client.

Key decorators:
- @Controller(): Defines a controller class, optionally with a route prefix
- @Get(), @Post(), @Put(), @Delete(), @Patch(): HTTP method decorators
- @Param(): Extract route parameters
- @Query(): Extract query parameters
- @Body(): Extract request body
- @Headers(): Extract headers
- @Req(), @Res(): Access Express/Fastify request/response objects

Response handling:
- Return values are automatically serialized to JSON
- Use @Res() for manual response handling (disables automatic serialization)
- Throw HttpException for error responses`,
    examples: [
      `@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  findAll(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string): Promise<User> {
    return this.userService.findOne(+id);
  }

  @Post()
  create(@Body() createUserDto: CreateUserDto): Promise<User> {
    return this.userService.create(createUserDto);
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.userService.remove(+id);
  }
}`,
      `// Using route parameters and query
@Get('search')
search(
  @Query('q') query: string,
  @Query('limit', ParseIntPipe) limit: number
) {
  return this.searchService.search(query, limit);
}`
    ],
    relatedTopics: ["modules", "providers", "pipes", "guards"]
  },

  providers: {
    title: "Providers",
    description: "Providers are injectable classes that contain business logic",
    content: `Providers are a fundamental concept in NestJS. Services, repositories, factories, helpers can all be providers.

The main idea is that a provider can be injected as a dependency. NestJS uses dependency injection to manage providers.

Provider types:
- Standard providers: Classes with @Injectable() decorator
- Value providers: useValue for static values
- Class providers: useClass for dynamic class selection
- Factory providers: useFactory for dynamic provider creation
- Existing providers: useExisting for aliasing

Scope options:
- DEFAULT: Singleton, shared across the application
- REQUEST: New instance per request
- TRANSIENT: New instance per injection`,
    examples: [
      `@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private configService: ConfigService
  ) {}

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  async findOne(id: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(\`User #\${id} not found\`);
    }
    return user;
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = this.userRepository.create(createUserDto);
    return this.userRepository.save(user);
  }
}`,
      `// Custom provider examples
const providers = [
  // Value provider
  { provide: 'API_KEY', useValue: process.env.API_KEY },

  // Factory provider
  {
    provide: 'DATABASE_CONNECTION',
    useFactory: async (configService: ConfigService) => {
      return createConnection(configService.get('database'));
    },
    inject: [ConfigService]
  },

  // Class provider
  {
    provide: UserService,
    useClass: process.env.NODE_ENV === 'test'
      ? MockUserService
      : UserService
  }
];`
    ],
    relatedTopics: ["modules", "dependency-injection", "scope"]
  },

  middleware: {
    title: "Middleware",
    description: "Functions executed before route handlers",
    content: `Middleware are functions that have access to the request, response, and next middleware function.

Middleware can:
- Execute any code
- Make changes to request/response objects
- End the request-response cycle
- Call the next middleware function

Implementation options:
- Functional middleware: Simple functions
- Class middleware: Classes implementing NestMiddleware interface

Apply middleware in module's configure() method using MiddlewareConsumer.`,
    examples: [
      `// Class middleware
@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    console.log(\`[\${new Date().toISOString()}] \${req.method} \${req.url}\`);
    next();
  }
}

// Functional middleware
export function logger(req: Request, res: Response, next: NextFunction) {
  console.log(\`Request...\`);
  next();
}

// Apply in module
@Module({})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LoggerMiddleware)
      .exclude(
        { path: 'health', method: RequestMethod.GET }
      )
      .forRoutes('*');
  }
}`
    ],
    relatedTopics: ["guards", "interceptors", "filters"]
  },

  guards: {
    title: "Guards",
    description: "Determine if a request should be handled by the route handler",
    content: `Guards determine whether a given request will be handled by the route handler or not, depending on certain conditions.

Guards are executed AFTER middleware but BEFORE interceptors and pipes.

Common use cases:
- Authentication
- Authorization (roles, permissions)
- Rate limiting
- Feature flags

Guards implement CanActivate interface and return boolean or Promise<boolean>.

Apply guards using @UseGuards() decorator at controller or method level, or globally.`,
    examples: [
      `// Auth guard
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync(token);
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}`,
      `// Roles guard
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}

// Usage
@Roles(Role.Admin)
@UseGuards(AuthGuard, RolesGuard)
@Controller('admin')
export class AdminController {}`
    ],
    relatedTopics: ["authentication", "authorization", "decorators"]
  },

  interceptors: {
    title: "Interceptors",
    description: "Transform data before/after method execution using RxJS",
    content: `Interceptors have a set of useful capabilities inspired by Aspect Oriented Programming (AOP).

Capabilities:
- Bind extra logic before/after method execution
- Transform the result returned from a function
- Transform exceptions thrown from a function
- Extend basic function behavior
- Override a function based on conditions (e.g., caching)

Interceptors use RxJS Observables, allowing powerful stream manipulation.

Common use cases:
- Logging
- Caching
- Response transformation
- Timeout handling
- Exception mapping`,
    examples: [
      `// Logging interceptor
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const now = Date.now();
    const request = context.switchToHttp().getRequest();

    console.log(\`Before: \${request.method} \${request.url}\`);

    return next.handle().pipe(
      tap(() => console.log(\`After: \${Date.now() - now}ms\`))
    );
  }
}`,
      `// Transform response interceptor
@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, Response<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<Response<T>> {
    return next.handle().pipe(
      map(data => ({
        success: true,
        data,
        timestamp: new Date().toISOString()
      }))
    );
  }
}`,
      `// Cache interceptor
@Injectable()
export class CacheInterceptor implements NestInterceptor {
  constructor(private cacheService: CacheService) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const key = context.switchToHttp().getRequest().url;
    const cached = await this.cacheService.get(key);

    if (cached) {
      return of(cached);
    }

    return next.handle().pipe(
      tap(data => this.cacheService.set(key, data))
    );
  }
}`
    ],
    relatedTopics: ["rxjs", "aop", "caching", "logging"]
  },

  pipes: {
    title: "Pipes",
    description: "Transform and validate input data",
    content: `Pipes have two typical use cases:
- Transformation: Transform input data to the desired form
- Validation: Evaluate input data and throw exception if invalid

Built-in pipes:
- ValidationPipe: Validates DTOs using class-validator
- ParseIntPipe: Parses string to integer
- ParseFloatPipe: Parses string to float
- ParseBoolPipe: Parses string to boolean
- ParseArrayPipe: Parses string to array
- ParseUUIDPipe: Validates and parses UUID strings
- ParseEnumPipe: Validates enum values
- DefaultValuePipe: Provides default values

Pipes can be applied at parameter, method, controller, or global level.`,
    examples: [
      `// Using built-in pipes
@Get(':id')
findOne(@Param('id', ParseIntPipe) id: number) {
  return this.userService.findOne(id);
}

@Get()
findAll(
  @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
  @Query('limit', new DefaultValuePipe(10), ParseIntPipe) limit: number
) {
  return this.userService.findAll({ page, limit });
}`,
      `// Custom validation pipe
@Injectable()
export class JoiValidationPipe implements PipeTransform {
  constructor(private schema: ObjectSchema) {}

  transform(value: any, metadata: ArgumentMetadata) {
    const { error } = this.schema.validate(value);
    if (error) {
      throw new BadRequestException('Validation failed');
    }
    return value;
  }
}`,
      `// Global validation pipe setup
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    transformOptions: {
      enableImplicitConversion: true
    }
  }));

  await app.listen(3000);
}`
    ],
    relatedTopics: ["validation", "transformation", "dto"]
  },

  filters: {
    title: "Exception Filters",
    description: "Handle exceptions across the application",
    content: `Exception filters handle all unhandled exceptions across the application.

NestJS provides built-in HttpException class and its subclasses:
- BadRequestException (400)
- UnauthorizedException (401)
- ForbiddenException (403)
- NotFoundException (404)
- ConflictException (409)
- InternalServerErrorException (500)

Custom exception filters implement ExceptionFilter interface and use @Catch() decorator.

Filters can be applied at method, controller, or global level.`,
    examples: [
      `// Custom exception filter
@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();

    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message: exception.message
    });
  }
}`,
      `// Catch all exceptions
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost;
    const ctx = host.switchToHttp();

    const httpStatus = exception instanceof HttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const responseBody = {
      statusCode: httpStatus,
      timestamp: new Date().toISOString(),
      path: httpAdapter.getRequestUrl(ctx.getRequest()),
    };

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
  }
}`
    ],
    relatedTopics: ["exceptions", "error-handling", "logging"]
  },

  decorators: {
    title: "Custom Decorators",
    description: "Create reusable decorators for common patterns",
    content: `NestJS allows creating custom decorators for various purposes:

- Parameter decorators: Extract data from requests
- Class decorators: Add metadata to classes
- Method decorators: Modify method behavior
- Property decorators: Add metadata to properties

Use createParamDecorator() for parameter decorators.
Use SetMetadata() for adding metadata to handlers.
Combine decorators using applyDecorators().`,
    examples: [
      `// Custom parameter decorator
export const User = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    return data ? user?.[data] : user;
  }
);

// Usage
@Get('profile')
getProfile(@User() user: UserEntity) {
  return user;
}

@Get('email')
getEmail(@User('email') email: string) {
  return { email };
}`,
      `// Roles decorator with metadata
export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);

// Usage
@Roles(Role.Admin, Role.Moderator)
@Get('admin')
adminEndpoint() {}`,
      `// Combined decorator
export function Auth(...roles: Role[]) {
  return applyDecorators(
    SetMetadata('roles', roles),
    UseGuards(AuthGuard, RolesGuard),
    ApiBearerAuth(),
    ApiUnauthorizedResponse({ description: 'Unauthorized' })
  );
}

// Usage
@Auth(Role.Admin)
@Get('dashboard')
getDashboard() {}`
    ],
    relatedTopics: ["guards", "pipes", "metadata"]
  }
};

// ============================================
// TECHNIQUES
// ============================================

export const techniques: Record<string, DocSection> = {
  database: {
    title: "Database Integration",
    description: "Connect to databases using TypeORM, Prisma, or other ORMs",
    content: `NestJS supports multiple database solutions:

TypeORM Integration:
- Install: @nestjs/typeorm typeorm
- Configure in AppModule with TypeOrmModule.forRoot()
- Use entities with @Entity() decorator
- Inject repositories with @InjectRepository()

Prisma Integration:
- Install: prisma @prisma/client
- Create PrismaService extending PrismaClient
- Use in modules as provider

Mongoose (MongoDB):
- Install: @nestjs/mongoose mongoose
- Configure with MongooseModule.forRoot()
- Define schemas with @Schema() decorator`,
    examples: [
      `// TypeORM configuration
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DB_HOST'),
        port: configService.get('DB_PORT'),
        username: configService.get('DB_USER'),
        password: configService.get('DB_PASS'),
        database: configService.get('DB_NAME'),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: configService.get('NODE_ENV') !== 'production',
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}`,
      `// Entity definition
@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @OneToMany(() => Post, post => post.author)
  posts: Post[];
}`
    ],
    relatedTopics: ["typeorm", "prisma", "mongoose", "repositories"]
  },

  authentication: {
    title: "Authentication",
    description: "Implement authentication using Passport.js and JWT",
    content: `NestJS authentication typically uses @nestjs/passport and @nestjs/jwt.

Setup steps:
1. Install dependencies: @nestjs/passport passport passport-local passport-jwt @nestjs/jwt
2. Create AuthModule with AuthService
3. Implement LocalStrategy for username/password auth
4. Implement JwtStrategy for token validation
5. Create AuthGuard for protecting routes

JWT Flow:
1. User submits credentials
2. Validate credentials, generate JWT
3. Client stores JWT, sends in Authorization header
4. JwtStrategy validates token on protected routes`,
    examples: [
      `// Auth module
@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: '1d' },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}`,
      `// JWT Strategy
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, username: payload.username };
  }
}`,
      `// Auth service
@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && await bcrypt.compare(pass, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}`
    ],
    relatedTopics: ["guards", "jwt", "passport", "security"]
  },

  validation: {
    title: "Validation",
    description: "Validate request data using class-validator and DTOs",
    content: `NestJS uses class-validator and class-transformer for validation.

Setup:
1. Install: class-validator class-transformer
2. Enable ValidationPipe globally
3. Create DTO classes with validation decorators
4. Use DTOs in controller method parameters

Common decorators:
- @IsString(), @IsNumber(), @IsBoolean()
- @IsEmail(), @IsUrl(), @IsUUID()
- @MinLength(), @MaxLength(), @Length()
- @Min(), @Max()
- @IsOptional(), @IsNotEmpty()
- @ValidateNested() with @Type()
- @IsArray(), @ArrayMinSize(), @ArrayMaxSize()`,
    examples: [
      `// DTO with validation
export class CreateUserDto {
  @IsString()
  @MinLength(2)
  @MaxLength(50)
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)/, {
    message: 'Password must contain uppercase, lowercase and number'
  })
  password: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(150)
  age?: number;

  @IsOptional()
  @ValidateNested()
  @Type(() => AddressDto)
  address?: AddressDto;
}`,
      `// Nested DTO
export class AddressDto {
  @IsString()
  street: string;

  @IsString()
  city: string;

  @IsString()
  @Length(5, 10)
  zipCode: string;
}`,
      `// Global validation pipe
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,          // Strip non-decorated properties
  forbidNonWhitelisted: true, // Throw on extra properties
  transform: true,          // Auto-transform to DTO types
  transformOptions: {
    enableImplicitConversion: true
  }
}));`
    ],
    relatedTopics: ["pipes", "dto", "class-validator"]
  },

  configuration: {
    title: "Configuration",
    description: "Manage application configuration with @nestjs/config",
    content: `@nestjs/config provides configuration management based on dotenv.

Features:
- Environment variable loading
- Configuration validation with Joi
- Namespaced configuration
- Custom configuration files
- Type-safe configuration access

Setup:
1. Install: @nestjs/config
2. Import ConfigModule.forRoot() in AppModule
3. Inject ConfigService where needed`,
    examples: [
      `// Basic setup
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'production', 'test')
          .default('development'),
        PORT: Joi.number().default(3000),
        DATABASE_URL: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}`,
      `// Namespaced configuration
// config/database.config.ts
export default registerAs('database', () => ({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  name: process.env.DB_NAME,
}));

// Usage
@Injectable()
export class DatabaseService {
  constructor(
    @Inject(databaseConfig.KEY)
    private dbConfig: ConfigType<typeof databaseConfig>
  ) {
    console.log(this.dbConfig.host);
  }
}`,
      `// Type-safe configuration
interface EnvironmentVariables {
  PORT: number;
  DATABASE_URL: string;
  JWT_SECRET: string;
}

@Injectable()
export class AppConfigService {
  constructor(private configService: ConfigService<EnvironmentVariables>) {}

  get port(): number {
    return this.configService.get('PORT', { infer: true });
  }

  get databaseUrl(): string {
    return this.configService.get('DATABASE_URL', { infer: true });
  }
}`
    ],
    relatedTopics: ["environment", "dotenv", "validation"]
  },

  caching: {
    title: "Caching",
    description: "Implement caching with cache-manager",
    content: `NestJS provides caching via @nestjs/cache-manager.

Features:
- In-memory caching (default)
- Redis, Memcached support
- Automatic cache interceptor
- TTL (time-to-live) configuration
- Custom cache keys

Setup:
1. Install: @nestjs/cache-manager cache-manager
2. Import CacheModule
3. Inject CACHE_MANAGER or use CacheInterceptor`,
    examples: [
      `// Cache module setup
@Module({
  imports: [
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        store: redisStore,
        host: configService.get('REDIS_HOST'),
        port: configService.get('REDIS_PORT'),
        ttl: 60 * 60, // 1 hour
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}`,
      `// Manual caching
@Injectable()
export class UserService {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  async getUser(id: number): Promise<User> {
    const cacheKey = \`user:\${id}\`;

    // Try cache first
    const cached = await this.cacheManager.get<User>(cacheKey);
    if (cached) return cached;

    // Fetch from database
    const user = await this.userRepository.findOne(id);

    // Store in cache
    await this.cacheManager.set(cacheKey, user, 3600);

    return user;
  }
}`,
      `// Auto-caching with interceptor
@Controller('users')
@UseInterceptors(CacheInterceptor)
export class UserController {
  @Get()
  @CacheTTL(30)
  @CacheKey('all-users')
  findAll() {
    return this.userService.findAll();
  }
}`
    ],
    relatedTopics: ["redis", "performance", "interceptors"]
  },

  testing: {
    title: "Testing",
    description: "Unit and e2e testing with Jest",
    content: `NestJS uses Jest for testing and provides testing utilities.

Test types:
- Unit tests: Test individual components in isolation
- Integration tests: Test component interactions
- E2E tests: Test complete request/response cycle

Key utilities:
- Test.createTestingModule(): Create testing module
- module.compile(): Compile the module
- module.get(): Get provider instance
- overrideProvider(): Mock providers

Best practices:
- Mock external dependencies
- Use beforeEach for fresh instances
- Test happy path and edge cases`,
    examples: [
      `// Unit test for service
describe('UserService', () => {
  let service: UserService;
  let repository: MockType<Repository<User>>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getRepositoryToken(User),
          useFactory: repositoryMockFactory,
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    repository = module.get(getRepositoryToken(User));
  });

  it('should find a user by id', async () => {
    const user = { id: 1, name: 'Test User' };
    repository.findOne.mockResolvedValue(user);

    expect(await service.findOne(1)).toEqual(user);
    expect(repository.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
  });
});`,
      `// E2E test
describe('UserController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('/users (GET)', () => {
    return request(app.getHttpServer())
      .get('/users')
      .expect(200)
      .expect((res) => {
        expect(Array.isArray(res.body)).toBe(true);
      });
  });

  it('/users (POST)', () => {
    return request(app.getHttpServer())
      .post('/users')
      .send({ name: 'Test', email: 'test@test.com' })
      .expect(201);
  });
});`
    ],
    relatedTopics: ["jest", "mocking", "e2e"]
  },

  swagger: {
    title: "OpenAPI (Swagger)",
    description: "Generate API documentation with Swagger",
    content: `@nestjs/swagger generates OpenAPI documentation automatically.

Setup:
1. Install: @nestjs/swagger
2. Configure SwaggerModule in main.ts
3. Use decorators to enhance documentation

Key decorators:
- @ApiTags(): Group endpoints
- @ApiOperation(): Describe operation
- @ApiResponse(): Document responses
- @ApiProperty(): Document DTO properties
- @ApiBearerAuth(): Document auth
- @ApiQuery(), @ApiParam(), @ApiBody()`,
    examples: [
      `// Swagger setup
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('API Documentation')
    .setDescription('The API description')
    .setVersion('1.0')
    .addBearerAuth()
    .addTag('users')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(3000);
}`,
      `// DTO with Swagger decorators
export class CreateUserDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com'
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password',
    minLength: 8,
    example: 'StrongP@ss1'
  })
  @IsString()
  @MinLength(8)
  password: string;

  @ApiPropertyOptional({
    description: 'User age',
    minimum: 0,
    maximum: 150
  })
  @IsOptional()
  @IsInt()
  age?: number;
}`,
      `// Controller with Swagger
@ApiTags('users')
@Controller('users')
export class UserController {
  @Post()
  @ApiOperation({ summary: 'Create a new user' })
  @ApiResponse({ status: 201, description: 'User created successfully' })
  @ApiResponse({ status: 400, description: 'Invalid input' })
  @ApiBody({ type: CreateUserDto })
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }
}`
    ],
    relatedTopics: ["documentation", "api", "openapi"]
  },

  websockets: {
    title: "WebSockets",
    description: "Real-time communication with WebSockets and Socket.IO",
    content: `NestJS supports WebSockets via @nestjs/websockets and @nestjs/platform-socket.io.

Key concepts:
- Gateway: WebSocket endpoint handler (like Controller)
- @WebSocketGateway(): Decorator for gateway class
- @SubscribeMessage(): Handle specific message events
- @WebSocketServer(): Access server instance
- @ConnectedSocket(): Access client socket

Features:
- Namespace support
- Room management
- Broadcasting
- Guards and interceptors support`,
    examples: [
      `// WebSocket gateway
@WebSocketGateway({
  cors: { origin: '*' },
  namespace: 'chat'
})
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  handleConnection(client: Socket) {
    console.log(\`Client connected: \${client.id}\`);
  }

  handleDisconnect(client: Socket) {
    console.log(\`Client disconnected: \${client.id}\`);
  }

  @SubscribeMessage('message')
  handleMessage(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { room: string; message: string }
  ) {
    this.server.to(data.room).emit('message', {
      sender: client.id,
      message: data.message,
      timestamp: new Date()
    });
  }

  @SubscribeMessage('join')
  handleJoin(
    @ConnectedSocket() client: Socket,
    @MessageBody() room: string
  ) {
    client.join(room);
    this.server.to(room).emit('userJoined', { id: client.id });
  }
}`,
      `// Module configuration
@Module({
  providers: [ChatGateway, ChatService],
})
export class ChatModule {}`
    ],
    relatedTopics: ["real-time", "socket-io", "events"]
  },

  microservices: {
    title: "Microservices",
    description: "Build microservices with various transport layers",
    content: `NestJS provides first-class support for microservices architecture.

Transport layers:
- TCP (default)
- Redis
- MQTT
- NATS
- RabbitMQ
- Kafka
- gRPC

Patterns:
- Request-response: @MessagePattern()
- Event-based: @EventPattern()

Features:
- Hybrid applications (HTTP + microservice)
- Exception filters for microservices
- Interceptors and guards support`,
    examples: [
      `// Microservice setup
async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AppModule,
    {
      transport: Transport.TCP,
      options: {
        host: 'localhost',
        port: 3001,
      },
    },
  );
  await app.listen();
}`,
      `// Message patterns
@Controller()
export class MathController {
  @MessagePattern({ cmd: 'sum' })
  sum(data: number[]): number {
    return data.reduce((a, b) => a + b, 0);
  }

  @EventPattern('user_created')
  async handleUserCreated(data: Record<string, unknown>) {
    console.log('User created:', data);
    // Handle event
  }
}`,
      `// Client usage
@Injectable()
export class MathService {
  constructor(@Inject('MATH_SERVICE') private client: ClientProxy) {}

  async sum(numbers: number[]): Promise<number> {
    return this.client.send<number>({ cmd: 'sum' }, numbers).toPromise();
  }

  emitUserCreated(user: User) {
    this.client.emit('user_created', user);
  }
}`
    ],
    relatedTopics: ["tcp", "redis", "rabbitmq", "kafka"]
  },

  graphql: {
    title: "GraphQL",
    description: "Build GraphQL APIs with code-first or schema-first approach",
    content: `NestJS supports GraphQL via @nestjs/graphql with Apollo or Mercurius.

Approaches:
- Code-first: Generate schema from TypeScript decorators
- Schema-first: Write SDL, generate TypeScript types

Key decorators (code-first):
- @ObjectType(): Define output type
- @InputType(): Define input type
- @Field(): Define field
- @Query(): Define query resolver
- @Mutation(): Define mutation resolver
- @Resolver(): Define resolver class
- @Args(): Extract arguments`,
    examples: [
      `// GraphQL module setup
@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
      sortSchema: true,
      playground: true,
    }),
  ],
})
export class AppModule {}`,
      `// Object type
@ObjectType()
export class User {
  @Field(() => ID)
  id: string;

  @Field()
  email: string;

  @Field({ nullable: true })
  name?: string;

  @Field(() => [Post])
  posts: Post[];
}`,
      `// Resolver
@Resolver(() => User)
export class UserResolver {
  constructor(private userService: UserService) {}

  @Query(() => [User])
  users(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Query(() => User, { nullable: true })
  user(@Args('id', { type: () => ID }) id: string): Promise<User> {
    return this.userService.findOne(id);
  }

  @Mutation(() => User)
  createUser(@Args('input') input: CreateUserInput): Promise<User> {
    return this.userService.create(input);
  }

  @ResolveField(() => [Post])
  posts(@Parent() user: User): Promise<Post[]> {
    return this.postService.findByAuthor(user.id);
  }
}`
    ],
    relatedTopics: ["apollo", "resolvers", "schema"]
  },

  queues: {
    title: "Queues",
    description: "Background job processing with Bull",
    content: `@nestjs/bull provides queue management using Bull (Redis-based).

Features:
- Background job processing
- Delayed jobs
- Job prioritization
- Rate limiting
- Job events and lifecycle hooks
- Separate processes for workers

Key concepts:
- Queue: Job container
- Producer: Adds jobs to queue
- Consumer: Processes jobs
- Processor: Decorated class that handles jobs`,
    examples: [
      `// Bull module setup
@Module({
  imports: [
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        redis: {
          host: configService.get('REDIS_HOST'),
          port: configService.get('REDIS_PORT'),
        },
      }),
      inject: [ConfigService],
    }),
    BullModule.registerQueue({
      name: 'email',
    }),
  ],
})
export class AppModule {}`,
      `// Producer service
@Injectable()
export class EmailService {
  constructor(@InjectQueue('email') private emailQueue: Queue) {}

  async sendWelcomeEmail(user: User) {
    await this.emailQueue.add('welcome', {
      to: user.email,
      name: user.name,
    }, {
      delay: 5000, // 5 second delay
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 1000,
      },
    });
  }
}`,
      `// Consumer processor
@Processor('email')
export class EmailProcessor {
  constructor(private mailerService: MailerService) {}

  @Process('welcome')
  async handleWelcome(job: Job<{ to: string; name: string }>) {
    await this.mailerService.sendMail({
      to: job.data.to,
      subject: 'Welcome!',
      template: 'welcome',
      context: { name: job.data.name },
    });
  }

  @OnQueueCompleted()
  onCompleted(job: Job) {
    console.log(\`Job \${job.id} completed\`);
  }

  @OnQueueFailed()
  onFailed(job: Job, error: Error) {
    console.error(\`Job \${job.id} failed: \${error.message}\`);
  }
}`
    ],
    relatedTopics: ["redis", "background-jobs", "bull"]
  }
};

// ============================================
// CLI COMMANDS
// ============================================

export const cliCommands: CLICommand[] = [
  {
    command: "nest new <project-name>",
    description: "Create a new NestJS project",
    options: [
      { flag: "--directory", description: "Specify destination directory" },
      { flag: "--skip-git", description: "Skip git initialization" },
      { flag: "--skip-install", description: "Skip package installation" },
      { flag: "--package-manager [pm]", description: "Specify package manager (npm, yarn, pnpm)" },
      { flag: "--strict", description: "Enable TypeScript strict mode" }
    ],
    examples: [
      "nest new my-app",
      "nest new my-app --package-manager pnpm",
      "nest new my-app --strict"
    ]
  },
  {
    command: "nest generate <schematic> <name>",
    alias: "nest g",
    description: "Generate NestJS elements from schematics",
    options: [
      { flag: "--dry-run", description: "Report changes without writing" },
      { flag: "--flat", description: "Generate without creating directory" },
      { flag: "--no-spec", description: "Skip test file generation" },
      { flag: "--skip-import", description: "Skip module import" }
    ],
    examples: [
      "nest g module users",
      "nest g controller users",
      "nest g service users",
      "nest g resource products",
      "nest g guard auth --no-spec",
      "nest g interceptor logging",
      "nest g pipe validation",
      "nest g filter http-exception"
    ]
  },
  {
    command: "nest build",
    description: "Compile the application",
    options: [
      { flag: "--webpack", description: "Use webpack for compilation" },
      { flag: "--tsc", description: "Use tsc for compilation" },
      { flag: "--watch", description: "Watch mode" },
      { flag: "--path [path]", description: "Path to tsconfig file" }
    ],
    examples: [
      "nest build",
      "nest build --webpack",
      "nest build --watch"
    ]
  },
  {
    command: "nest start",
    description: "Start the application",
    options: [
      { flag: "--watch", description: "Watch mode" },
      { flag: "--debug [port]", description: "Debug mode with optional port" },
      { flag: "--webpack", description: "Use webpack" },
      { flag: "--exec [binary]", description: "Binary to run (default: node)" }
    ],
    examples: [
      "nest start",
      "nest start --watch",
      "nest start --debug 9229"
    ]
  },
  {
    command: "nest info",
    description: "Display NestJS project details",
    examples: ["nest info"]
  },
  {
    command: "nest add <library>",
    description: "Add a library to the project",
    examples: [
      "nest add @nestjs/config",
      "nest add @nestjs/swagger"
    ]
  }
];

// ============================================
// SCHEMATICS
// ============================================

export const schematics = [
  { name: "application", alias: "app", description: "Generate a new application workspace" },
  { name: "class", alias: "cl", description: "Generate a new class" },
  { name: "controller", alias: "co", description: "Generate a controller" },
  { name: "decorator", alias: "d", description: "Generate a custom decorator" },
  { name: "filter", alias: "f", description: "Generate a filter" },
  { name: "gateway", alias: "ga", description: "Generate a gateway" },
  { name: "guard", alias: "gu", description: "Generate a guard" },
  { name: "interceptor", alias: "itc", description: "Generate an interceptor" },
  { name: "interface", alias: "itf", description: "Generate an interface" },
  { name: "middleware", alias: "mi", description: "Generate a middleware" },
  { name: "module", alias: "mo", description: "Generate a module" },
  { name: "pipe", alias: "pi", description: "Generate a pipe" },
  { name: "provider", alias: "pr", description: "Generate a provider" },
  { name: "resolver", alias: "r", description: "Generate a GraphQL resolver" },
  { name: "resource", alias: "res", description: "Generate a CRUD resource" },
  { name: "service", alias: "s", description: "Generate a service" },
  { name: "library", alias: "lib", description: "Generate a library" },
  { name: "sub-app", alias: "app", description: "Generate a sub-application" }
];

// ============================================
// COMMON DECORATORS
// ============================================

export const decorators: Decorator[] = [
  // Module decorators
  { name: "@Module()", type: "class", description: "Define a module", usage: "@Module({ imports: [], controllers: [], providers: [], exports: [] })" },
  { name: "@Global()", type: "class", description: "Make module global", usage: "@Global()" },

  // Controller decorators
  { name: "@Controller()", type: "class", description: "Define a controller", usage: "@Controller('prefix')" },

  // HTTP method decorators
  { name: "@Get()", type: "method", description: "Handle GET request", usage: "@Get('path')" },
  { name: "@Post()", type: "method", description: "Handle POST request", usage: "@Post('path')" },
  { name: "@Put()", type: "method", description: "Handle PUT request", usage: "@Put('path')" },
  { name: "@Delete()", type: "method", description: "Handle DELETE request", usage: "@Delete('path')" },
  { name: "@Patch()", type: "method", description: "Handle PATCH request", usage: "@Patch('path')" },
  { name: "@Options()", type: "method", description: "Handle OPTIONS request", usage: "@Options('path')" },
  { name: "@Head()", type: "method", description: "Handle HEAD request", usage: "@Head('path')" },
  { name: "@All()", type: "method", description: "Handle all HTTP methods", usage: "@All('path')" },

  // Parameter decorators
  { name: "@Param()", type: "parameter", description: "Extract route parameter", usage: "@Param('id') id: string" },
  { name: "@Query()", type: "parameter", description: "Extract query parameter", usage: "@Query('page') page: string" },
  { name: "@Body()", type: "parameter", description: "Extract request body", usage: "@Body() dto: CreateDto" },
  { name: "@Headers()", type: "parameter", description: "Extract headers", usage: "@Headers('authorization') auth: string" },
  { name: "@Req()", type: "parameter", description: "Access request object", usage: "@Req() req: Request" },
  { name: "@Res()", type: "parameter", description: "Access response object", usage: "@Res() res: Response" },
  { name: "@Session()", type: "parameter", description: "Access session", usage: "@Session() session" },
  { name: "@Ip()", type: "parameter", description: "Access client IP", usage: "@Ip() ip: string" },

  // Provider decorators
  { name: "@Injectable()", type: "class", description: "Mark class as injectable", usage: "@Injectable()" },
  { name: "@Inject()", type: "parameter", description: "Inject by token", usage: "@Inject('TOKEN') value" },
  { name: "@Optional()", type: "parameter", description: "Mark dependency optional", usage: "@Optional()" },

  // Guard/Pipe/Interceptor decorators
  { name: "@UseGuards()", type: "method", description: "Apply guards", usage: "@UseGuards(AuthGuard)" },
  { name: "@UsePipes()", type: "method", description: "Apply pipes", usage: "@UsePipes(ValidationPipe)" },
  { name: "@UseInterceptors()", type: "method", description: "Apply interceptors", usage: "@UseInterceptors(LoggingInterceptor)" },
  { name: "@UseFilters()", type: "method", description: "Apply exception filters", usage: "@UseFilters(HttpExceptionFilter)" },

  // Response decorators
  { name: "@HttpCode()", type: "method", description: "Set HTTP status code", usage: "@HttpCode(204)" },
  { name: "@Header()", type: "method", description: "Set response header", usage: "@Header('Cache-Control', 'none')" },
  { name: "@Redirect()", type: "method", description: "Redirect response", usage: "@Redirect('https://example.com', 301)" },
  { name: "@Render()", type: "method", description: "Render template", usage: "@Render('index')" },

  // Metadata decorators
  { name: "@SetMetadata()", type: "method", description: "Set custom metadata", usage: "@SetMetadata('roles', ['admin'])" }
];

// ============================================
// BEST PRACTICES
// ============================================

export const bestPractices = {
  projectStructure: `
Recommended NestJS Project Structure:

src/
├── common/                  # Shared code
│   ├── decorators/         # Custom decorators
│   ├── filters/            # Exception filters
│   ├── guards/             # Guards
│   ├── interceptors/       # Interceptors
│   ├── pipes/              # Pipes
│   └── middleware/         # Middleware
├── config/                  # Configuration
│   ├── app.config.ts
│   ├── database.config.ts
│   └── config.module.ts
├── modules/                 # Feature modules
│   ├── users/
│   │   ├── dto/
│   │   ├── entities/
│   │   ├── users.controller.ts
│   │   ├── users.service.ts
│   │   ├── users.module.ts
│   │   └── users.controller.spec.ts
│   └── auth/
├── database/               # Database related
│   ├── migrations/
│   └── seeds/
├── app.module.ts           # Root module
└── main.ts                 # Entry point
`,

  codeGuidelines: [
    "Use DTOs for all input validation",
    "Keep controllers thin - move logic to services",
    "Use dependency injection consistently",
    "Implement proper error handling with filters",
    "Use guards for authentication/authorization",
    "Use interceptors for cross-cutting concerns",
    "Write unit tests for services, e2e tests for controllers",
    "Use environment configuration with validation",
    "Document APIs with Swagger decorators",
    "Follow single responsibility principle for modules"
  ],

  securityPractices: [
    "Enable CORS appropriately",
    "Use helmet for security headers",
    "Implement rate limiting",
    "Validate and sanitize all inputs",
    "Use parameterized queries (TypeORM handles this)",
    "Hash passwords with bcrypt",
    "Use HTTPS in production",
    "Implement proper JWT token management",
    "Use environment variables for secrets",
    "Enable CSRF protection for forms"
  ]
};

// ============================================
// COMMON PACKAGES
// ============================================

export const commonPackages = [
  { name: "@nestjs/config", description: "Configuration module" },
  { name: "@nestjs/typeorm", description: "TypeORM integration" },
  { name: "@nestjs/mongoose", description: "Mongoose integration" },
  { name: "@nestjs/swagger", description: "OpenAPI/Swagger support" },
  { name: "@nestjs/passport", description: "Passport authentication" },
  { name: "@nestjs/jwt", description: "JWT utilities" },
  { name: "@nestjs/cache-manager", description: "Caching support" },
  { name: "@nestjs/bull", description: "Queue management" },
  { name: "@nestjs/schedule", description: "Task scheduling" },
  { name: "@nestjs/throttler", description: "Rate limiting" },
  { name: "@nestjs/websockets", description: "WebSocket support" },
  { name: "@nestjs/platform-socket.io", description: "Socket.IO platform" },
  { name: "@nestjs/graphql", description: "GraphQL support" },
  { name: "@nestjs/apollo", description: "Apollo GraphQL driver" },
  { name: "@nestjs/microservices", description: "Microservices support" },
  { name: "class-validator", description: "Validation decorators" },
  { name: "class-transformer", description: "Object transformation" },
  { name: "helmet", description: "Security headers" },
  { name: "compression", description: "Response compression" }
];
