// Advanced NestJS Techniques Documentation
import { DocSection } from './nestjs-docs.js';

export const advancedTechniques: Record<string, DocSection> = {
  cqrs: {
    title: "CQRS (Command Query Responsibility Segregation)",
    description: "Separate read and write operations for complex domains",
    content: `CQRS pattern separates read (Query) and write (Command) operations into different models.

NestJS CQRS module (@nestjs/cqrs) provides:
- Commands: Write operations that change state
- Queries: Read operations that return data
- Events: Notifications about state changes
- Sagas: Long-running business processes

Key components:
- CommandBus: Dispatches commands to handlers
- QueryBus: Dispatches queries to handlers
- EventBus: Publishes and subscribes to events
- @CommandHandler(), @QueryHandler(), @EventsHandler() decorators

When to use CQRS:
- Complex domain logic
- Different read/write scaling needs
- Event sourcing requirements
- Audit trail needs`,
    examples: [
      `// Command
export class CreateUserCommand {
  constructor(
    public readonly email: string,
    public readonly name: string,
  ) {}
}

// Command Handler
@CommandHandler(CreateUserCommand)
export class CreateUserHandler implements ICommandHandler<CreateUserCommand> {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(command: CreateUserCommand): Promise<User> {
    const user = await this.userRepository.create({
      email: command.email,
      name: command.name,
    });

    this.eventBus.publish(new UserCreatedEvent(user.id, user.email));
    return user;
  }
}`,
      `// Query
export class GetUserQuery {
  constructor(public readonly userId: string) {}
}

// Query Handler
@QueryHandler(GetUserQuery)
export class GetUserHandler implements IQueryHandler<GetUserQuery> {
  constructor(private readonly userRepository: UserRepository) {}

  async execute(query: GetUserQuery): Promise<User> {
    return this.userRepository.findById(query.userId);
  }
}`,
      `// Event
export class UserCreatedEvent {
  constructor(
    public readonly userId: string,
    public readonly email: string,
  ) {}
}

// Event Handler
@EventsHandler(UserCreatedEvent)
export class UserCreatedHandler implements IEventHandler<UserCreatedEvent> {
  constructor(private readonly emailService: EmailService) {}

  handle(event: UserCreatedEvent) {
    this.emailService.sendWelcome(event.email);
  }
}`,
      `// Saga
@Injectable()
export class UserSaga {
  @Saga()
  userCreated = (events$: Observable<any>): Observable<ICommand> => {
    return events$.pipe(
      ofType(UserCreatedEvent),
      delay(1000),
      map(event => new SendWelcomeEmailCommand(event.email)),
    );
  };
}`,
      `// Module setup
@Module({
  imports: [CqrsModule],
  providers: [
    CreateUserHandler,
    GetUserHandler,
    UserCreatedHandler,
    UserSaga,
  ],
})
export class UserModule {}`
    ],
    relatedTopics: ["events", "sagas", "domain-driven-design"]
  },

  events: {
    title: "Event Emitter",
    description: "Publish and subscribe to application events",
    content: `NestJS Event Emitter (@nestjs/event-emitter) provides event-driven architecture support.

Features:
- Async event handling
- Multiple listeners per event
- Wildcard listeners
- Typed events
- Request-scoped listeners

Use cases:
- Decoupled module communication
- Audit logging
- Notifications
- Cache invalidation
- Analytics tracking`,
    examples: [
      `// Setup
@Module({
  imports: [
    EventEmitterModule.forRoot({
      wildcard: true,
      delimiter: '.',
      maxListeners: 10,
      verboseMemoryLeak: true,
    }),
  ],
})
export class AppModule {}`,
      `// Event class
export class OrderCreatedEvent {
  constructor(
    public readonly orderId: string,
    public readonly userId: string,
    public readonly items: OrderItem[],
    public readonly total: number,
  ) {}
}`,
      `// Emit event
@Injectable()
export class OrderService {
  constructor(private eventEmitter: EventEmitter2) {}

  async createOrder(dto: CreateOrderDto): Promise<Order> {
    const order = await this.orderRepository.create(dto);

    this.eventEmitter.emit(
      'order.created',
      new OrderCreatedEvent(order.id, dto.userId, dto.items, order.total),
    );

    return order;
  }
}`,
      `// Listen to events
@Injectable()
export class NotificationListener {
  @OnEvent('order.created')
  handleOrderCreated(event: OrderCreatedEvent) {
    console.log(\`Order \${event.orderId} created for user \${event.userId}\`);
    // Send notification
  }

  @OnEvent('order.*')
  handleAllOrderEvents(event: any) {
    // Handle all order events
  }

  @OnEvent('**')
  handleAllEvents(event: any) {
    // Handle all events (audit log)
  }
}`,
      `// Async event handling
@OnEvent('order.created', { async: true })
async handleOrderCreatedAsync(event: OrderCreatedEvent) {
  await this.emailService.sendOrderConfirmation(event);
}`
    ],
    relatedTopics: ["cqrs", "microservices", "queues"]
  },

  fileUpload: {
    title: "File Upload",
    description: "Handle file uploads with Multer integration",
    content: `NestJS uses Multer for handling multipart/form-data file uploads.

Features:
- Single and multiple file uploads
- File validation (size, type)
- Custom storage engines
- Memory and disk storage
- Streaming support

Key decorators:
- @UseInterceptors(FileInterceptor): Single file
- @UseInterceptors(FilesInterceptor): Multiple files, same field
- @UseInterceptors(FileFieldsInterceptor): Multiple fields
- @UploadedFile(), @UploadedFiles(): Extract files`,
    examples: [
      `// Single file upload
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
uploadFile(@UploadedFile() file: Express.Multer.File) {
  console.log(file);
  return {
    filename: file.originalname,
    size: file.size,
    mimetype: file.mimetype,
  };
}`,
      `// Multiple files upload
@Post('uploads')
@UseInterceptors(FilesInterceptor('files', 10))
uploadFiles(@UploadedFiles() files: Express.Multer.File[]) {
  return files.map(file => ({
    filename: file.originalname,
    size: file.size,
  }));
}`,
      `// Multiple fields
@Post('profile')
@UseInterceptors(FileFieldsInterceptor([
  { name: 'avatar', maxCount: 1 },
  { name: 'documents', maxCount: 5 },
]))
uploadProfileFiles(
  @UploadedFiles() files: {
    avatar?: Express.Multer.File[],
    documents?: Express.Multer.File[]
  },
) {
  return {
    avatar: files.avatar?.[0]?.filename,
    documents: files.documents?.map(f => f.filename),
  };
}`,
      `// File validation pipe
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
uploadFile(
  @UploadedFile(
    new ParseFilePipe({
      validators: [
        new MaxFileSizeValidator({ maxSize: 1024 * 1024 * 5 }), // 5MB
        new FileTypeValidator({ fileType: /(jpg|jpeg|png|gif)$/ }),
      ],
    }),
  )
  file: Express.Multer.File,
) {
  return { filename: file.originalname };
}`,
      `// Custom storage
import { diskStorage } from 'multer';
import { extname } from 'path';

@Post('upload')
@UseInterceptors(
  FileInterceptor('file', {
    storage: diskStorage({
      destination: './uploads',
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, \`\${uniqueSuffix}\${extname(file.originalname)}\`);
      },
    }),
    limits: { fileSize: 1024 * 1024 * 10 }, // 10MB
    fileFilter: (req, file, cb) => {
      if (!file.mimetype.match(/\\/(jpg|jpeg|png|gif)$/)) {
        cb(new BadRequestException('Only image files allowed'), false);
      }
      cb(null, true);
    },
  }),
)
uploadFile(@UploadedFile() file: Express.Multer.File) {
  return { path: file.path };
}`,
      `// Stream to S3
@Post('upload-s3')
@UseInterceptors(FileInterceptor('file'))
async uploadToS3(@UploadedFile() file: Express.Multer.File) {
  const result = await this.s3Service.upload({
    Bucket: 'my-bucket',
    Key: \`uploads/\${Date.now()}-\${file.originalname}\`,
    Body: file.buffer,
    ContentType: file.mimetype,
  });
  return { url: result.Location };
}`
    ],
    relatedTopics: ["streaming", "validation", "s3"]
  },

  streaming: {
    title: "Streaming Responses",
    description: "Stream large data responses efficiently",
    content: `NestJS supports streaming responses for large files and real-time data.

Types of streaming:
- File streaming: Send files without loading into memory
- SSE (Server-Sent Events): Real-time server-to-client updates
- Chunked responses: Large data in chunks

Benefits:
- Lower memory usage
- Faster time-to-first-byte
- Better handling of large files
- Real-time updates`,
    examples: [
      `// Stream file response
@Get('download/:filename')
async downloadFile(
  @Param('filename') filename: string,
  @Res() res: Response,
) {
  const file = createReadStream(join(process.cwd(), 'uploads', filename));

  res.set({
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': \`attachment; filename="\${filename}"\`,
  });

  file.pipe(res);
}`,
      `// Using StreamableFile
@Get('file/:id')
getFile(@Param('id') id: string): StreamableFile {
  const file = createReadStream(join(process.cwd(), 'files', id));
  return new StreamableFile(file, {
    type: 'application/pdf',
    disposition: 'attachment; filename="document.pdf"',
  });
}`,
      `// Server-Sent Events (SSE)
@Sse('events')
sendEvents(): Observable<MessageEvent> {
  return interval(1000).pipe(
    map((num) => ({
      data: { timestamp: new Date().toISOString(), count: num },
    } as MessageEvent)),
  );
}

// Client side
const eventSource = new EventSource('/events');
eventSource.onmessage = (event) => {
  console.log(JSON.parse(event.data));
};`,
      `// SSE with real data
@Sse('notifications')
notifications(@Req() req: Request): Observable<MessageEvent> {
  const userId = req.user.id;

  return this.notificationService.getNotificationStream(userId).pipe(
    map((notification) => ({
      data: notification,
      type: 'notification',
    } as MessageEvent)),
  );
}`,
      `// Chunked JSON response
@Get('large-data')
async getLargeData(@Res() res: Response) {
  res.setHeader('Content-Type', 'application/json');
  res.write('[');

  let first = true;
  for await (const item of this.dataService.streamItems()) {
    if (!first) res.write(',');
    first = false;
    res.write(JSON.stringify(item));
  }

  res.write(']');
  res.end();
}`
    ],
    relatedTopics: ["websockets", "performance", "file-upload"]
  },

  healthChecks: {
    title: "Health Checks",
    description: "Monitor application health with Terminus",
    content: `@nestjs/terminus provides health check endpoints for monitoring.

Built-in health indicators:
- HttpHealthIndicator: Check HTTP endpoints
- TypeOrmHealthIndicator: Database connectivity
- MongooseHealthIndicator: MongoDB connectivity
- MicroserviceHealthIndicator: Microservice health
- MemoryHealthIndicator: Memory usage
- DiskHealthIndicator: Disk space

Use cases:
- Kubernetes liveness/readiness probes
- Load balancer health checks
- Monitoring dashboards
- Auto-scaling triggers`,
    examples: [
      `// Health module setup
@Module({
  imports: [TerminusModule],
  controllers: [HealthController],
})
export class HealthModule {}`,
      `// Health controller
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private http: HttpHealthIndicator,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
    private disk: DiskHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      () => this.http.pingCheck('api', 'https://api.example.com'),
      () => this.db.pingCheck('database'),
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),
      () => this.disk.checkStorage('storage', {
        path: '/',
        thresholdPercent: 0.9,
      }),
    ]);
  }

  @Get('liveness')
  @HealthCheck()
  liveness() {
    return this.health.check([]);
  }

  @Get('readiness')
  @HealthCheck()
  readiness() {
    return this.health.check([
      () => this.db.pingCheck('database'),
    ]);
  }
}`,
      `// Custom health indicator
@Injectable()
export class RedisHealthIndicator extends HealthIndicator {
  constructor(private readonly redis: Redis) {
    super();
  }

  async isHealthy(key: string): Promise<HealthIndicatorResult> {
    try {
      await this.redis.ping();
      return this.getStatus(key, true);
    } catch (error) {
      return this.getStatus(key, false, { message: error.message });
    }
  }
}

// Usage
@Get()
@HealthCheck()
check() {
  return this.health.check([
    () => this.redisHealth.isHealthy('redis'),
  ]);
}`,
      `// Graceful shutdown
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableShutdownHooks();

  await app.listen(3000);
}

// In service
@Injectable()
export class AppService implements OnModuleDestroy {
  async onModuleDestroy() {
    // Cleanup connections
    await this.database.disconnect();
    await this.cache.quit();
  }
}`
    ],
    relatedTopics: ["monitoring", "kubernetes", "graceful-shutdown"]
  },

  taskScheduling: {
    title: "Task Scheduling",
    description: "Run scheduled tasks with cron expressions",
    content: `@nestjs/schedule provides task scheduling using cron expressions.

Features:
- Cron-based scheduling
- Interval-based scheduling
- Timeout-based scheduling
- Dynamic task management
- Cluster-safe execution

Cron expression format:
* * * * * *
│ │ │ │ │ │
│ │ │ │ │ └── Day of week (0-7, SUN-SAT)
│ │ │ │ └──── Month (1-12, JAN-DEC)
│ │ │ └────── Day of month (1-31)
│ │ └──────── Hour (0-23)
│ └────────── Minute (0-59)
└──────────── Second (0-59, optional)`,
    examples: [
      `// Module setup
@Module({
  imports: [ScheduleModule.forRoot()],
  providers: [TasksService],
})
export class AppModule {}`,
      `// Scheduled tasks
@Injectable()
export class TasksService {
  private readonly logger = new Logger(TasksService.name);

  // Every 30 seconds
  @Cron('*/30 * * * * *')
  handleCron() {
    this.logger.debug('Called every 30 seconds');
  }

  // Every day at midnight
  @Cron('0 0 0 * * *')
  handleDailyTask() {
    this.logger.debug('Called at midnight');
  }

  // Every Monday at 9:00 AM
  @Cron('0 0 9 * * 1')
  handleWeeklyTask() {
    this.logger.debug('Called every Monday at 9 AM');
  }

  // Using predefined expressions
  @Cron(CronExpression.EVERY_HOUR)
  handleHourlyTask() {
    this.logger.debug('Called every hour');
  }
}`,
      `// Interval and timeout
@Injectable()
export class TasksService {
  // Every 10 seconds
  @Interval(10000)
  handleInterval() {
    console.log('Called every 10 seconds');
  }

  // Once after 5 seconds
  @Timeout(5000)
  handleTimeout() {
    console.log('Called once after 5 seconds');
  }
}`,
      `// Dynamic scheduling
@Injectable()
export class DynamicTaskService {
  constructor(private schedulerRegistry: SchedulerRegistry) {}

  addCronJob(name: string, cronExpression: string) {
    const job = new CronJob(cronExpression, () => {
      console.log(\`Job \${name} running!\`);
    });

    this.schedulerRegistry.addCronJob(name, job);
    job.start();
  }

  deleteCronJob(name: string) {
    this.schedulerRegistry.deleteCronJob(name);
  }

  getCronJobs() {
    const jobs = this.schedulerRegistry.getCronJobs();
    jobs.forEach((value, key) => {
      console.log(\`Job: \${key}, Next: \${value.nextDate()}\`);
    });
  }

  addInterval(name: string, ms: number) {
    const callback = () => console.log(\`Interval \${name} executing\`);
    const interval = setInterval(callback, ms);
    this.schedulerRegistry.addInterval(name, interval);
  }

  deleteInterval(name: string) {
    this.schedulerRegistry.deleteInterval(name);
  }
}`
    ],
    relatedTopics: ["queues", "cron", "background-jobs"]
  },

  compression: {
    title: "Compression",
    description: "Compress HTTP responses for better performance",
    content: `Response compression reduces bandwidth and improves load times.

Options:
- Gzip compression (most common)
- Brotli compression (better ratio)
- Deflate compression

Best practices:
- Enable for text-based responses (JSON, HTML, CSS, JS)
- Set minimum size threshold
- Skip already compressed content (images, videos)
- Consider CPU vs bandwidth tradeoff`,
    examples: [
      `// Enable compression globally
import compression from 'compression';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(compression({
    filter: (req, res) => {
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    },
    threshold: 1024, // Only compress if > 1KB
    level: 6, // Compression level (0-9)
  }));

  await app.listen(3000);
}`,
      `// Selective compression with interceptor
@Injectable()
export class CompressionInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    const acceptEncoding = request.headers['accept-encoding'] || '';

    if (acceptEncoding.includes('br')) {
      response.setHeader('Content-Encoding', 'br');
    } else if (acceptEncoding.includes('gzip')) {
      response.setHeader('Content-Encoding', 'gzip');
    }

    return next.handle();
  }
}`,
      `// Fastify compression
import fastifyCompress from '@fastify/compress';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  );

  await app.register(fastifyCompress, {
    encodings: ['gzip', 'deflate', 'br'],
  });

  await app.listen(3000);
}`
    ],
    relatedTopics: ["performance", "caching", "http"]
  },

  rateLimiting: {
    title: "Rate Limiting",
    description: "Protect APIs from abuse with rate limiting",
    content: `@nestjs/throttler provides rate limiting functionality.

Features:
- Request rate limiting
- Multiple rate limit tiers
- Custom storage (Redis for distributed)
- Skip certain routes
- Custom key generation

Use cases:
- API abuse prevention
- DDoS protection
- Fair usage enforcement
- Tiered API access`,
    examples: [
      `// Module setup
@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60000,    // Time window in ms
      limit: 100,    // Max requests per window
    }),
  ],
})
export class AppModule {}`,
      `// Apply globally
@Module({
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}`,
      `// Custom rate limits per route
@Controller('api')
export class ApiController {
  @Get('public')
  @Throttle({ default: { limit: 100, ttl: 60000 } })
  publicEndpoint() {
    return 'Public data';
  }

  @Get('premium')
  @Throttle({ default: { limit: 1000, ttl: 60000 } })
  premiumEndpoint() {
    return 'Premium data';
  }

  @Get('unlimited')
  @SkipThrottle()
  unlimitedEndpoint() {
    return 'No rate limit';
  }
}`,
      `// Multiple throttlers
@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 1000,
        limit: 3,
      },
      {
        name: 'medium',
        ttl: 10000,
        limit: 20,
      },
      {
        name: 'long',
        ttl: 60000,
        limit: 100,
      },
    ]),
  ],
})
export class AppModule {}`,
      `// Redis storage for distributed rate limiting
@Module({
  imports: [
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [{ ttl: 60000, limit: 100 }],
        storage: new ThrottlerStorageRedisService(
          new Redis({
            host: config.get('REDIS_HOST'),
            port: config.get('REDIS_PORT'),
          }),
        ),
      }),
    }),
  ],
})
export class AppModule {}`,
      `// Custom throttler guard
@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
    // Use user ID instead of IP for authenticated users
    return req.user?.id || req.ip;
  }

  protected async shouldSkip(context: ExecutionContext): Promise<boolean> {
    // Skip rate limiting for admin users
    const request = context.switchToHttp().getRequest();
    return request.user?.role === 'admin';
  }

  protected getErrorMessage(): string {
    return 'Rate limit exceeded. Please try again later.';
  }
}`
    ],
    relatedTopics: ["security", "guards", "redis"]
  },

  versioning: {
    title: "API Versioning",
    description: "Version your APIs for backward compatibility",
    content: `NestJS supports multiple versioning strategies:

1. URI Versioning: /v1/users, /v2/users
2. Header Versioning: X-API-Version: 1
3. Media Type Versioning: Accept: application/vnd.api+json;version=1
4. Custom Versioning: Any custom logic

Best practices:
- Plan versioning from the start
- Document version differences
- Deprecate old versions gracefully
- Use semantic versioning`,
    examples: [
      `// Enable versioning
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  await app.listen(3000);
}`,
      `// Version controllers
@Controller({
  path: 'users',
  version: '1',
})
export class UsersV1Controller {
  @Get()
  findAll() {
    return 'V1: All users';
  }
}

@Controller({
  path: 'users',
  version: '2',
})
export class UsersV2Controller {
  @Get()
  findAll() {
    return { version: 2, users: [] };
  }
}`,
      `// Version individual routes
@Controller('users')
export class UsersController {
  @Version('1')
  @Get()
  findAllV1() {
    return 'V1 response';
  }

  @Version('2')
  @Get()
  findAllV2() {
    return { version: 2, data: [] };
  }

  @Version(['1', '2'])
  @Get(':id')
  findOne(@Param('id') id: string) {
    return \`User \${id} - works for v1 and v2\`;
  }

  @Version(VERSION_NEUTRAL)
  @Get('health')
  health() {
    return 'OK - no version required';
  }
}`,
      `// Header versioning
app.enableVersioning({
  type: VersioningType.HEADER,
  header: 'X-API-Version',
});

// Media type versioning
app.enableVersioning({
  type: VersioningType.MEDIA_TYPE,
  key: 'v=',
});
// Accept: application/json;v=1`,
      `// Custom versioning
app.enableVersioning({
  type: VersioningType.CUSTOM,
  extractor: (request: Request) => {
    // Extract version from query param, header, or any custom logic
    return request.query.version as string ||
           request.headers['x-version'] as string ||
           '1';
  },
});`
    ],
    relatedTopics: ["controllers", "routing", "api-design"]
  },

  serialization: {
    title: "Serialization",
    description: "Transform and exclude response data",
    content: `class-transformer integration for response serialization.

Features:
- Exclude sensitive fields (@Exclude)
- Expose specific fields (@Expose)
- Transform values (@Transform)
- Conditional exposure (groups)
- Nested object serialization

Use cases:
- Hide passwords/tokens in responses
- Format dates consistently
- Rename fields for API
- Different views for different clients`,
    examples: [
      `// Entity with serialization
import { Exclude, Expose, Transform } from 'class-transformer';

export class User {
  id: number;

  @Expose()
  email: string;

  @Exclude()
  password: string;

  @Exclude()
  refreshToken: string;

  @Transform(({ value }) => value.toISOString())
  createdAt: Date;

  @Expose({ name: 'fullName' })
  get name(): string {
    return \`\${this.firstName} \${this.lastName}\`;
  }

  @Expose({ groups: ['admin'] })
  internalNotes: string;
}`,
      `// Enable globally with interceptor
@Module({
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: ClassSerializerInterceptor,
    },
  ],
})
export class AppModule {}`,
      `// Use on specific routes
@Controller('users')
@UseInterceptors(ClassSerializerInterceptor)
export class UserController {
  @Get(':id')
  findOne(@Param('id') id: string): User {
    return this.userService.findOne(id);
  }

  @Get(':id/admin')
  @SerializeOptions({ groups: ['admin'] })
  findOneAdmin(@Param('id') id: string): User {
    return this.userService.findOne(id);
  }
}`,
      `// Custom serializer interceptor
@Injectable()
export class TransformInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map(data => ({
        success: true,
        data: instanceToPlain(data, {
          excludeExtraneousValues: true,
        }),
        timestamp: new Date().toISOString(),
      })),
    );
  }
}`,
      `// Response DTO pattern
export class UserResponseDto {
  @Expose()
  id: number;

  @Expose()
  email: string;

  @Expose()
  @Transform(({ obj }) => obj.firstName + ' ' + obj.lastName)
  fullName: string;

  constructor(partial: Partial<UserResponseDto>) {
    Object.assign(this, partial);
  }
}

// In controller
@Get(':id')
async findOne(@Param('id') id: string): Promise<UserResponseDto> {
  const user = await this.userService.findOne(id);
  return plainToInstance(UserResponseDto, user, {
    excludeExtraneousValues: true,
  });
}`
    ],
    relatedTopics: ["dto", "validation", "interceptors"]
  }
};

// Common error solutions
export const commonErrors: Record<string, {
  error: string;
  causes: string[];
  solutions: string[];
  example?: string;
}> = {
  circularDependency: {
    error: "Circular dependency detected",
    causes: [
      "Two or more modules/providers depend on each other",
      "Service A injects Service B, and Service B injects Service A",
      "Module imports create a cycle"
    ],
    solutions: [
      "Use forwardRef() to resolve the circular reference",
      "Refactor to remove the circular dependency",
      "Extract shared code into a separate module",
      "Use events instead of direct dependencies"
    ],
    example: `// Using forwardRef
@Injectable()
export class ServiceA {
  constructor(
    @Inject(forwardRef(() => ServiceB))
    private serviceB: ServiceB,
  ) {}
}

@Injectable()
export class ServiceB {
  constructor(
    @Inject(forwardRef(() => ServiceA))
    private serviceA: ServiceA,
  ) {}
}

// Better solution: Use events
@Injectable()
export class ServiceA {
  constructor(private eventEmitter: EventEmitter2) {}

  doSomething() {
    this.eventEmitter.emit('serviceA.action', data);
  }
}`
  },

  cannotResolveDepedency: {
    error: "Nest can't resolve dependencies of the X",
    causes: [
      "Provider not added to module's providers array",
      "Module not imported where the provider is used",
      "Injection token mismatch",
      "Missing @Injectable() decorator"
    ],
    solutions: [
      "Add the provider to the module's providers array",
      "Import the module that exports the provider",
      "Check for typos in injection tokens",
      "Add @Injectable() decorator to the class",
      "Export the provider from its module"
    ],
    example: `// Problem: UserService not available
@Module({
  controllers: [UserController],
  // Missing: providers: [UserService]
})

// Solution 1: Add to providers
@Module({
  controllers: [UserController],
  providers: [UserService],
})

// Solution 2: Import module that exports it
@Module({
  imports: [UserModule], // UserModule exports UserService
  controllers: [SomeController],
})`
  },

  unknownElement: {
    error: "Unknown element in template / Unknown module",
    causes: [
      "Module not imported in the current module",
      "Provider not exported from its module",
      "Typo in module/provider name"
    ],
    solutions: [
      "Import the required module",
      "Export the provider from its module",
      "Check spelling of imports and exports"
    ],
    example: `// UserModule needs to export UserService
@Module({
  providers: [UserService],
  exports: [UserService], // Don't forget this!
})
export class UserModule {}

// Then import in consumer module
@Module({
  imports: [UserModule],
})`
  },

  typeOrmConnection: {
    error: "TypeORM connection error / Repository not found",
    causes: [
      "Database connection configuration issues",
      "Entity not registered",
      "TypeOrmModule.forFeature() not called",
      "Wrong database credentials"
    ],
    solutions: [
      "Verify database connection settings",
      "Register entities in TypeOrmModule.forRoot()",
      "Import TypeOrmModule.forFeature([Entity]) in feature module",
      "Check database server is running"
    ],
    example: `// Register entity in root module
@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      entities: [User, Post], // Register entities
      // OR
      autoLoadEntities: true, // Auto-load all entities
    }),
  ],
})

// In feature module
@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UserService],
})`
  },

  validationFailed: {
    error: "Validation failed / BadRequestException",
    causes: [
      "Invalid input data",
      "Missing required fields",
      "Wrong data types",
      "ValidationPipe not enabled"
    ],
    solutions: [
      "Enable ValidationPipe globally or per-route",
      "Check DTO decorators match expected input",
      "Enable transform option for type conversion",
      "Review validation error messages"
    ],
    example: `// Enable ValidationPipe globally
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  transformOptions: {
    enableImplicitConversion: true,
  },
}));

// DTO with proper validation
export class CreateUserDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  age?: number;
}`
  },

  corsError: {
    error: "CORS error / Access-Control-Allow-Origin",
    causes: [
      "CORS not enabled",
      "Wrong origin configuration",
      "Missing headers in preflight",
      "Credentials mode mismatch"
    ],
    solutions: [
      "Enable CORS in main.ts",
      "Configure allowed origins properly",
      "Allow necessary headers and methods",
      "Set credentials if using cookies"
    ],
    example: `// Enable CORS
app.enableCors({
  origin: ['http://localhost:3000', 'https://myapp.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
});

// Or allow all (development only!)
app.enableCors();`
  },

  jwtExpired: {
    error: "JWT expired / Unauthorized",
    causes: [
      "Token has expired",
      "Token not provided",
      "Invalid token signature",
      "Wrong secret key"
    ],
    solutions: [
      "Implement token refresh mechanism",
      "Check token expiration settings",
      "Verify secret key matches",
      "Handle expired token error gracefully"
    ],
    example: `// Refresh token implementation
@Post('refresh')
async refresh(@Body() body: { refreshToken: string }) {
  const payload = await this.authService.verifyRefreshToken(body.refreshToken);

  const newAccessToken = this.jwtService.sign(
    { sub: payload.sub },
    { expiresIn: '15m' }
  );

  return { accessToken: newAccessToken };
}

// Handle in auth guard
catch (error) {
  if (error.name === 'TokenExpiredError') {
    throw new UnauthorizedException('Token expired');
  }
  throw new UnauthorizedException('Invalid token');
}`
  },

  memoryLeak: {
    error: "Memory leak / Heap out of memory",
    causes: [
      "Event listeners not removed",
      "Unclosed database connections",
      "Large data cached indefinitely",
      "Circular references in objects"
    ],
    solutions: [
      "Implement OnModuleDestroy for cleanup",
      "Use connection pooling",
      "Set TTL on cached data",
      "Profile memory usage",
      "Use streaming for large data"
    ],
    example: `// Proper cleanup
@Injectable()
export class MyService implements OnModuleDestroy {
  private subscriptions: Subscription[] = [];

  onModuleDestroy() {
    // Clean up subscriptions
    this.subscriptions.forEach(sub => sub.unsubscribe());

    // Close connections
    this.redis.disconnect();
  }
}

// Use streaming for large data
async processLargeFile(path: string) {
  const stream = createReadStream(path);
  for await (const chunk of stream) {
    await this.processChunk(chunk);
  }
}`
  }
};
