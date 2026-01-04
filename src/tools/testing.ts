// NestJS Testing Generation Tools

export interface TestResult {
  filename: string;
  code: string;
  description: string;
}

// Generate unit test for a service
export function generateServiceTest(serviceName: string, methods: string[] = []): TestResult {
  const className = toPascalCase(serviceName);
  const fileName = toKebabCase(serviceName);

  const methodTests = methods.map(method => `
  describe('${method}', () => {
    it('should be defined', () => {
      expect(service.${method}).toBeDefined();
    });

    it('should ${method} successfully', async () => {
      // Arrange
      const expected = {}; // TODO: Define expected result

      // Act
      const result = await service.${method}();

      // Assert
      expect(result).toEqual(expected);
    });

    it('should handle errors', async () => {
      // Arrange
      jest.spyOn(repository, 'findOne').mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(service.${method}()).rejects.toThrow();
    });
  });`).join('\n');

  const code = `import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ${className}Service } from './${fileName}.service';
import { ${className} } from './entities/${fileName}.entity';
import { NotFoundException } from '@nestjs/common';

describe('${className}Service', () => {
  let service: ${className}Service;
  let repository: jest.Mocked<Repository<${className}>>;

  const mockRepository = {
    find: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    remove: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ${className}Service,
        {
          provide: getRepositoryToken(${className}),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<${className}Service>(${className}Service);
    repository = module.get(getRepositoryToken(${className}));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findAll', () => {
    it('should return an array of ${fileName}s', async () => {
      const expected = [{ id: 1, name: 'Test' }];
      mockRepository.find.mockResolvedValue(expected);

      const result = await service.findAll();

      expect(result).toEqual(expected);
      expect(mockRepository.find).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a ${fileName} if found', async () => {
      const expected = { id: 1, name: 'Test' };
      mockRepository.findOne.mockResolvedValue(expected);

      const result = await service.findOne(1);

      expect(result).toEqual(expected);
      expect(mockRepository.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
    });

    it('should throw NotFoundException if ${fileName} not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      await expect(service.findOne(999)).rejects.toThrow(NotFoundException);
    });
  });

  describe('create', () => {
    it('should create a new ${fileName}', async () => {
      const createDto = { name: 'New Test' };
      const expected = { id: 1, ...createDto };

      mockRepository.create.mockReturnValue(expected);
      mockRepository.save.mockResolvedValue(expected);

      const result = await service.create(createDto);

      expect(result).toEqual(expected);
      expect(mockRepository.create).toHaveBeenCalledWith(createDto);
      expect(mockRepository.save).toHaveBeenCalled();
    });
  });

  describe('update', () => {
    it('should update an existing ${fileName}', async () => {
      const existing = { id: 1, name: 'Old Name' };
      const updateDto = { name: 'New Name' };
      const expected = { ...existing, ...updateDto };

      mockRepository.findOne.mockResolvedValue(existing);
      mockRepository.save.mockResolvedValue(expected);

      const result = await service.update(1, updateDto);

      expect(result).toEqual(expected);
    });
  });

  describe('remove', () => {
    it('should remove an existing ${fileName}', async () => {
      const existing = { id: 1, name: 'Test' };
      mockRepository.findOne.mockResolvedValue(existing);
      mockRepository.remove.mockResolvedValue(existing);

      await service.remove(1);

      expect(mockRepository.remove).toHaveBeenCalledWith(existing);
    });
  });
${methodTests}
});
`;

  return {
    filename: `${fileName}.service.spec.ts`,
    code,
    description: `Unit tests for ${className}Service`,
  };
}

// Generate unit test for a controller
export function generateControllerTest(controllerName: string): TestResult {
  const className = toPascalCase(controllerName);
  const fileName = toKebabCase(controllerName);
  const serviceName = `${toCamelCase(controllerName)}Service`;

  const code = `import { Test, TestingModule } from '@nestjs/testing';
import { ${className}Controller } from './${fileName}.controller';
import { ${className}Service } from './${fileName}.service';
import { Create${className}Dto } from './dto/create-${fileName}.dto';
import { Update${className}Dto } from './dto/update-${fileName}.dto';
import { NotFoundException } from '@nestjs/common';

describe('${className}Controller', () => {
  let controller: ${className}Controller;
  let service: jest.Mocked<${className}Service>;

  const mockService = {
    findAll: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [${className}Controller],
      providers: [
        {
          provide: ${className}Service,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<${className}Controller>(${className}Controller);
    service = module.get(${className}Service);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('findAll', () => {
    it('should return an array of ${fileName}s', async () => {
      const expected = [{ id: 1, name: 'Test' }];
      mockService.findAll.mockResolvedValue(expected);

      const result = await controller.findAll();

      expect(result).toEqual(expected);
      expect(mockService.findAll).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a single ${fileName}', async () => {
      const expected = { id: 1, name: 'Test' };
      mockService.findOne.mockResolvedValue(expected);

      const result = await controller.findOne(1);

      expect(result).toEqual(expected);
      expect(mockService.findOne).toHaveBeenCalledWith(1);
    });

    it('should throw NotFoundException if not found', async () => {
      mockService.findOne.mockRejectedValue(new NotFoundException());

      await expect(controller.findOne(999)).rejects.toThrow(NotFoundException);
    });
  });

  describe('create', () => {
    it('should create a new ${fileName}', async () => {
      const createDto: Create${className}Dto = { name: 'New Test' };
      const expected = { id: 1, ...createDto };
      mockService.create.mockResolvedValue(expected);

      const result = await controller.create(createDto);

      expect(result).toEqual(expected);
      expect(mockService.create).toHaveBeenCalledWith(createDto);
    });
  });

  describe('update', () => {
    it('should update an existing ${fileName}', async () => {
      const updateDto: Update${className}Dto = { name: 'Updated' };
      const expected = { id: 1, ...updateDto };
      mockService.update.mockResolvedValue(expected);

      const result = await controller.update(1, updateDto);

      expect(result).toEqual(expected);
      expect(mockService.update).toHaveBeenCalledWith(1, updateDto);
    });
  });

  describe('remove', () => {
    it('should remove an existing ${fileName}', async () => {
      mockService.remove.mockResolvedValue(undefined);

      await controller.remove(1);

      expect(mockService.remove).toHaveBeenCalledWith(1);
    });
  });
});
`;

  return {
    filename: `${fileName}.controller.spec.ts`,
    code,
    description: `Unit tests for ${className}Controller`,
  };
}

// Generate E2E test
export function generateE2ETest(moduleName: string, endpoints: {
  method: string;
  path: string;
  body?: Record<string, any>;
  expectedStatus?: number;
}[] = []): TestResult {
  const className = toPascalCase(moduleName);
  const fileName = toKebabCase(moduleName);

  const endpointTests = endpoints.map(ep => {
    const testBody = ep.body ? `.send(${JSON.stringify(ep.body)})` : '';
    return `
  it('${ep.method} ${ep.path}', () => {
    return request(app.getHttpServer())
      .${ep.method.toLowerCase()}('${ep.path}')${testBody}
      .expect(${ep.expectedStatus || 200});
  });`;
  }).join('\n');

  const defaultEndpoints = endpointTests || `
  it('GET /${fileName}', () => {
    return request(app.getHttpServer())
      .get('/${fileName}')
      .expect(200)
      .expect((res) => {
        expect(Array.isArray(res.body)).toBe(true);
      });
  });

  it('POST /${fileName}', () => {
    return request(app.getHttpServer())
      .post('/${fileName}')
      .send({ name: 'Test' })
      .expect(201)
      .expect((res) => {
        expect(res.body.name).toBe('Test');
      });
  });

  it('GET /${fileName}/:id', () => {
    return request(app.getHttpServer())
      .get('/${fileName}/1')
      .expect(200);
  });

  it('PUT /${fileName}/:id', () => {
    return request(app.getHttpServer())
      .put('/${fileName}/1')
      .send({ name: 'Updated' })
      .expect(200);
  });

  it('DELETE /${fileName}/:id', () => {
    return request(app.getHttpServer())
      .delete('/${fileName}/1')
      .expect(204);
  });

  it('GET /${fileName}/:id - should return 404 for non-existent', () => {
    return request(app.getHttpServer())
      .get('/${fileName}/99999')
      .expect(404);
  });`;

  const code = `import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { ${className}Module } from '../src/${fileName}/${fileName}.module';

describe('${className}Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });
${defaultEndpoints}
});
`;

  return {
    filename: `${fileName}.e2e-spec.ts`,
    code,
    description: `E2E tests for ${className} endpoints`,
  };
}

// Generate test factory
export function generateTestFactory(entityName: string, fields: { name: string; type: string; example?: any }[]): TestResult {
  const className = toPascalCase(entityName);
  const fileName = toKebabCase(entityName);

  const fieldDefaults = fields.map(f => {
    let value: string;
    switch (f.type) {
      case 'string':
        value = f.example ? `'${f.example}'` : `'test-${f.name}'`;
        break;
      case 'number':
        value = f.example?.toString() || '1';
        break;
      case 'boolean':
        value = f.example?.toString() || 'true';
        break;
      case 'Date':
        value = 'new Date()';
        break;
      default:
        value = 'null';
    }
    return `    ${f.name}: ${value},`;
  }).join('\n');

  const code = `import { ${className} } from '../entities/${fileName}.entity';
import { Create${className}Dto } from '../dto/create-${fileName}.dto';

export class ${className}Factory {
  static create(overrides: Partial<${className}> = {}): ${className} {
    const ${toCamelCase(entityName)} = new ${className}();

    const defaults = {
      id: 1,
${fieldDefaults}
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    return Object.assign(${toCamelCase(entityName)}, defaults, overrides);
  }

  static createMany(count: number, overrides: Partial<${className}> = {}): ${className}[] {
    return Array.from({ length: count }, (_, index) =>
      this.create({ ...overrides, id: index + 1 }),
    );
  }

  static createDto(overrides: Partial<Create${className}Dto> = {}): Create${className}Dto {
    const defaults: Create${className}Dto = {
${fieldDefaults.replace(/id:.*,\n/g, '').replace(/createdAt:.*,\n/g, '').replace(/updatedAt:.*,\n/g, '')}
    };

    return { ...defaults, ...overrides };
  }
}
`;

  return {
    filename: `${fileName}.factory.ts`,
    code,
    description: `Test factory for ${className}`,
  };
}

// Generate mock repository
export function generateMockRepository(entityName: string): TestResult {
  const className = toPascalCase(entityName);
  const fileName = toKebabCase(entityName);

  const code = `import { ${className} } from '../entities/${fileName}.entity';

export const mock${className}Repository = () => ({
  find: jest.fn(),
  findOne: jest.fn(),
  findOneBy: jest.fn(),
  findAndCount: jest.fn(),
  create: jest.fn().mockImplementation((dto) => dto),
  save: jest.fn().mockImplementation((entity) => Promise.resolve({ id: 1, ...entity })),
  update: jest.fn().mockResolvedValue({ affected: 1 }),
  delete: jest.fn().mockResolvedValue({ affected: 1 }),
  remove: jest.fn().mockImplementation((entity) => Promise.resolve(entity)),
  createQueryBuilder: jest.fn(() => ({
    where: jest.fn().mockReturnThis(),
    andWhere: jest.fn().mockReturnThis(),
    orderBy: jest.fn().mockReturnThis(),
    skip: jest.fn().mockReturnThis(),
    take: jest.fn().mockReturnThis(),
    getManyAndCount: jest.fn(),
    getOne: jest.fn(),
    getMany: jest.fn(),
  })),
  count: jest.fn(),
  exist: jest.fn(),
});

export type MockRepository<T> = {
  [P in keyof T]: jest.Mock;
};
`;

  return {
    filename: `mock-${fileName}.repository.ts`,
    code,
    description: `Mock repository for ${className}`,
  };
}

// Generate integration test helpers
export function generateTestHelpers(): TestResult {
  const code = `import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

/**
 * Create a testing module with in-memory SQLite database
 */
export async function createTestingModule(
  modules: any[],
  entities: any[],
): Promise<TestingModule> {
  return Test.createTestingModule({
    imports: [
      TypeOrmModule.forRoot({
        type: 'sqlite',
        database: ':memory:',
        entities,
        synchronize: true,
        dropSchema: true,
      }),
      TypeOrmModule.forFeature(entities),
      ...modules,
    ],
  }).compile();
}

/**
 * Create a NestJS application for testing
 */
export async function createTestingApp(
  module: TestingModule,
): Promise<INestApplication> {
  const app = module.createNestApplication();

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  await app.init();
  return app;
}

/**
 * Clean up testing resources
 */
export async function cleanupTestingApp(app: INestApplication): Promise<void> {
  if (app) {
    await app.close();
  }
}

/**
 * Generate random test data
 */
export const testData = {
  email: () => \`test-\${Date.now()}@example.com\`,
  username: () => \`user-\${Date.now()}\`,
  password: () => 'TestPassword123!',
  uuid: () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  }),
  number: (min = 1, max = 100) => Math.floor(Math.random() * (max - min + 1)) + min,
};

/**
 * Wait for a condition to be true
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeout = 5000,
  interval = 100,
): Promise<void> {
  const start = Date.now();

  while (Date.now() - start < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }

  throw new Error(\`Condition not met within \${timeout}ms\`);
}
`;

  return {
    filename: 'test-helpers.ts',
    code,
    description: 'Common test helper utilities',
  };
}

// Helper functions
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
