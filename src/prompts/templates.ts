// NestJS MCP Prompt Templates

export interface PromptTemplate {
  name: string;
  description: string;
  arguments?: PromptArgument[];
  template: string;
}

export interface PromptArgument {
  name: string;
  description: string;
  required: boolean;
}

// All available prompts
export const prompts: PromptTemplate[] = [
  {
    name: 'create-module',
    description: 'Generate a complete NestJS module with controller, service, and entities',
    arguments: [
      { name: 'name', description: 'Module name (e.g., users, products)', required: true },
      { name: 'features', description: 'Features to include (crud, auth, validation)', required: false },
    ],
    template: `Create a complete NestJS module for "{{name}}" with the following structure:

1. **Module** ({{name}}.module.ts)
   - Import necessary modules
   - Register controller and service
   - Export service if needed

2. **Controller** ({{name}}.controller.ts)
   {{#if features.crud}}
   - CRUD endpoints (GET, POST, PUT, DELETE)
   - Proper route parameters and body handling
   - Use DTOs for validation
   {{/if}}
   {{#if features.auth}}
   - Add @UseGuards(AuthGuard) where needed
   {{/if}}

3. **Service** ({{name}}.service.ts)
   - Business logic implementation
   - Repository injection for database operations
   - Proper error handling with NestJS exceptions

4. **DTOs** (dto/)
   - Create{{Name}}Dto with validation decorators
   - Update{{Name}}Dto with optional fields

5. **Entity** (entities/{{name}}.entity.ts)
   - TypeORM entity definition
   - Proper column types and relations

Please follow NestJS best practices and include proper TypeScript types.`,
  },

  {
    name: 'create-auth',
    description: 'Generate authentication module with JWT',
    arguments: [
      { name: 'strategy', description: 'Auth strategy (jwt, local, oauth)', required: false },
    ],
    template: `Create a complete authentication module for NestJS with:

1. **AuthModule** with:
   - PassportModule
   - JwtModule configuration
   - Strategy providers

2. **AuthService** with:
   - validateUser() method
   - login() method returning JWT
   - register() method (optional)

3. **Strategies**:
   {{#if strategy.jwt}}
   - JwtStrategy extending PassportStrategy
   {{/if}}
   {{#if strategy.local}}
   - LocalStrategy for username/password
   {{/if}}

4. **Guards**:
   - JwtAuthGuard
   - LocalAuthGuard

5. **DTOs**:
   - LoginDto
   - RegisterDto

6. **Decorators**:
   - @Public() for public routes
   - @CurrentUser() for extracting user from request

Include proper error handling and security best practices.`,
  },

  {
    name: 'create-crud-api',
    description: 'Generate a complete CRUD API endpoint',
    arguments: [
      { name: 'resource', description: 'Resource name', required: true },
      { name: 'fields', description: 'Entity fields (comma-separated)', required: false },
    ],
    template: `Create a complete CRUD API for "{{resource}}" resource:

## Entity Fields
{{#if fields}}
{{fields}}
{{else}}
- id (primary key)
- name (string)
- description (string, optional)
- isActive (boolean, default true)
- createdAt (timestamp)
- updatedAt (timestamp)
{{/if}}

## Required Files

1. **Controller** with endpoints:
   - POST /{{resource}} - Create
   - GET /{{resource}} - List all (with pagination)
   - GET /{{resource}}/:id - Get one
   - PUT /{{resource}}/:id - Update
   - DELETE /{{resource}}/:id - Delete

2. **Service** with:
   - TypeORM repository injection
   - Proper error handling (NotFoundException, etc.)
   - Pagination support

3. **DTOs** with class-validator decorators

4. **Entity** with TypeORM decorators

5. **Module** registering all components

Include Swagger decorators for API documentation.`,
  },

  {
    name: 'add-validation',
    description: 'Add validation to an existing DTO or controller',
    arguments: [
      { name: 'code', description: 'Existing code to add validation to', required: true },
    ],
    template: `Add comprehensive validation to the following code using class-validator:

{{code}}

Requirements:
1. Add appropriate validation decorators:
   - @IsString(), @IsNumber(), @IsBoolean() for types
   - @IsEmail(), @IsUrl(), @IsUUID() for formats
   - @MinLength(), @MaxLength(), @Length() for strings
   - @Min(), @Max() for numbers
   - @IsOptional() for optional fields
   - @ValidateNested() + @Type() for nested objects

2. Add @ApiProperty() decorators for Swagger documentation

3. Include meaningful validation messages

4. Consider security (sanitization, whitelist)`,
  },

  {
    name: 'add-swagger',
    description: 'Add OpenAPI/Swagger documentation to code',
    arguments: [
      { name: 'code', description: 'Code to document', required: true },
    ],
    template: `Add comprehensive Swagger/OpenAPI documentation to:

{{code}}

Add:
1. @ApiTags() for controller grouping
2. @ApiOperation() with summary and description
3. @ApiResponse() for all possible responses (200, 201, 400, 401, 404, 500)
4. @ApiProperty() for all DTO properties with:
   - description
   - example values
   - required/optional
5. @ApiBearerAuth() if authentication is used
6. @ApiQuery() for query parameters
7. @ApiParam() for path parameters`,
  },

  {
    name: 'create-guard',
    description: 'Create a custom guard',
    arguments: [
      { name: 'name', description: 'Guard name', required: true },
      { name: 'type', description: 'Guard type (auth, roles, throttle, custom)', required: false },
    ],
    template: `Create a NestJS guard named "{{name}}":

Type: {{type}}

Requirements:
1. Implement CanActivate interface
2. Use ExecutionContext properly
3. Handle errors with appropriate exceptions
{{#if type.roles}}
4. Use Reflector for reading metadata
5. Create corresponding @Roles() decorator
{{/if}}
{{#if type.auth}}
4. Extract and validate JWT token
5. Attach user to request object
{{/if}}
{{#if type.throttle}}
4. Implement rate limiting logic
5. Use cache for tracking requests
{{/if}}

Include proper TypeScript types and error handling.`,
  },

  {
    name: 'create-interceptor',
    description: 'Create a custom interceptor',
    arguments: [
      { name: 'name', description: 'Interceptor name', required: true },
      { name: 'type', description: 'Interceptor type (logging, transform, cache, timeout)', required: false },
    ],
    template: `Create a NestJS interceptor named "{{name}}":

Type: {{type}}

Requirements:
1. Implement NestInterceptor interface
2. Use RxJS operators properly
{{#if type.logging}}
3. Log request method, URL, and timing
4. Use NestJS Logger
{{/if}}
{{#if type.transform}}
3. Wrap response in standard format
4. Add timestamp and success flag
{{/if}}
{{#if type.cache}}
3. Check cache before handler
4. Store result in cache after handler
{{/if}}
{{#if type.timeout}}
3. Use RxJS timeout operator
4. Throw RequestTimeoutException
{{/if}}

Include proper error handling and TypeScript types.`,
  },

  {
    name: 'create-pipe',
    description: 'Create a custom pipe',
    arguments: [
      { name: 'name', description: 'Pipe name', required: true },
      { name: 'type', description: 'Pipe type (validation, transform)', required: false },
    ],
    template: `Create a NestJS pipe named "{{name}}":

Type: {{type}}

Requirements:
1. Implement PipeTransform interface
2. Use ArgumentMetadata properly
{{#if type.validation}}
3. Validate input according to rules
4. Throw BadRequestException with details
{{/if}}
{{#if type.transform}}
3. Transform input to desired format
4. Handle edge cases
{{/if}}

Include proper TypeScript types and meaningful error messages.`,
  },

  {
    name: 'create-filter',
    description: 'Create a custom exception filter',
    arguments: [
      { name: 'name', description: 'Filter name', required: true },
      { name: 'exception', description: 'Exception type to catch', required: false },
    ],
    template: `Create a NestJS exception filter named "{{name}}":

Catches: {{exception}}

Requirements:
1. Implement ExceptionFilter interface
2. Use @Catch() decorator properly
3. Extract request and response from ArgumentsHost
4. Return consistent error response format:
   - statusCode
   - timestamp
   - path
   - message
   - errors (for validation)
5. Log errors appropriately
6. Handle different exception types

Include proper TypeScript types.`,
  },

  {
    name: 'create-middleware',
    description: 'Create custom middleware',
    arguments: [
      { name: 'name', description: 'Middleware name', required: true },
    ],
    template: `Create a NestJS middleware named "{{name}}":

Requirements:
1. Implement NestMiddleware interface
2. Access Request, Response, NextFunction
3. Call next() to continue pipeline
4. Add logging with NestJS Logger

Also show how to apply this middleware in a module using MiddlewareConsumer.`,
  },

  {
    name: 'explain-concept',
    description: 'Explain a NestJS concept in detail',
    arguments: [
      { name: 'concept', description: 'Concept to explain', required: true },
    ],
    template: `Explain the NestJS concept "{{concept}}" in detail:

1. What it is and its purpose
2. When to use it
3. How it works internally
4. Best practices
5. Common pitfalls to avoid
6. Code examples showing proper usage
7. Related concepts`,
  },

  {
    name: 'review-code',
    description: 'Review NestJS code for best practices',
    arguments: [
      { name: 'code', description: 'Code to review', required: true },
    ],
    template: `Review the following NestJS code for best practices:

{{code}}

Analyze:
1. Code structure and organization
2. Proper use of NestJS patterns
3. Error handling
4. Security considerations
5. Performance implications
6. Testing considerations
7. Suggested improvements

Provide specific recommendations with code examples.`,
  },

  {
    name: 'debug-issue',
    description: 'Help debug a NestJS issue',
    arguments: [
      { name: 'issue', description: 'Description of the issue', required: true },
      { name: 'code', description: 'Relevant code', required: false },
      { name: 'error', description: 'Error message', required: false },
    ],
    template: `Help debug this NestJS issue:

**Issue:** {{issue}}

{{#if code}}
**Code:**
{{code}}
{{/if}}

{{#if error}}
**Error:**
{{error}}
{{/if}}

Please:
1. Identify potential causes
2. Explain why this might be happening
3. Suggest solutions with code examples
4. Recommend how to prevent this in the future`,
  },

  {
    name: 'migrate-express',
    description: 'Help migrate Express.js code to NestJS',
    arguments: [
      { name: 'code', description: 'Express.js code to migrate', required: true },
    ],
    template: `Migrate the following Express.js code to NestJS:

{{code}}

Requirements:
1. Convert routes to Controllers
2. Convert middleware to NestJS equivalents (Middleware, Guards, Interceptors)
3. Use proper dependency injection
4. Add DTOs with validation
5. Use NestJS exception handling
6. Follow NestJS best practices

Explain the mapping between Express and NestJS patterns.`,
  },

  {
    name: 'setup-testing',
    description: 'Set up testing for a NestJS module',
    arguments: [
      { name: 'module', description: 'Module name to test', required: true },
    ],
    template: `Set up comprehensive testing for the "{{module}}" module:

1. **Unit Tests** for Service:
   - Mock repository
   - Test all methods
   - Test error cases

2. **Controller Tests**:
   - Mock service
   - Test all endpoints
   - Test validation

3. **E2E Tests**:
   - Set up test application
   - Test complete request/response cycle
   - Test authentication if applicable

Include:
- Jest configuration
- Test utilities and factories
- Mocking strategies
- Coverage configuration`,
  },

  {
    name: 'setup-database',
    description: 'Set up database connection',
    arguments: [
      { name: 'database', description: 'Database type (postgres, mysql, mongodb)', required: true },
      { name: 'orm', description: 'ORM to use (typeorm, prisma, mongoose)', required: false },
    ],
    template: `Set up {{database}} database connection with {{orm}}:

1. **Installation**: Required packages

2. **Configuration**:
   - Environment variables
   - Module configuration
   - Connection options

3. **Entity/Schema** example

4. **Repository/Service** pattern

5. **Migrations** setup (if applicable)

6. **Best practices**:
   - Connection pooling
   - Error handling
   - Testing setup`,
  },
];

// Get prompt by name
export function getPrompt(name: string): PromptTemplate | undefined {
  return prompts.find((p) => p.name === name);
}

// Get all prompt names
export function listPrompts(): { name: string; description: string }[] {
  return prompts.map((p) => ({
    name: p.name,
    description: p.description,
  }));
}

// Render a prompt with arguments
export function renderPrompt(name: string, args: Record<string, string>): string | null {
  const prompt = getPrompt(name);
  if (!prompt) return null;

  let rendered = prompt.template;

  // Simple template replacement
  Object.entries(args).forEach(([key, value]) => {
    rendered = rendered.replace(new RegExp(`{{${key}}}`, 'g'), value);

    // Handle conditional blocks (simplified)
    const ifRegex = new RegExp(`{{#if ${key}}}([\\s\\S]*?){{/if}}`, 'g');
    if (value) {
      rendered = rendered.replace(ifRegex, '$1');
    } else {
      rendered = rendered.replace(ifRegex, '');
    }
  });

  // Clean up any remaining template syntax
  rendered = rendered.replace(/{{[^}]+}}/g, '');
  rendered = rendered.replace(/{{#if [^}]+}}[\s\S]*?{{\/if}}/g, '');

  return rendered;
}
