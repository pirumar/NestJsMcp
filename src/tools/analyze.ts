// NestJS Code Analysis Tools

export interface AnalysisResult {
  type: string;
  name: string;
  issues: AnalysisIssue[];
  suggestions: string[];
  metrics?: Record<string, number>;
}

export interface AnalysisIssue {
  severity: 'error' | 'warning' | 'info';
  message: string;
  line?: number;
  suggestion?: string;
}

// Analyze controller code
export function analyzeController(code: string): AnalysisResult {
  const issues: AnalysisIssue[] = [];
  const suggestions: string[] = [];

  // Check for @Controller decorator
  if (!code.includes('@Controller')) {
    issues.push({
      severity: 'error',
      message: 'Missing @Controller decorator',
      suggestion: 'Add @Controller() decorator to the class',
    });
  }

  // Check for constructor injection
  if (code.includes('constructor(') && !code.includes('private') && !code.includes('readonly')) {
    issues.push({
      severity: 'warning',
      message: 'Consider using private readonly for constructor parameters',
      suggestion: 'Use "private readonly" for injected dependencies',
    });
  }

  // Check for async/await consistency
  const asyncMethods = (code.match(/async\s+\w+\s*\(/g) || []).length;
  const promiseReturns = (code.match(/Promise</g) || []).length;
  if (asyncMethods > 0 && promiseReturns === 0) {
    issues.push({
      severity: 'info',
      message: 'Consider adding return type annotations for async methods',
    });
  }

  // Check for @Res() usage warning
  if (code.includes('@Res()')) {
    issues.push({
      severity: 'warning',
      message: '@Res() disables automatic response handling',
      suggestion: 'Prefer returning values directly unless manual response control is needed',
    });
  }

  // Check for route parameter validation
  if (code.includes('@Param(') && !code.includes('Pipe')) {
    suggestions.push('Consider using ParseIntPipe or ParseUUIDPipe for route parameters');
  }

  // Check for DTOs in body
  if (code.includes('@Body()') && !code.includes('Dto')) {
    suggestions.push('Use DTOs with class-validator for request body validation');
  }

  // Extract controller name
  const nameMatch = code.match(/class\s+(\w+)Controller/);
  const name = nameMatch ? nameMatch[1] : 'Unknown';

  return {
    type: 'controller',
    name,
    issues,
    suggestions,
    metrics: {
      methodCount: (code.match(/@(Get|Post|Put|Delete|Patch)\(/g) || []).length,
      hasGuards: code.includes('@UseGuards') ? 1 : 0,
      hasInterceptors: code.includes('@UseInterceptors') ? 1 : 0,
    },
  };
}

// Analyze service code
export function analyzeService(code: string): AnalysisResult {
  const issues: AnalysisIssue[] = [];
  const suggestions: string[] = [];

  // Check for @Injectable decorator
  if (!code.includes('@Injectable')) {
    issues.push({
      severity: 'error',
      message: 'Missing @Injectable decorator',
      suggestion: 'Add @Injectable() decorator to make the class injectable',
    });
  }

  // Check for error handling
  if (!code.includes('throw') && !code.includes('try')) {
    suggestions.push('Consider adding error handling with appropriate NestJS exceptions');
  }

  // Check for proper exception types
  if (code.includes('throw new Error(')) {
    issues.push({
      severity: 'warning',
      message: 'Use NestJS HttpException instead of generic Error',
      suggestion: 'Use NotFoundException, BadRequestException, etc.',
    });
  }

  // Check for transaction usage with multiple operations
  if (code.includes('Repository') && code.includes('save') && !code.includes('transaction')) {
    const saveCount = (code.match(/\.save\(/g) || []).length;
    if (saveCount > 1) {
      suggestions.push('Consider using transactions for multiple database operations');
    }
  }

  // Check for logging
  if (!code.includes('Logger')) {
    suggestions.push('Consider adding a Logger for debugging and monitoring');
  }

  // Extract service name
  const nameMatch = code.match(/class\s+(\w+)Service/);
  const name = nameMatch ? nameMatch[1] : 'Unknown';

  return {
    type: 'service',
    name,
    issues,
    suggestions,
    metrics: {
      methodCount: (code.match(/\basync\s+\w+\s*\(|public\s+\w+\s*\(/g) || []).length,
      hasRepository: code.includes('Repository') ? 1 : 0,
      hasLogger: code.includes('Logger') ? 1 : 0,
    },
  };
}

// Analyze module code
export function analyzeModule(code: string): AnalysisResult {
  const issues: AnalysisIssue[] = [];
  const suggestions: string[] = [];

  // Check for @Module decorator
  if (!code.includes('@Module')) {
    issues.push({
      severity: 'error',
      message: 'Missing @Module decorator',
    });
  }

  // Check for empty module
  if (code.includes('@Module({})') || code.includes('@Module({ })')) {
    issues.push({
      severity: 'warning',
      message: 'Empty module configuration',
      suggestion: 'Add providers, controllers, or imports to the module',
    });
  }

  // Check if controllers have matching providers
  const controllerMatch = code.match(/controllers:\s*\[([\s\S]*?)\]/);
  const providerMatch = code.match(/providers:\s*\[([\s\S]*?)\]/);

  if (controllerMatch && !providerMatch) {
    suggestions.push('Controllers typically need services - consider adding providers');
  }

  // Check for exports
  if (!code.includes('exports:')) {
    suggestions.push('Consider exporting providers that other modules might need');
  }

  // Extract module name
  const nameMatch = code.match(/class\s+(\w+)Module/);
  const name = nameMatch ? nameMatch[1] : 'Unknown';

  return {
    type: 'module',
    name,
    issues,
    suggestions,
    metrics: {
      imports: (code.match(/imports:\s*\[[\s\S]*?\]/g) || []).length,
      controllers: (code.match(/\w+Controller/g) || []).length,
      providers: (code.match(/\w+Service|\w+Provider/g) || []).length,
    },
  };
}

// Analyze DTO code
export function analyzeDto(code: string): AnalysisResult {
  const issues: AnalysisIssue[] = [];
  const suggestions: string[] = [];

  // Check for validation decorators
  if (!code.includes('class-validator') && !code.includes('@Is')) {
    issues.push({
      severity: 'warning',
      message: 'No validation decorators found',
      suggestion: 'Add class-validator decorators for input validation',
    });
  }

  // Check for optional fields
  if (code.includes('?:') && !code.includes('@IsOptional')) {
    issues.push({
      severity: 'warning',
      message: 'Optional fields should use @IsOptional() decorator',
    });
  }

  // Check for nested objects
  if (code.includes('[]') && !code.includes('@ValidateNested')) {
    suggestions.push('Use @ValidateNested() and @Type() for nested object validation');
  }

  // Check for API documentation
  if (!code.includes('@ApiProperty')) {
    suggestions.push('Add @ApiProperty decorators for Swagger documentation');
  }

  // Extract DTO name
  const nameMatch = code.match(/class\s+(\w+Dto)/);
  const name = nameMatch ? nameMatch[1] : 'Unknown';

  return {
    type: 'dto',
    name,
    issues,
    suggestions,
    metrics: {
      fieldCount: (code.match(/\w+[?]?:\s*\w+/g) || []).length,
      validatorCount: (code.match(/@Is\w+|@Min|@Max|@Length/g) || []).length,
    },
  };
}

// Analyze entity code
export function analyzeEntity(code: string): AnalysisResult {
  const issues: AnalysisIssue[] = [];
  const suggestions: string[] = [];

  // Check for @Entity decorator
  if (!code.includes('@Entity')) {
    issues.push({
      severity: 'error',
      message: 'Missing @Entity decorator',
    });
  }

  // Check for primary key
  if (!code.includes('@PrimaryGeneratedColumn') && !code.includes('@PrimaryColumn')) {
    issues.push({
      severity: 'error',
      message: 'Missing primary key column',
      suggestion: 'Add @PrimaryGeneratedColumn() or @PrimaryColumn()',
    });
  }

  // Check for timestamps
  if (!code.includes('CreateDateColumn') && !code.includes('createdAt')) {
    suggestions.push('Consider adding @CreateDateColumn() for audit tracking');
  }

  // Check for indexes on foreign keys
  if (code.includes('@ManyToOne') && !code.includes('@Index')) {
    suggestions.push('Consider adding @Index() on foreign key columns for performance');
  }

  // Check for column options
  if (code.includes('@Column()') && !code.includes('@Column({')) {
    suggestions.push('Consider specifying column options (type, length, nullable) explicitly');
  }

  // Extract entity name
  const nameMatch = code.match(/class\s+(\w+)/);
  const name = nameMatch ? nameMatch[1] : 'Unknown';

  return {
    type: 'entity',
    name,
    issues,
    suggestions,
    metrics: {
      columnCount: (code.match(/@Column/g) || []).length,
      relationCount: (code.match(/@(OneToMany|ManyToOne|OneToOne|ManyToMany)/g) || []).length,
    },
  };
}

// Analyze guard code
export function analyzeGuard(code: string): AnalysisResult {
  const issues: AnalysisIssue[] = [];
  const suggestions: string[] = [];

  // Check for CanActivate implementation
  if (!code.includes('CanActivate')) {
    issues.push({
      severity: 'error',
      message: 'Guard must implement CanActivate interface',
    });
  }

  // Check for canActivate method
  if (!code.includes('canActivate')) {
    issues.push({
      severity: 'error',
      message: 'Missing canActivate method',
    });
  }

  // Check for proper exception handling
  if (!code.includes('UnauthorizedException') && !code.includes('ForbiddenException')) {
    suggestions.push('Consider throwing UnauthorizedException or ForbiddenException for better error handling');
  }

  // Check for Reflector usage in roles guard
  if (code.toLowerCase().includes('role') && !code.includes('Reflector')) {
    suggestions.push('Use Reflector to read metadata for role-based guards');
  }

  // Extract guard name
  const nameMatch = code.match(/class\s+(\w+)Guard/);
  const name = nameMatch ? nameMatch[1] : 'Unknown';

  return {
    type: 'guard',
    name,
    issues,
    suggestions,
  };
}

// General code analysis
export function analyzeCode(code: string): AnalysisResult {
  // Detect code type
  if (code.includes('@Controller')) {
    return analyzeController(code);
  }
  if (code.includes('@Injectable') && code.includes('Service')) {
    return analyzeService(code);
  }
  if (code.includes('@Module')) {
    return analyzeModule(code);
  }
  if (code.includes('Dto') && (code.includes('@Is') || code.includes('class-validator'))) {
    return analyzeDto(code);
  }
  if (code.includes('@Entity')) {
    return analyzeEntity(code);
  }
  if (code.includes('CanActivate') || code.includes('Guard')) {
    return analyzeGuard(code);
  }

  // Generic analysis
  return {
    type: 'unknown',
    name: 'Unknown',
    issues: [],
    suggestions: ['Could not determine code type for specific analysis'],
  };
}

// Suggest improvements
export function suggestImprovements(code: string): string[] {
  const suggestions: string[] = [];

  // General suggestions
  if (!code.includes('Logger')) {
    suggestions.push('Add logging for better debugging and monitoring');
  }

  if (code.includes('any')) {
    suggestions.push('Avoid using "any" type - use proper TypeScript types');
  }

  if (code.includes('console.log')) {
    suggestions.push('Replace console.log with NestJS Logger');
  }

  if (!code.includes('async') && code.includes('await')) {
    suggestions.push('Ensure async keyword is present for functions using await');
  }

  if (code.includes('require(')) {
    suggestions.push('Use ES6 imports instead of require()');
  }

  // NestJS specific
  if (code.includes('@Inject(') && code.includes("'")) {
    suggestions.push('Consider using Symbol for injection tokens instead of strings');
  }

  if (code.includes('forwardRef')) {
    suggestions.push('forwardRef indicates circular dependency - consider refactoring');
  }

  return suggestions;
}

// Validate NestJS structure
export function validateStructure(files: string[]): AnalysisResult {
  const issues: AnalysisIssue[] = [];
  const suggestions: string[] = [];

  const hasModule = files.some((f) => f.endsWith('.module.ts'));
  const hasController = files.some((f) => f.endsWith('.controller.ts'));
  const hasService = files.some((f) => f.endsWith('.service.ts'));
  const hasMain = files.some((f) => f === 'main.ts');
  const hasAppModule = files.some((f) => f === 'app.module.ts');

  if (!hasMain) {
    issues.push({
      severity: 'error',
      message: 'Missing main.ts entry point',
    });
  }

  if (!hasAppModule) {
    issues.push({
      severity: 'error',
      message: 'Missing app.module.ts root module',
    });
  }

  if (!hasModule) {
    issues.push({
      severity: 'warning',
      message: 'No feature modules found',
      suggestion: 'Organize code into feature modules',
    });
  }

  if (hasController && !hasService) {
    suggestions.push('Controllers should typically have corresponding services');
  }

  // Check for common directories
  const hasDtoDir = files.some((f) => f.includes('/dto/'));
  const hasEntitiesDir = files.some((f) => f.includes('/entities/'));

  if (!hasDtoDir && hasController) {
    suggestions.push('Create a dto/ directory for Data Transfer Objects');
  }

  if (!hasEntitiesDir && files.some((f) => f.includes('typeorm') || f.includes('entity'))) {
    suggestions.push('Create an entities/ directory for database entities');
  }

  return {
    type: 'structure',
    name: 'Project',
    issues,
    suggestions,
    metrics: {
      modules: files.filter((f) => f.endsWith('.module.ts')).length,
      controllers: files.filter((f) => f.endsWith('.controller.ts')).length,
      services: files.filter((f) => f.endsWith('.service.ts')).length,
      entities: files.filter((f) => f.endsWith('.entity.ts')).length,
    },
  };
}
