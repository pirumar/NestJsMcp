// NestJS Explanation Tools
import {
  coreConcepts,
  techniques,
  cliCommands,
  schematics,
  decorators,
  bestPractices,
  commonPackages,
} from '../data/nestjs-docs.js';

export interface ExplanationResult {
  title: string;
  description: string;
  content: string;
  examples?: string[];
  relatedTopics?: string[];
}

// Explain a NestJS concept
export function explainConcept(concept: string): ExplanationResult | null {
  const key = concept.toLowerCase().replace(/\s+/g, '');

  // Check core concepts
  if (coreConcepts[key]) {
    return {
      title: coreConcepts[key].title,
      description: coreConcepts[key].description,
      content: coreConcepts[key].content,
      examples: coreConcepts[key].examples,
      relatedTopics: coreConcepts[key].relatedTopics,
    };
  }

  // Check techniques
  if (techniques[key]) {
    return {
      title: techniques[key].title,
      description: techniques[key].description,
      content: techniques[key].content,
      examples: techniques[key].examples,
      relatedTopics: techniques[key].relatedTopics,
    };
  }

  // Try partial match
  const allConcepts = { ...coreConcepts, ...techniques };
  const matchingKey = Object.keys(allConcepts).find(
    (k) => k.includes(key) || key.includes(k)
  );

  if (matchingKey) {
    const matched = allConcepts[matchingKey];
    return {
      title: matched.title,
      description: matched.description,
      content: matched.content,
      examples: matched.examples,
      relatedTopics: matched.relatedTopics,
    };
  }

  return null;
}

// Explain a decorator
export function explainDecorator(decoratorName: string): ExplanationResult | null {
  const normalized = decoratorName.replace('@', '').replace('()', '');

  const decorator = decorators.find(
    (d) =>
      d.name.toLowerCase().includes(normalized.toLowerCase()) ||
      normalized.toLowerCase().includes(d.name.replace('@', '').replace('()', '').toLowerCase())
  );

  if (decorator) {
    return {
      title: decorator.name,
      description: decorator.description,
      content: `Type: ${decorator.type} decorator\n\nUsage: ${decorator.usage}`,
      examples: [decorator.usage],
    };
  }

  return null;
}

// Explain a CLI command
export function explainCliCommand(command: string): ExplanationResult | null {
  const normalized = command.toLowerCase().replace('nest ', '');

  const cmd = cliCommands.find(
    (c) =>
      c.command.toLowerCase().includes(normalized) ||
      c.alias?.toLowerCase().includes(normalized)
  );

  if (cmd) {
    const optionsContent = cmd.options
      ? '\n\nOptions:\n' + cmd.options.map((o) => `  ${o.flag}: ${o.description}`).join('\n')
      : '';

    return {
      title: cmd.command,
      description: cmd.description,
      content: cmd.description + optionsContent,
      examples: cmd.examples,
    };
  }

  return null;
}

// Explain a schematic
export function explainSchematic(schematicName: string): ExplanationResult | null {
  const normalized = schematicName.toLowerCase();

  const schematic = schematics.find(
    (s) => s.name.toLowerCase() === normalized || s.alias === normalized
  );

  if (schematic) {
    return {
      title: `nest generate ${schematic.name}`,
      description: schematic.description,
      content: `Schematic: ${schematic.name}\nAlias: ${schematic.alias}\n\n${schematic.description}`,
      examples: [
        `nest generate ${schematic.name} <name>`,
        `nest g ${schematic.alias} <name>`,
        `nest g ${schematic.alias} <name> --no-spec`,
      ],
    };
  }

  return null;
}

// Get all available concepts
export function listConcepts(): string[] {
  return [
    ...Object.keys(coreConcepts),
    ...Object.keys(techniques),
  ];
}

// Get all decorators
export function listDecorators(): { name: string; type: string; description: string }[] {
  return decorators.map((d) => ({
    name: d.name,
    type: d.type,
    description: d.description,
  }));
}

// Get all CLI commands
export function listCliCommands(): { command: string; description: string }[] {
  return cliCommands.map((c) => ({
    command: c.command,
    description: c.description,
  }));
}

// Get all schematics
export function listSchematics(): { name: string; alias: string; description: string }[] {
  return schematics.map((s) => ({
    name: s.name,
    alias: s.alias,
    description: s.description,
  }));
}

// Get best practices
export function getBestPractices(category?: 'structure' | 'code' | 'security'): ExplanationResult {
  switch (category) {
    case 'structure':
      return {
        title: 'Project Structure Best Practices',
        description: 'Recommended project structure for NestJS applications',
        content: bestPractices.projectStructure,
      };
    case 'code':
      return {
        title: 'Code Guidelines',
        description: 'Best practices for writing NestJS code',
        content: bestPractices.codeGuidelines.map((g, i) => `${i + 1}. ${g}`).join('\n'),
      };
    case 'security':
      return {
        title: 'Security Best Practices',
        description: 'Security recommendations for NestJS applications',
        content: bestPractices.securityPractices.map((p, i) => `${i + 1}. ${p}`).join('\n'),
      };
    default:
      return {
        title: 'NestJS Best Practices',
        description: 'Comprehensive best practices guide',
        content: `
## Project Structure
${bestPractices.projectStructure}

## Code Guidelines
${bestPractices.codeGuidelines.map((g, i) => `${i + 1}. ${g}`).join('\n')}

## Security Practices
${bestPractices.securityPractices.map((p, i) => `${i + 1}. ${p}`).join('\n')}
`,
      };
  }
}

// Get recommended packages
export function getRecommendedPackages(category?: string): { name: string; description: string }[] {
  if (category) {
    const categoryLower = category.toLowerCase();
    return commonPackages.filter(
      (p) =>
        p.name.toLowerCase().includes(categoryLower) ||
        p.description.toLowerCase().includes(categoryLower)
    );
  }
  return commonPackages;
}

// Search documentation
export function searchDocs(query: string): ExplanationResult[] {
  const results: ExplanationResult[] = [];
  const queryLower = query.toLowerCase();

  // Search concepts
  Object.entries(coreConcepts).forEach(([key, value]) => {
    if (
      key.includes(queryLower) ||
      value.title.toLowerCase().includes(queryLower) ||
      value.description.toLowerCase().includes(queryLower) ||
      value.content.toLowerCase().includes(queryLower)
    ) {
      results.push({
        title: value.title,
        description: value.description,
        content: value.content,
        examples: value.examples,
        relatedTopics: value.relatedTopics,
      });
    }
  });

  // Search techniques
  Object.entries(techniques).forEach(([key, value]) => {
    if (
      key.includes(queryLower) ||
      value.title.toLowerCase().includes(queryLower) ||
      value.description.toLowerCase().includes(queryLower) ||
      value.content.toLowerCase().includes(queryLower)
    ) {
      results.push({
        title: value.title,
        description: value.description,
        content: value.content,
        examples: value.examples,
        relatedTopics: value.relatedTopics,
      });
    }
  });

  return results;
}

// Get request lifecycle explanation
export function explainRequestLifecycle(): ExplanationResult {
  return {
    title: 'NestJS Request Lifecycle',
    description: 'Understanding how requests flow through NestJS',
    content: `
The NestJS request lifecycle defines the order in which different components process a request:

1. **Incoming Request**

2. **Middleware**
   - Global middleware
   - Module middleware
   - Route middleware

3. **Guards**
   - Global guards
   - Controller guards
   - Route guards

4. **Interceptors (pre-handler)**
   - Global interceptors
   - Controller interceptors
   - Route interceptors

5. **Pipes**
   - Global pipes
   - Controller pipes
   - Route pipes
   - Parameter pipes

6. **Route Handler**
   - Controller method execution

7. **Interceptors (post-handler)**
   - Route interceptors
   - Controller interceptors
   - Global interceptors

8. **Exception Filters** (if exception thrown)
   - Route filters
   - Controller filters
   - Global filters

9. **Response**
`,
    examples: [
      `// Order of execution example
@UseGuards(AuthGuard)           // 3rd: Guards
@UseInterceptors(LoggingInterceptor) // 4th & 7th: Interceptors
@UsePipes(ValidationPipe)       // 5th: Pipes
@Controller('users')
export class UserController {
  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    // 6th: Route handler
    return this.userService.findOne(id);
  }
}`,
    ],
    relatedTopics: ['middleware', 'guards', 'interceptors', 'pipes', 'filters'],
  };
}

// Explain dependency injection
export function explainDependencyInjection(): ExplanationResult {
  return {
    title: 'Dependency Injection in NestJS',
    description: 'Understanding NestJS DI system',
    content: `
NestJS has a built-in Dependency Injection (DI) container that manages the instantiation and lifecycle of providers.

## Key Concepts

### Providers
Any class decorated with @Injectable() can be a provider. Providers are registered in a module's providers array.

### Injection Scopes
- **DEFAULT (Singleton)**: Single instance shared across the entire application
- **REQUEST**: New instance created for each incoming request
- **TRANSIENT**: New instance created for each injection

### Injection Methods
1. **Constructor Injection** (recommended)
2. **Property Injection** with @Inject()
3. **Optional Dependencies** with @Optional()

### Custom Providers
- **Value Providers**: useValue
- **Class Providers**: useClass
- **Factory Providers**: useFactory
- **Existing Providers**: useExisting

### Injection Tokens
Use strings or Symbols when injecting non-class values.
`,
    examples: [
      `// Constructor injection
@Injectable()
export class UserService {
  constructor(
    private readonly configService: ConfigService,
    @InjectRepository(User) private userRepo: Repository<User>,
  ) {}
}`,
      `// Custom providers
@Module({
  providers: [
    {
      provide: 'CONFIG',
      useValue: { apiUrl: 'https://api.example.com' },
    },
    {
      provide: 'DATABASE',
      useFactory: (config: ConfigService) => createConnection(config.get('db')),
      inject: [ConfigService],
    },
  ],
})
export class AppModule {}`,
    ],
    relatedTopics: ['providers', 'modules', 'scope'],
  };
}
