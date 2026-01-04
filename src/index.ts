#!/usr/bin/env node
/**
 * NestJS MCP Server
 * A Model Context Protocol server for NestJS development
 *
 * Provides:
 * - Tools for code generation
 * - Documentation resources
 * - Prompt templates for common tasks
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

// Import tools
import {
  generateController,
  generateService,
  generateModule,
  generateDto,
  generateEntity,
  generateGuard,
  generateInterceptor,
  generatePipe,
  generateFilter,
  generateMiddleware,
  generateResource,
} from './tools/generate.js';

import {
  explainConcept,
  explainDecorator,
  explainCliCommand,
  explainSchematic,
  listConcepts,
  listDecorators,
  listCliCommands,
  listSchematics,
  getBestPractices,
  getRecommendedPackages,
  searchDocs,
  explainRequestLifecycle,
  explainDependencyInjection,
} from './tools/explain.js';

import {
  analyzeController,
  analyzeService,
  analyzeModule,
  analyzeDto,
  analyzeEntity,
  analyzeGuard,
  analyzeCode,
  suggestImprovements,
  validateStructure,
} from './tools/analyze.js';

// Import scaffold tools
import { scaffoldProject } from './tools/scaffold.js';

// Import testing tools
import {
  generateServiceTest,
  generateControllerTest,
  generateE2ETest,
  generateTestFactory,
  generateMockRepository,
  generateTestHelpers,
} from './tools/testing.js';

// Import security tools
import {
  auditCode,
  performSecurityAudit,
  calculateSecurityScore,
  getSecurityChecklist,
  generateSecureMainTs,
} from './tools/security.js';

// Import deployment tools
import {
  generateGitHubActions,
  generateGitLabCI,
  generateKubernetesConfig,
  generatePM2Config,
  generateNginxConfig,
  generateSystemdService,
  generateEnvFiles,
} from './tools/deployment.js';

// Import advanced techniques
import { advancedTechniques, commonErrors } from './data/advanced-techniques.js';

// Import resources
import {
  getDocumentationResources,
  getResourceContent,
  searchResources,
} from './resources/documentation.js';

// Import prompts
import { prompts, getPrompt, renderPrompt } from './prompts/templates.js';

// Create server
const server = new Server(
  {
    name: 'nestjs-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {},
    },
  }
);

// ============================================
// TOOLS
// ============================================

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // Generation tools
      {
        name: 'nestjs_generate_controller',
        description: 'Generate a NestJS controller with optional CRUD operations',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Controller name' },
            crud: { type: 'boolean', description: 'Generate CRUD endpoints', default: false },
            prefix: { type: 'string', description: 'Route prefix' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_service',
        description: 'Generate a NestJS service with optional repository integration',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Service name' },
            crud: { type: 'boolean', description: 'Generate CRUD methods', default: false },
            withRepository: { type: 'boolean', description: 'Include TypeORM repository', default: false },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_module',
        description: 'Generate a NestJS module',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Module name' },
            withController: { type: 'boolean', description: 'Include controller', default: true },
            withService: { type: 'boolean', description: 'Include service', default: true },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_resource',
        description: 'Generate a complete CRUD resource (module, controller, service, entity, DTOs)',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Resource name' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_dto',
        description: 'Generate a DTO with validation decorators',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'DTO name' },
            type: { type: 'string', enum: ['create', 'update'], description: 'DTO type' },
            fields: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  type: { type: 'string' },
                  required: { type: 'boolean' },
                  validators: { type: 'array', items: { type: 'string' } },
                },
              },
              description: 'DTO fields',
            },
          },
          required: ['name', 'type', 'fields'],
        },
      },
      {
        name: 'nestjs_generate_entity',
        description: 'Generate a TypeORM entity',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Entity name' },
            fields: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  type: { type: 'string' },
                  primary: { type: 'boolean' },
                  unique: { type: 'boolean' },
                  nullable: { type: 'boolean' },
                },
              },
              description: 'Entity fields',
            },
          },
          required: ['name', 'fields'],
        },
      },
      {
        name: 'nestjs_generate_guard',
        description: 'Generate a NestJS guard',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Guard name' },
            type: { type: 'string', enum: ['auth', 'roles', 'custom'], description: 'Guard type', default: 'custom' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_interceptor',
        description: 'Generate a NestJS interceptor',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Interceptor name' },
            type: { type: 'string', enum: ['logging', 'transform', 'cache', 'timeout', 'custom'], description: 'Interceptor type', default: 'custom' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_pipe',
        description: 'Generate a NestJS pipe',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Pipe name' },
            type: { type: 'string', enum: ['validation', 'transform', 'custom'], description: 'Pipe type', default: 'custom' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_filter',
        description: 'Generate a NestJS exception filter',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Filter name' },
            exceptionType: { type: 'string', description: 'Exception type to catch', default: 'HttpException' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_middleware',
        description: 'Generate a NestJS middleware',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Middleware name' },
          },
          required: ['name'],
        },
      },

      // Explanation tools
      {
        name: 'nestjs_explain_concept',
        description: 'Explain a NestJS concept (modules, controllers, providers, guards, etc.)',
        inputSchema: {
          type: 'object',
          properties: {
            concept: { type: 'string', description: 'Concept to explain' },
          },
          required: ['concept'],
        },
      },
      {
        name: 'nestjs_explain_decorator',
        description: 'Explain a NestJS decorator',
        inputSchema: {
          type: 'object',
          properties: {
            decorator: { type: 'string', description: 'Decorator name (e.g., @Controller, @Injectable)' },
          },
          required: ['decorator'],
        },
      },
      {
        name: 'nestjs_explain_cli',
        description: 'Explain a NestJS CLI command',
        inputSchema: {
          type: 'object',
          properties: {
            command: { type: 'string', description: 'CLI command (e.g., generate, build, start)' },
          },
          required: ['command'],
        },
      },
      {
        name: 'nestjs_list_schematics',
        description: 'List all available NestJS schematics for code generation',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'nestjs_list_decorators',
        description: 'List all NestJS decorators',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'nestjs_best_practices',
        description: 'Get NestJS best practices',
        inputSchema: {
          type: 'object',
          properties: {
            category: { type: 'string', enum: ['structure', 'code', 'security'], description: 'Category of best practices' },
          },
        },
      },
      {
        name: 'nestjs_recommended_packages',
        description: 'Get recommended NestJS packages',
        inputSchema: {
          type: 'object',
          properties: {
            category: { type: 'string', description: 'Filter by category (auth, database, etc.)' },
          },
        },
      },
      {
        name: 'nestjs_search_docs',
        description: 'Search NestJS documentation',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query' },
          },
          required: ['query'],
        },
      },
      {
        name: 'nestjs_request_lifecycle',
        description: 'Explain the NestJS request lifecycle',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'nestjs_dependency_injection',
        description: 'Explain NestJS dependency injection system',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },

      // Analysis tools
      {
        name: 'nestjs_analyze_code',
        description: 'Analyze NestJS code for issues and improvements',
        inputSchema: {
          type: 'object',
          properties: {
            code: { type: 'string', description: 'Code to analyze' },
          },
          required: ['code'],
        },
      },
      {
        name: 'nestjs_suggest_improvements',
        description: 'Suggest improvements for NestJS code',
        inputSchema: {
          type: 'object',
          properties: {
            code: { type: 'string', description: 'Code to improve' },
          },
          required: ['code'],
        },
      },
      {
        name: 'nestjs_validate_structure',
        description: 'Validate NestJS project structure',
        inputSchema: {
          type: 'object',
          properties: {
            files: {
              type: 'array',
              items: { type: 'string' },
              description: 'List of file paths in the project',
            },
          },
          required: ['files'],
        },
      },

      // Scaffold tools
      {
        name: 'nestjs_scaffold_project',
        description: 'Generate a complete NestJS project with all configurations',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Project name' },
            database: { type: 'string', enum: ['postgres', 'mysql', 'mongodb', 'sqlite'], description: 'Database type' },
            auth: { type: 'boolean', description: 'Include authentication module' },
            swagger: { type: 'boolean', description: 'Include Swagger documentation' },
            docker: { type: 'boolean', description: 'Include Docker configuration' },
            testing: { type: 'boolean', description: 'Include testing setup' },
            websockets: { type: 'boolean', description: 'Include WebSocket support' },
          },
          required: ['name'],
        },
      },

      // Testing tools
      {
        name: 'nestjs_generate_service_test',
        description: 'Generate unit tests for a service',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Service name' },
            methods: { type: 'array', items: { type: 'string' }, description: 'Methods to test' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_controller_test',
        description: 'Generate unit tests for a controller',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Controller name' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_e2e_test',
        description: 'Generate E2E tests for a module',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Module name' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_test_factory',
        description: 'Generate a test factory for an entity',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Entity name' },
            fields: { type: 'array', items: { type: 'object' }, description: 'Entity fields' },
          },
          required: ['name'],
        },
      },

      // Security tools
      {
        name: 'nestjs_security_audit',
        description: 'Perform security audit on NestJS code',
        inputSchema: {
          type: 'object',
          properties: {
            code: { type: 'string', description: 'Code to audit' },
            filename: { type: 'string', description: 'Optional filename for context' },
          },
          required: ['code'],
        },
      },
      {
        name: 'nestjs_security_checklist',
        description: 'Get NestJS security best practices checklist',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'nestjs_generate_secure_main',
        description: 'Generate a security-hardened main.ts file',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },

      // Deployment tools
      {
        name: 'nestjs_generate_github_actions',
        description: 'Generate GitHub Actions CI/CD workflow',
        inputSchema: {
          type: 'object',
          properties: {
            nodeVersion: { type: 'string', description: 'Node.js version', default: '20' },
            database: { type: 'string', enum: ['postgres', 'mysql', 'mongodb'], description: 'Database for tests' },
            docker: { type: 'boolean', description: 'Include Docker build step' },
          },
        },
      },
      {
        name: 'nestjs_generate_dockerfile',
        description: 'Generate optimized Dockerfile for NestJS',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Application name' },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_kubernetes',
        description: 'Generate Kubernetes deployment configurations',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Application name' },
            replicas: { type: 'number', description: 'Number of replicas', default: 3 },
            port: { type: 'number', description: 'Application port', default: 3000 },
          },
          required: ['name'],
        },
      },
      {
        name: 'nestjs_generate_nginx',
        description: 'Generate Nginx configuration',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Application name' },
            domain: { type: 'string', description: 'Domain name' },
            ssl: { type: 'boolean', description: 'Include SSL configuration' },
          },
          required: ['name', 'domain'],
        },
      },

      // Error solutions
      {
        name: 'nestjs_common_errors',
        description: 'Get solutions for common NestJS errors',
        inputSchema: {
          type: 'object',
          properties: {
            error: { type: 'string', description: 'Error message or type' },
          },
        },
      },

      // Advanced techniques
      {
        name: 'nestjs_explain_advanced',
        description: 'Explain advanced NestJS techniques (CQRS, Events, Streaming, etc.)',
        inputSchema: {
          type: 'object',
          properties: {
            topic: { type: 'string', description: 'Topic to explain (cqrs, events, fileUpload, streaming, healthChecks, taskScheduling, rateLimiting, versioning, serialization)' },
          },
          required: ['topic'],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  const toolArgs = args as Record<string, unknown>;

  try {
    switch (name) {
      // Generation tools
      case 'nestjs_generate_controller': {
        const result = generateController(toolArgs.name as string, {
          crud: toolArgs.crud as boolean,
          prefix: toolArgs.prefix as string,
        });
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_service': {
        const result = generateService(toolArgs.name as string, {
          crud: toolArgs.crud as boolean,
          withRepository: toolArgs.withRepository as boolean,
        });
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_module': {
        const result = generateModule(toolArgs.name as string, {
          withController: toolArgs.withController as boolean,
          withService: toolArgs.withService as boolean,
        });
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_resource': {
        const result = generateResource(toolArgs.name as string);
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_dto': {
        const result = generateDto(
          toolArgs.name as string,
          toolArgs.type as 'create' | 'update',
          toolArgs.fields as any[]
        );
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_entity': {
        const result = generateEntity(toolArgs.name as string, toolArgs.fields as any[]);
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_guard': {
        const result = generateGuard(toolArgs.name as string, (toolArgs.type as any) || 'custom');
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_interceptor': {
        const result = generateInterceptor(toolArgs.name as string, (toolArgs.type as any) || 'custom');
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_pipe': {
        const result = generatePipe(toolArgs.name as string, (toolArgs.type as any) || 'custom');
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_filter': {
        const result = generateFilter(toolArgs.name as string, toolArgs.exceptionType as string);
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      case 'nestjs_generate_middleware': {
        const result = generateMiddleware(toolArgs.name as string);
        return { content: [{ type: 'text', text: formatGenerateResult(result) }] };
      }

      // Explanation tools
      case 'nestjs_explain_concept': {
        const concept = toolArgs.concept as string;
        const result = explainConcept(concept);
        if (!result) {
          return { content: [{ type: 'text', text: `Concept "${concept}" not found. Available concepts: ${listConcepts().join(', ')}` }] };
        }
        return { content: [{ type: 'text', text: formatExplanation(result) }] };
      }

      case 'nestjs_explain_decorator': {
        const decorator = toolArgs.decorator as string;
        const result = explainDecorator(decorator);
        if (!result) {
          return { content: [{ type: 'text', text: `Decorator "${decorator}" not found.` }] };
        }
        return { content: [{ type: 'text', text: formatExplanation(result) }] };
      }

      case 'nestjs_explain_cli': {
        const command = toolArgs.command as string;
        const result = explainCliCommand(command);
        if (!result) {
          const commands = listCliCommands();
          return { content: [{ type: 'text', text: `Command "${command}" not found. Available: ${commands.map(c => c.command).join(', ')}` }] };
        }
        return { content: [{ type: 'text', text: formatExplanation(result) }] };
      }

      case 'nestjs_list_schematics': {
        const schems = listSchematics();
        const text = '# NestJS Schematics\n\n' + schems.map(s => `- **${s.name}** (${s.alias}): ${s.description}`).join('\n');
        return { content: [{ type: 'text', text }] };
      }

      case 'nestjs_list_decorators': {
        const decs = listDecorators();
        const grouped: Record<string, typeof decs> = {};
        decs.forEach(d => {
          if (!grouped[d.type]) grouped[d.type] = [];
          grouped[d.type].push(d);
        });

        let text = '# NestJS Decorators\n\n';
        Object.entries(grouped).forEach(([type, list]) => {
          text += `## ${type.charAt(0).toUpperCase() + type.slice(1)} Decorators\n\n`;
          list.forEach(d => {
            text += `- **${d.name}**: ${d.description}\n`;
          });
          text += '\n';
        });
        return { content: [{ type: 'text', text }] };
      }

      case 'nestjs_best_practices': {
        const result = getBestPractices(toolArgs.category as any);
        return { content: [{ type: 'text', text: formatExplanation(result) }] };
      }

      case 'nestjs_recommended_packages': {
        const packages = getRecommendedPackages(toolArgs.category as string);
        const text = '# Recommended Packages\n\n' + packages.map(p => `- **${p.name}**: ${p.description}`).join('\n');
        return { content: [{ type: 'text', text }] };
      }

      case 'nestjs_search_docs': {
        const query = toolArgs.query as string;
        const results = searchDocs(query);
        if (results.length === 0) {
          return { content: [{ type: 'text', text: `No results found for "${query}"` }] };
        }
        const text = `# Search Results for "${query}"\n\n` +
          results.map(r => `## ${r.title}\n\n${r.description}\n`).join('\n');
        return { content: [{ type: 'text', text }] };
      }

      case 'nestjs_request_lifecycle': {
        const result = explainRequestLifecycle();
        return { content: [{ type: 'text', text: formatExplanation(result) }] };
      }

      case 'nestjs_dependency_injection': {
        const result = explainDependencyInjection();
        return { content: [{ type: 'text', text: formatExplanation(result) }] };
      }

      // Analysis tools
      case 'nestjs_analyze_code': {
        const result = analyzeCode(toolArgs.code as string);
        return { content: [{ type: 'text', text: formatAnalysis(result) }] };
      }

      case 'nestjs_suggest_improvements': {
        const suggestions = suggestImprovements(toolArgs.code as string);
        const text = '# Suggested Improvements\n\n' + suggestions.map((s, i) => `${i + 1}. ${s}`).join('\n');
        return { content: [{ type: 'text', text }] };
      }

      case 'nestjs_validate_structure': {
        const result = validateStructure(toolArgs.files as string[]);
        return { content: [{ type: 'text', text: formatAnalysis(result) }] };
      }

      // Scaffold tools
      case 'nestjs_scaffold_project': {
        const result = scaffoldProject(toolArgs.name as string, {
          database: toolArgs.database as any,
          auth: toolArgs.auth as boolean,
          swagger: toolArgs.swagger as boolean,
          docker: toolArgs.docker as boolean,
          testing: toolArgs.testing as boolean,
          websockets: toolArgs.websockets as boolean,
        });
        return { content: [{ type: 'text', text: formatScaffoldResult(result) }] };
      }

      // Testing tools
      case 'nestjs_generate_service_test': {
        const result = generateServiceTest(toolArgs.name as string, toolArgs.methods as string[]);
        return { content: [{ type: 'text', text: formatTestResult(result) }] };
      }

      case 'nestjs_generate_controller_test': {
        const result = generateControllerTest(toolArgs.name as string);
        return { content: [{ type: 'text', text: formatTestResult(result) }] };
      }

      case 'nestjs_generate_e2e_test': {
        const result = generateE2ETest(toolArgs.name as string);
        return { content: [{ type: 'text', text: formatTestResult(result) }] };
      }

      case 'nestjs_generate_test_factory': {
        const result = generateTestFactory(toolArgs.name as string, toolArgs.fields as any[] || []);
        return { content: [{ type: 'text', text: formatTestResult(result) }] };
      }

      // Security tools
      case 'nestjs_security_audit': {
        const issues = auditCode(toolArgs.code as string, toolArgs.filename as string);
        const { score, grade } = calculateSecurityScore(issues);
        return { content: [{ type: 'text', text: formatSecurityAudit(issues, score, grade) }] };
      }

      case 'nestjs_security_checklist': {
        const checklist = getSecurityChecklist();
        return { content: [{ type: 'text', text: formatSecurityChecklist(checklist) }] };
      }

      case 'nestjs_generate_secure_main': {
        const code = generateSecureMainTs();
        return { content: [{ type: 'text', text: `# Secure main.ts\n\n\`\`\`typescript\n${code}\n\`\`\`` }] };
      }

      // Deployment tools
      case 'nestjs_generate_github_actions': {
        const result = generateGitHubActions({
          nodeVersion: toolArgs.nodeVersion as string,
          database: toolArgs.database as any,
          docker: toolArgs.docker as boolean,
        });
        return { content: [{ type: 'text', text: formatDeploymentConfig(result) }] };
      }

      case 'nestjs_generate_dockerfile': {
        const result = scaffoldProject(toolArgs.name as string, { docker: true });
        const dockerfile = result.files.find(f => f.path === 'Dockerfile');
        return { content: [{ type: 'text', text: `# Dockerfile\n\n\`\`\`dockerfile\n${dockerfile?.content || ''}\n\`\`\`` }] };
      }

      case 'nestjs_generate_kubernetes': {
        const configs = generateKubernetesConfig(toolArgs.name as string, {
          replicas: toolArgs.replicas as number,
          port: toolArgs.port as number,
        });
        const text = configs.map(c => formatDeploymentConfig(c)).join('\n\n---\n\n');
        return { content: [{ type: 'text', text }] };
      }

      case 'nestjs_generate_nginx': {
        const result = generateNginxConfig(toolArgs.name as string, {
          domain: toolArgs.domain as string,
          ssl: toolArgs.ssl as boolean,
        });
        return { content: [{ type: 'text', text: formatDeploymentConfig(result) }] };
      }

      // Error solutions
      case 'nestjs_common_errors': {
        const errorKey = toolArgs.error as string;
        return { content: [{ type: 'text', text: formatCommonErrors(errorKey) }] };
      }

      // Advanced techniques
      case 'nestjs_explain_advanced': {
        const topic = toolArgs.topic as string;
        const technique = advancedTechniques[topic.toLowerCase()];
        if (!technique) {
          const available = Object.keys(advancedTechniques).join(', ');
          return { content: [{ type: 'text', text: `Topic "${topic}" not found. Available: ${available}` }] };
        }
        return { content: [{ type: 'text', text: formatExplanation(technique) }] };
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
  } catch (error: any) {
    throw new McpError(ErrorCode.InternalError, error.message);
  }
});

// ============================================
// RESOURCES
// ============================================

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: getDocumentationResources(),
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  const content = getResourceContent(uri);
  if (!content) {
    throw new McpError(ErrorCode.InvalidRequest, `Resource not found: ${uri}`);
  }

  return {
    contents: [content],
  };
});

// ============================================
// PROMPTS
// ============================================

server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return {
    prompts: prompts.map((p) => ({
      name: p.name,
      description: p.description,
      arguments: p.arguments,
    })),
  };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  const prompt = getPrompt(name);
  if (!prompt) {
    throw new McpError(ErrorCode.InvalidRequest, `Prompt not found: ${name}`);
  }

  const rendered = renderPrompt(name, args || {});

  return {
    description: prompt.description,
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text: rendered || prompt.template,
        },
      },
    ],
  };
});

// ============================================
// HELPERS
// ============================================

function formatGenerateResult(result: {
  code: string;
  filename: string;
  description: string;
  additionalFiles?: { filename: string; code: string }[];
}): string {
  let output = `# ${result.description}\n\n`;
  output += `## ${result.filename}\n\n`;
  output += '```typescript\n' + result.code + '\n```\n\n';

  if (result.additionalFiles) {
    output += '## Additional Files\n\n';
    result.additionalFiles.forEach((file) => {
      output += `### ${file.filename}\n\n`;
      output += '```typescript\n' + file.code + '\n```\n\n';
    });
  }

  return output;
}

function formatExplanation(result: {
  title: string;
  description: string;
  content: string;
  examples?: string[];
  relatedTopics?: string[];
}): string {
  let output = `# ${result.title}\n\n`;
  output += `> ${result.description}\n\n`;
  output += result.content + '\n\n';

  if (result.examples && result.examples.length > 0) {
    output += '## Examples\n\n';
    result.examples.forEach((ex, i) => {
      output += `### Example ${i + 1}\n\n`;
      output += '```typescript\n' + ex + '\n```\n\n';
    });
  }

  if (result.relatedTopics && result.relatedTopics.length > 0) {
    output += '## Related Topics\n\n';
    output += result.relatedTopics.map((t) => `- ${t}`).join('\n') + '\n';
  }

  return output;
}

function formatAnalysis(result: {
  type: string;
  name: string;
  issues: { severity: string; message: string; suggestion?: string }[];
  suggestions: string[];
  metrics?: Record<string, number>;
}): string {
  let output = `# Analysis: ${result.name} (${result.type})\n\n`;

  if (result.issues.length > 0) {
    output += '## Issues\n\n';
    result.issues.forEach((issue) => {
      const icon = issue.severity === 'error' ? '❌' : issue.severity === 'warning' ? '⚠️' : 'ℹ️';
      output += `${icon} **${issue.severity.toUpperCase()}**: ${issue.message}\n`;
      if (issue.suggestion) {
        output += `   → ${issue.suggestion}\n`;
      }
    });
    output += '\n';
  }

  if (result.suggestions.length > 0) {
    output += '## Suggestions\n\n';
    result.suggestions.forEach((s, i) => {
      output += `${i + 1}. ${s}\n`;
    });
    output += '\n';
  }

  if (result.metrics) {
    output += '## Metrics\n\n';
    Object.entries(result.metrics).forEach(([key, value]) => {
      output += `- ${key}: ${value}\n`;
    });
  }

  return output;
}

function formatScaffoldResult(result: {
  files: { path: string; content: string }[];
  instructions: string[];
  dependencies: string[];
  devDependencies: string[];
}): string {
  let output = '# Project Scaffold\n\n';

  output += '## Files Generated\n\n';
  result.files.forEach((file) => {
    const ext = file.path.split('.').pop() || 'txt';
    const lang = ext === 'ts' ? 'typescript' : ext === 'json' ? 'json' : ext === 'yml' ? 'yaml' : ext;
    output += `### ${file.path}\n\n`;
    output += `\`\`\`${lang}\n${file.content}\n\`\`\`\n\n`;
  });

  if (result.instructions.length > 0) {
    output += '## Setup Instructions\n\n';
    result.instructions.forEach((inst, i) => {
      output += `${i + 1}. ${inst}\n`;
    });
    output += '\n';
  }

  output += '## Dependencies\n\n';
  output += '```bash\nnpm install ' + result.dependencies.join(' ') + '\n```\n\n';

  output += '## Dev Dependencies\n\n';
  output += '```bash\nnpm install -D ' + result.devDependencies.join(' ') + '\n```\n';

  return output;
}

function formatTestResult(result: {
  filename: string;
  code: string;
  description: string;
}): string {
  let output = `# ${result.description}\n\n`;
  output += `## ${result.filename}\n\n`;
  output += '```typescript\n' + result.code + '\n```\n';
  return output;
}

function formatSecurityAudit(issues: any[], score: number, grade: string): string {
  let output = `# Security Audit Report\n\n`;
  output += `## Score: ${score}/100 (Grade: ${grade})\n\n`;

  if (issues.length === 0) {
    output += '✅ No security issues found!\n';
    return output;
  }

  const grouped: Record<string, any[]> = {};
  issues.forEach((issue) => {
    if (!grouped[issue.severity]) grouped[issue.severity] = [];
    grouped[issue.severity].push(issue);
  });

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const icons: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    info: 'ℹ️',
  };

  severityOrder.forEach((severity) => {
    if (grouped[severity]) {
      output += `## ${icons[severity]} ${severity.toUpperCase()} (${grouped[severity].length})\n\n`;
      grouped[severity].forEach((issue) => {
        output += `### ${issue.title}\n`;
        output += `- **Category**: ${issue.category}\n`;
        output += `- **Description**: ${issue.description}\n`;
        if (issue.location) output += `- **Location**: ${issue.location}\n`;
        output += `- **Recommendation**: ${issue.recommendation}\n`;
        if (issue.cweId) output += `- **CWE**: ${issue.cweId}\n`;
        output += '\n';
      });
    }
  });

  return output;
}

function formatSecurityChecklist(checklist: any[]): string {
  let output = '# NestJS Security Checklist\n\n';

  checklist.forEach((category) => {
    output += `## ${category.category}\n\n`;
    category.items.forEach((item: any) => {
      const priority = item.priority === 'required' ? '🔴' : item.priority === 'recommended' ? '🟡' : '🔵';
      output += `- ${priority} **${item.item}** (${item.priority})\n`;
      output += `  ${item.description}\n\n`;
    });
  });

  return output;
}

function formatDeploymentConfig(config: {
  filename: string;
  content: string;
  description: string;
}): string {
  const ext = config.filename.split('.').pop() || 'txt';
  const lang = ext === 'yml' || ext === 'yaml' ? 'yaml' : ext === 'json' ? 'json' : ext === 'conf' ? 'nginx' : ext;

  let output = `# ${config.description}\n\n`;
  output += `## ${config.filename}\n\n`;
  output += `\`\`\`${lang}\n${config.content}\n\`\`\`\n`;
  return output;
}

function formatCommonErrors(errorKey?: string): string {
  if (!errorKey) {
    let output = '# Common NestJS Errors\n\n';
    Object.entries(commonErrors).forEach(([key, error]) => {
      output += `## ${error.error}\n\n`;
      output += `**Causes:**\n`;
      error.causes.forEach((c) => output += `- ${c}\n`);
      output += `\n**Solutions:**\n`;
      error.solutions.forEach((s) => output += `- ${s}\n`);
      if (error.example) {
        output += `\n**Example:**\n\`\`\`typescript\n${error.example}\n\`\`\`\n`;
      }
      output += '\n---\n\n';
    });
    return output;
  }

  const searchKey = errorKey.toLowerCase();
  const matched = Object.entries(commonErrors).find(([key, error]) =>
    key.toLowerCase().includes(searchKey) ||
    error.error.toLowerCase().includes(searchKey)
  );

  if (!matched) {
    return `No solution found for "${errorKey}". Available errors:\n\n` +
      Object.keys(commonErrors).map((k) => `- ${k}`).join('\n');
  }

  const [, error] = matched;
  let output = `# ${error.error}\n\n`;
  output += `## Possible Causes\n\n`;
  error.causes.forEach((c) => output += `- ${c}\n`);
  output += `\n## Solutions\n\n`;
  error.solutions.forEach((s) => output += `- ${s}\n`);
  if (error.example) {
    output += `\n## Example Fix\n\n\`\`\`typescript\n${error.example}\n\`\`\`\n`;
  }
  return output;
}

// ============================================
// SERVER START
// ============================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('NestJS MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});
