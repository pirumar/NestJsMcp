# NestJS MCP Server

A Model Context Protocol (MCP) server that provides comprehensive NestJS development assistance for AI assistants like Claude, Cursor, and others.

## Features

### Tools

#### Code Generation
- `nestjs_generate_controller` - Generate controllers with optional CRUD operations
- `nestjs_generate_service` - Generate services with optional repository integration
- `nestjs_generate_module` - Generate modules with controllers and services
- `nestjs_generate_resource` - Generate complete CRUD resources (module, controller, service, entity, DTOs)
- `nestjs_generate_dto` - Generate DTOs with validation decorators
- `nestjs_generate_entity` - Generate TypeORM entities
- `nestjs_generate_guard` - Generate guards (auth, roles, custom)
- `nestjs_generate_interceptor` - Generate interceptors (logging, transform, cache, timeout)
- `nestjs_generate_pipe` - Generate pipes (validation, transform)
- `nestjs_generate_filter` - Generate exception filters
- `nestjs_generate_middleware` - Generate middleware

#### Documentation & Learning
- `nestjs_explain_concept` - Explain NestJS concepts
- `nestjs_explain_decorator` - Explain decorators
- `nestjs_explain_cli` - Explain CLI commands
- `nestjs_list_schematics` - List available schematics
- `nestjs_list_decorators` - List all decorators
- `nestjs_best_practices` - Get best practices
- `nestjs_recommended_packages` - Get recommended packages
- `nestjs_search_docs` - Search documentation
- `nestjs_request_lifecycle` - Explain request lifecycle
- `nestjs_dependency_injection` - Explain DI system

#### Code Analysis
- `nestjs_analyze_code` - Analyze code for issues
- `nestjs_suggest_improvements` - Get improvement suggestions
- `nestjs_validate_structure` - Validate project structure

### Resources

Access NestJS documentation directly:
- `nestjs://docs/concepts/*` - Core concepts (modules, controllers, providers, etc.)
- `nestjs://docs/techniques/*` - Techniques (database, auth, validation, etc.)
- `nestjs://docs/cli/commands` - CLI commands reference
- `nestjs://docs/cli/schematics` - Schematics reference
- `nestjs://docs/decorators` - Decorators reference
- `nestjs://docs/best-practices` - Best practices guide
- `nestjs://docs/packages` - Recommended packages

### Prompts

Pre-built prompts for common tasks:
- `create-module` - Generate a complete module
- `create-auth` - Generate authentication module
- `create-crud-api` - Generate CRUD API
- `add-validation` - Add validation to code
- `add-swagger` - Add Swagger documentation
- `create-guard` - Create custom guard
- `create-interceptor` - Create custom interceptor
- `create-pipe` - Create custom pipe
- `create-filter` - Create exception filter
- `create-middleware` - Create middleware
- `explain-concept` - Explain a concept
- `review-code` - Review code
- `debug-issue` - Debug an issue
- `migrate-express` - Migrate from Express
- `setup-testing` - Set up testing
- `setup-database` - Set up database

## Installation

```bash
# Clone or download
git clone <repository-url>
cd nestjs-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nestjs": {
      "command": "node",
      "args": ["/absolute/path/to/nestjs-mcp/dist/index.js"]
    }
  }
}
```

### Cursor

Add to your Cursor MCP settings:

```json
{
  "mcpServers": {
    "nestjs": {
      "command": "node",
      "args": ["/absolute/path/to/nestjs-mcp/dist/index.js"]
    }
  }
}
```

### Claude Code CLI

Add to your Claude Code configuration:

```json
{
  "mcpServers": {
    "nestjs": {
      "command": "node",
      "args": ["/absolute/path/to/nestjs-mcp/dist/index.js"]
    }
  }
}
```

## Usage Examples

### Generate a CRUD Resource

Ask the AI:
> "Generate a complete CRUD resource for 'products' using nestjs_generate_resource"

### Explain a Concept

Ask the AI:
> "Explain how guards work in NestJS using nestjs_explain_concept"

### Analyze Code

Ask the AI:
> "Analyze this controller code for best practices using nestjs_analyze_code"

### Get Best Practices

Ask the AI:
> "What are the security best practices for NestJS using nestjs_best_practices with category 'security'"

## Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## Project Structure

```
nestjs-mcp/
├── src/
│   ├── index.ts              # Main MCP server entry point
│   ├── data/
│   │   └── nestjs-docs.ts    # NestJS documentation data
│   ├── tools/
│   │   ├── index.ts
│   │   ├── generate.ts       # Code generation tools
│   │   ├── explain.ts        # Documentation/explanation tools
│   │   └── analyze.ts        # Code analysis tools
│   ├── resources/
│   │   ├── index.ts
│   │   └── documentation.ts  # Documentation resources
│   └── prompts/
│       ├── index.ts
│       └── templates.ts      # Prompt templates
├── package.json
├── tsconfig.json
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT
