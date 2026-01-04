<div align="center">

# NestJS MCP Server

**A comprehensive Model Context Protocol (MCP) server for NestJS development**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![NestJS](https://img.shields.io/badge/NestJS-10.x-e0234e.svg)](https://nestjs.com/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*Supercharge your NestJS development with AI-powered assistance*

[Features](#features) • [Installation](#installation) • [Configuration](#configuration) • [Tools](#available-tools) • [Usage](#usage-examples) • [Contributing](#contributing)

</div>

---

## Overview

NestJS MCP Server is a powerful Model Context Protocol server that provides **40+ specialized tools** for NestJS development. It integrates seamlessly with AI assistants like **Claude Desktop**, **Cursor**, **Claude Code CLI**, and any MCP-compatible client.

### Why NestJS MCP?

- **Accelerate Development**: Generate boilerplate code, controllers, services, and complete CRUD resources in seconds
- **Best Practices Built-in**: All generated code follows NestJS best practices and conventions
- **Security First**: Built-in security audit tools to identify vulnerabilities in your code
- **Complete Ecosystem**: From scaffolding to deployment, covers the entire development lifecycle
- **AI-Powered Learning**: Instant explanations of NestJS concepts, decorators, and patterns

---

## Features

### Code Generation
Generate production-ready NestJS code with proper decorators, types, and best practices.

### Project Scaffolding
Create complete NestJS projects with your preferred database, authentication, and tooling pre-configured.

### Testing Tools
Generate unit tests, E2E tests, test factories, and mock repositories automatically.

### Security Auditing
Scan your code for common vulnerabilities (SQL injection, XSS, hardcoded secrets, etc.) with severity ratings.

### Deployment Automation
Generate Docker, Kubernetes, CI/CD pipelines, Nginx configs, and more.

### Documentation & Learning
Access NestJS documentation, concepts, and best practices directly through your AI assistant.

---

## Installation

### Prerequisites

- **Node.js** 18.x or higher
- **npm** 9.x or higher

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/nestjs-mcp.git
cd nestjs-mcp

# Install dependencies
npm install

# Build the project
npm run build

# Verify installation
npm start
```

### Build Scripts

| Command | Description |
|---------|-------------|
| `npm run build` | Compile TypeScript to JavaScript |
| `npm run dev` | Watch mode for development |
| `npm start` | Run the MCP server |

---

## Configuration

### Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

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

### Cursor IDE

Add to your Cursor MCP settings (`.cursor/mcp.json`):

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

Add to your Claude Code settings:

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

> **Note**: Replace `/absolute/path/to/nestjs-mcp` with the actual path to your installation.

---

## Available Tools

### Code Generation Tools

| Tool | Description |
|------|-------------|
| `nestjs_generate_controller` | Generate controllers with optional CRUD operations |
| `nestjs_generate_service` | Generate services with repository integration |
| `nestjs_generate_module` | Generate modules with providers and imports |
| `nestjs_generate_resource` | Generate complete CRUD resources (module, controller, service, entity, DTOs) |
| `nestjs_generate_dto` | Generate DTOs with class-validator decorators |
| `nestjs_generate_entity` | Generate TypeORM/Mongoose entities |
| `nestjs_generate_guard` | Generate auth, roles, or custom guards |
| `nestjs_generate_interceptor` | Generate logging, transform, cache, or timeout interceptors |
| `nestjs_generate_pipe` | Generate validation or transform pipes |
| `nestjs_generate_filter` | Generate exception filters |
| `nestjs_generate_middleware` | Generate custom middleware |

### Project Scaffolding Tools

| Tool | Description |
|------|-------------|
| `nestjs_scaffold_project` | Generate a complete NestJS project with customizable options |

**Scaffolding Options:**
- **Database**: PostgreSQL, MySQL, MongoDB, SQLite
- **Authentication**: JWT-based auth with Passport
- **Documentation**: Swagger/OpenAPI integration
- **Containerization**: Docker & Docker Compose
- **Testing**: Jest configuration with coverage
- **WebSockets**: Socket.io integration

### Testing Tools

| Tool | Description |
|------|-------------|
| `nestjs_generate_unit_test` | Generate unit tests for services |
| `nestjs_generate_controller_test` | Generate controller unit tests |
| `nestjs_generate_e2e_test` | Generate end-to-end tests |
| `nestjs_generate_test_factory` | Generate test data factories |
| `nestjs_generate_mock_repository` | Generate mock repository for testing |
| `nestjs_generate_test_helpers` | Generate common test utilities |

### Security Tools

| Tool | Description |
|------|-------------|
| `nestjs_security_audit` | Comprehensive security audit of your codebase |
| `nestjs_security_checklist` | Get security best practices checklist |
| `nestjs_generate_secure_main` | Generate security-hardened main.ts |

**Security Checks Include:**
- SQL Injection vulnerabilities
- Cross-Site Scripting (XSS)
- Hardcoded secrets and credentials
- Insecure cryptographic practices
- Path traversal vulnerabilities
- Command injection risks
- Sensitive data exposure
- Missing security headers

### Deployment Tools

| Tool | Description |
|------|-------------|
| `nestjs_generate_dockerfile` | Generate optimized multi-stage Dockerfile |
| `nestjs_generate_docker_compose` | Generate Docker Compose configuration |
| `nestjs_generate_github_actions` | Generate GitHub Actions CI/CD pipeline |
| `nestjs_generate_gitlab_ci` | Generate GitLab CI/CD pipeline |
| `nestjs_generate_kubernetes` | Generate Kubernetes deployment manifests |
| `nestjs_generate_pm2_config` | Generate PM2 ecosystem configuration |
| `nestjs_generate_nginx_config` | Generate Nginx reverse proxy configuration |
| `nestjs_generate_systemd_service` | Generate systemd service file |
| `nestjs_generate_env_files` | Generate environment configuration files |

### Documentation & Learning Tools

| Tool | Description |
|------|-------------|
| `nestjs_explain_concept` | Detailed explanation of NestJS concepts |
| `nestjs_explain_decorator` | Explain specific decorators with examples |
| `nestjs_explain_cli` | Explain NestJS CLI commands |
| `nestjs_list_schematics` | List all available NestJS schematics |
| `nestjs_list_decorators` | List decorators by category |
| `nestjs_best_practices` | Get best practices by category |
| `nestjs_recommended_packages` | Get recommended packages by use case |
| `nestjs_search_docs` | Search through NestJS documentation |
| `nestjs_request_lifecycle` | Understand the request lifecycle |
| `nestjs_dependency_injection` | Learn about dependency injection |
| `nestjs_get_common_errors` | Get solutions for common errors |

### Code Analysis Tools

| Tool | Description |
|------|-------------|
| `nestjs_analyze_code` | Analyze code for issues and anti-patterns |
| `nestjs_suggest_improvements` | Get improvement suggestions |
| `nestjs_validate_structure` | Validate project structure |

---

## Available Resources

Access NestJS documentation directly through MCP resources:

| Resource URI | Description |
|--------------|-------------|
| `nestjs://docs/concepts/{topic}` | Core concepts (modules, controllers, providers, etc.) |
| `nestjs://docs/techniques/{topic}` | Techniques (database, auth, validation, caching, etc.) |
| `nestjs://docs/advanced/{topic}` | Advanced topics (CQRS, events, microservices, etc.) |
| `nestjs://docs/cli/commands` | CLI commands reference |
| `nestjs://docs/cli/schematics` | Schematics reference |
| `nestjs://docs/decorators` | Complete decorators reference |
| `nestjs://docs/best-practices` | Best practices guide |
| `nestjs://docs/packages` | Recommended packages |
| `nestjs://docs/errors/{error}` | Common errors and solutions |

---

## Usage Examples

### Generate a Complete CRUD Resource

```
"Generate a complete CRUD resource for 'products' with TypeORM entity"
```

This creates:
- `products.module.ts`
- `products.controller.ts`
- `products.service.ts`
- `product.entity.ts`
- `create-product.dto.ts`
- `update-product.dto.ts`

### Scaffold a New Project

```
"Scaffold a new NestJS project called 'my-api' with PostgreSQL, JWT auth, Swagger, and Docker"
```

This generates a complete project structure with:
- Database configuration
- Authentication module
- Swagger setup
- Docker & Docker Compose files
- Environment configuration
- Testing setup

### Security Audit

```
"Run a security audit on my NestJS application"
```

Returns:
- List of vulnerabilities with severity ratings
- CWE references
- Remediation suggestions
- Overall security score (A-F grade)

### Generate CI/CD Pipeline

```
"Generate a GitHub Actions workflow for my NestJS project"
```

Creates a complete CI/CD pipeline with:
- Linting and type checking
- Unit and E2E tests
- Docker build and push
- Deployment stages

### Generate Kubernetes Deployment

```
"Generate Kubernetes manifests for deploying my NestJS app"
```

Generates:
- Deployment with health checks
- Service (ClusterIP/LoadBalancer)
- ConfigMap
- Secret template
- Horizontal Pod Autoscaler
- Ingress configuration

### Get Error Solutions

```
"How do I fix the circular dependency error in NestJS?"
```

Returns:
- Common causes
- Step-by-step solutions
- Code examples

---

## Project Structure

```
nestjs-mcp/
├── src/
│   ├── index.ts                    # Main MCP server entry point
│   ├── data/
│   │   ├── nestjs-docs.ts          # Core NestJS documentation
│   │   └── advanced-techniques.ts  # Advanced topics & error solutions
│   ├── tools/
│   │   ├── index.ts                # Tools barrel export
│   │   ├── generate.ts             # Code generation tools
│   │   ├── explain.ts              # Documentation tools
│   │   ├── analyze.ts              # Code analysis tools
│   │   ├── scaffold.ts             # Project scaffolding
│   │   ├── testing.ts              # Test generation tools
│   │   ├── security.ts             # Security audit tools
│   │   └── deployment.ts           # Deployment config generators
│   ├── resources/
│   │   ├── index.ts
│   │   └── documentation.ts        # MCP resources
│   └── prompts/
│       ├── index.ts
│       └── templates.ts            # Prompt templates
├── dist/                           # Compiled JavaScript
├── package.json
├── tsconfig.json
└── README.md
```

---

## Advanced Topics Covered

The MCP server includes comprehensive documentation and code generation for:

| Topic | Description |
|-------|-------------|
| **CQRS** | Command Query Responsibility Segregation pattern |
| **Event-Driven** | Event emitters and event sourcing |
| **File Upload** | Multer integration and streaming uploads |
| **Streaming** | SSE and streaming responses |
| **Health Checks** | Terminus health indicators |
| **Task Scheduling** | Cron jobs and intervals |
| **Compression** | Gzip/Brotli response compression |
| **Rate Limiting** | Throttling and rate limiting |
| **API Versioning** | URI, header, and media type versioning |
| **Serialization** | Class-transformer and interceptors |

---

## Common Errors Database

Built-in solutions for common NestJS errors:

- **Circular Dependency** - Detection and resolution strategies
- **Cannot Resolve Dependency** - Missing provider troubleshooting
- **Invalid Module** - Module configuration issues
- **Unknown Element** - Template and decorator problems
- **Timeout Errors** - Async operation handling
- **Validation Failures** - DTO and pipe configuration
- **TypeORM Issues** - Database connection and query problems
- **Authentication Errors** - JWT and Passport configuration

---

## Contributing

Contributions are welcome! Here's how you can help:

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/nestjs-mcp.git
cd nestjs-mcp

# Install dependencies
npm install

# Start development mode
npm run dev
```

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas for Contribution

- Additional code generators
- More security checks
- Extended documentation coverage
- Bug fixes and improvements
- Additional deployment targets

---

## Troubleshooting

### Common Issues

**MCP Server Not Starting**
```bash
# Ensure the project is built
npm run build

# Check for TypeScript errors
npx tsc --noEmit
```

**Claude Desktop Not Detecting Server**
- Verify the path in `claude_desktop_config.json` is absolute
- Restart Claude Desktop after configuration changes
- Check Claude Desktop logs for connection errors

**Permission Errors on Linux/macOS**
```bash
chmod +x dist/index.js
```

---

## Roadmap

- [ ] GraphQL code generation
- [ ] Microservices scaffolding
- [ ] gRPC integration templates
- [ ] Database migration generators
- [ ] OpenAPI spec to code generation
- [ ] Custom template support
- [ ] Plugin architecture

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [NestJS](https://nestjs.com/) - The progressive Node.js framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification
- [Anthropic](https://anthropic.com/) - Claude AI assistant

---

<div align="center">

**Built with love for the NestJS community**

[Report Bug](https://github.com/yourusername/nestjs-mcp/issues) • [Request Feature](https://github.com/yourusername/nestjs-mcp/issues)

</div>
