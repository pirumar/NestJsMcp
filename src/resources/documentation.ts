// NestJS Documentation Resources
import {
  coreConcepts,
  techniques,
  cliCommands,
  schematics,
  decorators,
  bestPractices,
  commonPackages,
} from '../data/nestjs-docs.js';

export interface Resource {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
}

export interface ResourceContent {
  uri: string;
  mimeType: string;
  text: string;
}

// Get all available documentation resources
export function getDocumentationResources(): Resource[] {
  const resources: Resource[] = [];

  // Core concepts
  Object.keys(coreConcepts).forEach((key) => {
    resources.push({
      uri: `nestjs://docs/concepts/${key}`,
      name: coreConcepts[key].title,
      description: coreConcepts[key].description,
      mimeType: 'text/markdown',
    });
  });

  // Techniques
  Object.keys(techniques).forEach((key) => {
    resources.push({
      uri: `nestjs://docs/techniques/${key}`,
      name: techniques[key].title,
      description: techniques[key].description,
      mimeType: 'text/markdown',
    });
  });

  // CLI commands
  resources.push({
    uri: 'nestjs://docs/cli/commands',
    name: 'CLI Commands',
    description: 'All NestJS CLI commands reference',
    mimeType: 'text/markdown',
  });

  // Schematics
  resources.push({
    uri: 'nestjs://docs/cli/schematics',
    name: 'Schematics',
    description: 'All available NestJS schematics',
    mimeType: 'text/markdown',
  });

  // Decorators
  resources.push({
    uri: 'nestjs://docs/decorators',
    name: 'Decorators Reference',
    description: 'All NestJS decorators',
    mimeType: 'text/markdown',
  });

  // Best practices
  resources.push({
    uri: 'nestjs://docs/best-practices',
    name: 'Best Practices',
    description: 'NestJS best practices guide',
    mimeType: 'text/markdown',
  });

  // Common packages
  resources.push({
    uri: 'nestjs://docs/packages',
    name: 'Common Packages',
    description: 'Recommended NestJS packages',
    mimeType: 'text/markdown',
  });

  return resources;
}

// Get content for a specific resource
export function getResourceContent(uri: string): ResourceContent | null {
  const parts = uri.replace('nestjs://docs/', '').split('/');

  // Core concepts
  if (parts[0] === 'concepts' && parts[1]) {
    const concept = coreConcepts[parts[1]];
    if (concept) {
      return {
        uri,
        mimeType: 'text/markdown',
        text: formatConceptContent(concept),
      };
    }
  }

  // Techniques
  if (parts[0] === 'techniques' && parts[1]) {
    const technique = techniques[parts[1]];
    if (technique) {
      return {
        uri,
        mimeType: 'text/markdown',
        text: formatConceptContent(technique),
      };
    }
  }

  // CLI commands
  if (parts[0] === 'cli' && parts[1] === 'commands') {
    return {
      uri,
      mimeType: 'text/markdown',
      text: formatCliCommands(),
    };
  }

  // Schematics
  if (parts[0] === 'cli' && parts[1] === 'schematics') {
    return {
      uri,
      mimeType: 'text/markdown',
      text: formatSchematics(),
    };
  }

  // Decorators
  if (parts[0] === 'decorators') {
    return {
      uri,
      mimeType: 'text/markdown',
      text: formatDecorators(),
    };
  }

  // Best practices
  if (parts[0] === 'best-practices') {
    return {
      uri,
      mimeType: 'text/markdown',
      text: formatBestPractices(),
    };
  }

  // Common packages
  if (parts[0] === 'packages') {
    return {
      uri,
      mimeType: 'text/markdown',
      text: formatPackages(),
    };
  }

  return null;
}

// Format concept/technique content as markdown
function formatConceptContent(concept: {
  title: string;
  description: string;
  content: string;
  examples?: string[];
  relatedTopics?: string[];
}): string {
  let markdown = `# ${concept.title}\n\n`;
  markdown += `> ${concept.description}\n\n`;
  markdown += `${concept.content}\n\n`;

  if (concept.examples && concept.examples.length > 0) {
    markdown += `## Examples\n\n`;
    concept.examples.forEach((example, index) => {
      markdown += `### Example ${index + 1}\n\n`;
      markdown += '```typescript\n' + example + '\n```\n\n';
    });
  }

  if (concept.relatedTopics && concept.relatedTopics.length > 0) {
    markdown += `## Related Topics\n\n`;
    markdown += concept.relatedTopics.map((t) => `- ${t}`).join('\n');
    markdown += '\n';
  }

  return markdown;
}

// Format CLI commands as markdown
function formatCliCommands(): string {
  let markdown = `# NestJS CLI Commands\n\n`;

  cliCommands.forEach((cmd) => {
    markdown += `## ${cmd.command}\n\n`;
    if (cmd.alias) {
      markdown += `**Alias:** \`${cmd.alias}\`\n\n`;
    }
    markdown += `${cmd.description}\n\n`;

    if (cmd.options && cmd.options.length > 0) {
      markdown += `### Options\n\n`;
      markdown += '| Flag | Description |\n';
      markdown += '|------|-------------|\n';
      cmd.options.forEach((opt) => {
        markdown += `| \`${opt.flag}\` | ${opt.description} |\n`;
      });
      markdown += '\n';
    }

    if (cmd.examples && cmd.examples.length > 0) {
      markdown += `### Examples\n\n`;
      markdown += '```bash\n';
      markdown += cmd.examples.join('\n');
      markdown += '\n```\n\n';
    }
  });

  return markdown;
}

// Format schematics as markdown
function formatSchematics(): string {
  let markdown = `# NestJS Schematics\n\n`;
  markdown += `Use \`nest generate <schematic> <name>\` or \`nest g <alias> <name>\`\n\n`;

  markdown += '| Schematic | Alias | Description |\n';
  markdown += '|-----------|-------|-------------|\n';

  schematics.forEach((s) => {
    markdown += `| ${s.name} | ${s.alias} | ${s.description} |\n`;
  });

  markdown += '\n## Common Options\n\n';
  markdown += '- `--dry-run`: Report changes without writing files\n';
  markdown += '- `--flat`: Generate without creating a subdirectory\n';
  markdown += '- `--no-spec`: Skip test file generation\n';
  markdown += '- `--skip-import`: Skip module import\n';

  return markdown;
}

// Format decorators as markdown
function formatDecorators(): string {
  let markdown = `# NestJS Decorators Reference\n\n`;

  const groupedDecorators: Record<string, typeof decorators> = {
    class: [],
    method: [],
    parameter: [],
    property: [],
  };

  decorators.forEach((d) => {
    groupedDecorators[d.type].push(d);
  });

  Object.entries(groupedDecorators).forEach(([type, decs]) => {
    if (decs.length > 0) {
      markdown += `## ${type.charAt(0).toUpperCase() + type.slice(1)} Decorators\n\n`;
      markdown += '| Decorator | Description | Usage |\n';
      markdown += '|-----------|-------------|-------|\n';
      decs.forEach((d) => {
        markdown += `| \`${d.name}\` | ${d.description} | \`${d.usage}\` |\n`;
      });
      markdown += '\n';
    }
  });

  return markdown;
}

// Format best practices as markdown
function formatBestPractices(): string {
  let markdown = `# NestJS Best Practices\n\n`;

  markdown += `## Project Structure\n\n`;
  markdown += '```\n' + bestPractices.projectStructure + '\n```\n\n';

  markdown += `## Code Guidelines\n\n`;
  bestPractices.codeGuidelines.forEach((g, i) => {
    markdown += `${i + 1}. ${g}\n`;
  });
  markdown += '\n';

  markdown += `## Security Best Practices\n\n`;
  bestPractices.securityPractices.forEach((p, i) => {
    markdown += `${i + 1}. ${p}\n`;
  });

  return markdown;
}

// Format packages as markdown
function formatPackages(): string {
  let markdown = `# Recommended NestJS Packages\n\n`;

  markdown += '| Package | Description |\n';
  markdown += '|---------|-------------|\n';

  commonPackages.forEach((p) => {
    markdown += `| \`${p.name}\` | ${p.description} |\n`;
  });

  markdown += '\n## Installation\n\n';
  markdown += '```bash\n';
  markdown += 'npm install <package-name>\n';
  markdown += '# or\n';
  markdown += 'yarn add <package-name>\n';
  markdown += '# or\n';
  markdown += 'pnpm add <package-name>\n';
  markdown += '```\n';

  return markdown;
}

// Search across all resources
export function searchResources(query: string): Resource[] {
  const results: Resource[] = [];
  const queryLower = query.toLowerCase();

  // Search concepts
  Object.entries(coreConcepts).forEach(([key, value]) => {
    if (
      key.includes(queryLower) ||
      value.title.toLowerCase().includes(queryLower) ||
      value.description.toLowerCase().includes(queryLower)
    ) {
      results.push({
        uri: `nestjs://docs/concepts/${key}`,
        name: value.title,
        description: value.description,
        mimeType: 'text/markdown',
      });
    }
  });

  // Search techniques
  Object.entries(techniques).forEach(([key, value]) => {
    if (
      key.includes(queryLower) ||
      value.title.toLowerCase().includes(queryLower) ||
      value.description.toLowerCase().includes(queryLower)
    ) {
      results.push({
        uri: `nestjs://docs/techniques/${key}`,
        name: value.title,
        description: value.description,
        mimeType: 'text/markdown',
      });
    }
  });

  return results;
}
