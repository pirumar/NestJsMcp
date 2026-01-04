// NestJS Deployment Tools

export interface DeploymentConfig {
  filename: string;
  content: string;
  description: string;
}

// Generate GitHub Actions CI/CD workflow
export function generateGitHubActions(options: {
  nodeVersion?: string;
  database?: 'postgres' | 'mysql' | 'mongodb';
  docker?: boolean;
  registry?: string;
}): DeploymentConfig {
  const nodeVersion = options.nodeVersion || '20';

  let testServices = '';
  let envVars = '';

  if (options.database === 'postgres') {
    testServices = `
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5`;
    envVars = `
        DB_HOST: localhost
        DB_PORT: 5432
        DB_USERNAME: test
        DB_PASSWORD: test
        DB_NAME: test`;
  }

  if (options.database === 'mongodb') {
    testServices = `
    services:
      mongodb:
        image: mongo:6
        ports:
          - 27017:27017`;
    envVars = `
        MONGODB_URI: mongodb://localhost:27017/test`;
  }

  let dockerBuild = '';
  if (options.docker) {
    const registry = options.registry || 'ghcr.io';
    dockerBuild = `

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Login to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${registry}
          username: \${{ github.actor }}
          password: \${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${registry}/\${{ github.repository }}
          tags: |
            type=ref,event=branch
            type=sha,prefix=

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: \${{ steps.meta.outputs.tags }}
          labels: \${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max`;
  }

  const content = `name: CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '${nodeVersion}'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run linter
        run: npm run lint

  test:
    runs-on: ubuntu-latest
${testServices}

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '${nodeVersion}'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm run test:cov
        env:
          NODE_ENV: test${envVars}

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info

  e2e:
    runs-on: ubuntu-latest
${testServices}

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '${nodeVersion}'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run e2e tests
        run: npm run test:e2e
        env:
          NODE_ENV: test${envVars}
${dockerBuild}
`;

  return {
    filename: '.github/workflows/ci.yml',
    content,
    description: 'GitHub Actions CI/CD workflow',
  };
}

// Generate GitLab CI configuration
export function generateGitLabCI(options: {
  nodeVersion?: string;
  database?: 'postgres' | 'mysql' | 'mongodb';
  docker?: boolean;
}): DeploymentConfig {
  const nodeVersion = options.nodeVersion || '20';

  let services = '';
  let variables = '';

  if (options.database === 'postgres') {
    services = `
  services:
    - postgres:15
  variables:
    POSTGRES_DB: test
    POSTGRES_USER: test
    POSTGRES_PASSWORD: test
    DB_HOST: postgres`;
  }

  if (options.database === 'mongodb') {
    services = `
  services:
    - mongo:6
  variables:
    MONGODB_URI: mongodb://mongo:27017/test`;
  }

  let dockerBuild = '';
  if (options.docker) {
    dockerBuild = `

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main

deploy:
  stage: deploy
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker pull $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - docker tag $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE:latest
    - docker push $CI_REGISTRY_IMAGE:latest
  only:
    - main
  when: manual`;
  }

  const content = `image: node:${nodeVersion}

stages:
  - install
  - lint
  - test
  - build
  - deploy

cache:
  key: \${CI_COMMIT_REF_SLUG}
  paths:
    - node_modules/

install:
  stage: install
  script:
    - npm ci
  artifacts:
    paths:
      - node_modules/

lint:
  stage: lint
  script:
    - npm run lint

test:
  stage: test${services}
  script:
    - npm run test:cov
  coverage: '/All files[^|]*\\|[^|]*\\s+([\\d\\.]+)/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

test:e2e:
  stage: test${services}
  script:
    - npm run test:e2e
${dockerBuild}
`;

  return {
    filename: '.gitlab-ci.yml',
    content,
    description: 'GitLab CI configuration',
  };
}

// Generate Kubernetes deployment
export function generateKubernetesConfig(appName: string, options: {
  replicas?: number;
  port?: number;
  resources?: { cpu: string; memory: string };
  database?: 'postgres' | 'mysql' | 'mongodb';
}): DeploymentConfig[] {
  const configs: DeploymentConfig[] = [];
  const replicas = options.replicas || 3;
  const port = options.port || 3000;
  const resources = options.resources || { cpu: '100m', memory: '128Mi' };

  // Deployment
  configs.push({
    filename: `k8s/${appName}-deployment.yaml`,
    content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${appName}
  labels:
    app: ${appName}
spec:
  replicas: ${replicas}
  selector:
    matchLabels:
      app: ${appName}
  template:
    metadata:
      labels:
        app: ${appName}
    spec:
      containers:
        - name: ${appName}
          image: ${appName}:latest
          ports:
            - containerPort: ${port}
          env:
            - name: NODE_ENV
              value: production
            - name: PORT
              value: "${port}"
          envFrom:
            - secretRef:
                name: ${appName}-secrets
            - configMapRef:
                name: ${appName}-config
          resources:
            requests:
              cpu: ${resources.cpu}
              memory: ${resources.memory}
            limits:
              cpu: ${parseInt(resources.cpu) * 2}m
              memory: ${parseInt(resources.memory) * 2}Mi
          livenessProbe:
            httpGet:
              path: /health
              port: ${port}
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: ${port}
            initialDelaySeconds: 5
            periodSeconds: 5
`,
    description: 'Kubernetes Deployment',
  });

  // Service
  configs.push({
    filename: `k8s/${appName}-service.yaml`,
    content: `apiVersion: v1
kind: Service
metadata:
  name: ${appName}
spec:
  selector:
    app: ${appName}
  ports:
    - protocol: TCP
      port: 80
      targetPort: ${port}
  type: ClusterIP
`,
    description: 'Kubernetes Service',
  });

  // Ingress
  configs.push({
    filename: `k8s/${appName}-ingress.yaml`,
    content: `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${appName}
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: ${appName}-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ${appName}
                port:
                  number: 80
`,
    description: 'Kubernetes Ingress',
  });

  // ConfigMap
  configs.push({
    filename: `k8s/${appName}-configmap.yaml`,
    content: `apiVersion: v1
kind: ConfigMap
metadata:
  name: ${appName}-config
data:
  NODE_ENV: production
  LOG_LEVEL: info
`,
    description: 'Kubernetes ConfigMap',
  });

  // Secret template
  configs.push({
    filename: `k8s/${appName}-secret.yaml`,
    content: `apiVersion: v1
kind: Secret
metadata:
  name: ${appName}-secrets
type: Opaque
stringData:
  JWT_SECRET: "your-jwt-secret-here"
  DB_PASSWORD: "your-db-password-here"
`,
    description: 'Kubernetes Secret (template)',
  });

  // HPA
  configs.push({
    filename: `k8s/${appName}-hpa.yaml`,
    content: `apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ${appName}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ${appName}
  minReplicas: ${replicas}
  maxReplicas: ${replicas * 3}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
`,
    description: 'Kubernetes HPA',
  });

  return configs;
}

// Generate PM2 ecosystem file
export function generatePM2Config(appName: string, options: {
  instances?: number | 'max';
  maxMemory?: string;
}): DeploymentConfig {
  const instances = options.instances || 'max';
  const maxMemory = options.maxMemory || '1G';

  const content = `module.exports = {
  apps: [
    {
      name: '${appName}',
      script: 'dist/main.js',
      instances: '${instances}',
      exec_mode: 'cluster',
      autorestart: true,
      watch: false,
      max_memory_restart: '${maxMemory}',
      env: {
        NODE_ENV: 'development',
        PORT: 3000,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000,
      },
      error_file: 'logs/error.log',
      out_file: 'logs/output.log',
      merge_logs: true,
      time: true,
    },
  ],

  deploy: {
    production: {
      user: 'deploy',
      host: ['server1.example.com', 'server2.example.com'],
      ref: 'origin/main',
      repo: 'git@github.com:username/${appName}.git',
      path: '/var/www/${appName}',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env production',
      'pre-setup': '',
    },
  },
};
`;

  return {
    filename: 'ecosystem.config.js',
    content,
    description: 'PM2 ecosystem configuration',
  };
}

// Generate Nginx configuration
export function generateNginxConfig(appName: string, options: {
  domain: string;
  port?: number;
  ssl?: boolean;
}): DeploymentConfig {
  const port = options.port || 3000;

  let sslConfig = '';
  let listenConfig = 'listen 80;';

  if (options.ssl) {
    listenConfig = `listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate /etc/letsencrypt/live/${options.domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${options.domain}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000" always;`;

    sslConfig = `
server {
    listen 80;
    listen [::]:80;
    server_name ${options.domain};
    return 301 https://$server_name$request_uri;
}
`;
  }

  const content = `${sslConfig}
upstream ${appName} {
    least_conn;
    server 127.0.0.1:${port} weight=1;
    # Add more servers for load balancing
    # server 127.0.0.1:${port + 1} weight=1;
    keepalive 64;
}

server {
    ${listenConfig}
    server_name ${options.domain};

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied expired no-cache no-store private auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml application/json;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    location / {
        limit_req zone=api burst=20 nodelay;

        proxy_pass http://${appName};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 90s;
        proxy_connect_timeout 90s;
    }

    # Health check endpoint (no rate limit)
    location /health {
        proxy_pass http://${appName};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }

    # Static files (if any)
    location /static/ {
        alias /var/www/${appName}/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Deny access to sensitive files
    location ~ /\\. {
        deny all;
    }
}
`;

  return {
    filename: `nginx/${appName}.conf`,
    content,
    description: 'Nginx configuration',
  };
}

// Generate systemd service
export function generateSystemdService(appName: string, options: {
  user?: string;
  workingDir?: string;
  nodeVersion?: string;
}): DeploymentConfig {
  const user = options.user || 'www-data';
  const workingDir = options.workingDir || `/var/www/${appName}`;
  const nodeVersion = options.nodeVersion || '20';

  const content = `[Unit]
Description=${appName} NestJS Application
Documentation=https://docs.nestjs.com
After=network.target

[Service]
Type=simple
User=${user}
WorkingDirectory=${workingDir}
Environment=NODE_ENV=production
Environment=PORT=3000
ExecStart=/usr/bin/node dist/main.js
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${appName}

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${workingDir}/logs

[Install]
WantedBy=multi-user.target
`;

  return {
    filename: `${appName}.service`,
    content,
    description: 'Systemd service configuration',
  };
}

// Generate environment-specific configuration
export function generateEnvFiles(): DeploymentConfig[] {
  return [
    {
      filename: '.env.development',
      content: `NODE_ENV=development
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_NAME=app_dev

# JWT
JWT_SECRET=dev-secret-change-in-production
JWT_EXPIRES_IN=1d

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:4200

# Logging
LOG_LEVEL=debug
`,
      description: 'Development environment variables',
    },
    {
      filename: '.env.production',
      content: `NODE_ENV=production
PORT=3000

# Database (use secrets manager in production)
DB_HOST=
DB_PORT=5432
DB_USERNAME=
DB_PASSWORD=
DB_NAME=

# JWT (use secrets manager in production)
JWT_SECRET=
JWT_EXPIRES_IN=15m

# Redis
REDIS_HOST=
REDIS_PORT=6379

# CORS
CORS_ORIGINS=https://app.example.com

# Logging
LOG_LEVEL=info
`,
      description: 'Production environment variables template',
    },
    {
      filename: '.env.test',
      content: `NODE_ENV=test
PORT=3001

# Test Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=test
DB_PASSWORD=test
DB_NAME=app_test

# JWT
JWT_SECRET=test-secret
JWT_EXPIRES_IN=1h

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# CORS
CORS_ORIGINS=*

# Logging
LOG_LEVEL=error
`,
      description: 'Test environment variables',
    },
  ];
}
