# Deployment Guide

## Overview

Panduan ini menjelaskan cara deploy aplikasi yang menggunakan Microservices Library Go ke berbagai environment, dari development hingga production.

## Prerequisites

### System Requirements

- **Go**: Version 1.19 atau lebih baru
- **Docker**: Version 20.10 atau lebih baru
- **Kubernetes**: Version 1.20 atau lebih baru (opsional)
- **Helm**: Version 3.0 atau lebih baru (opsional)

### External Services

- **Database**: PostgreSQL, MySQL, MongoDB, dll
- **Cache**: Redis, Memcached
- **Message Queue**: Kafka, NATS, RabbitMQ
- **Storage**: S3, GCS, Azure Blob
- **Monitoring**: Prometheus, Jaeger, Elasticsearch

## Development Environment

### 1. Local Development Setup

```bash
# Clone repository
git clone https://github.com/anasamu/go-micro-libs.git
cd microservices-library-go

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o microservice ./cmd/main.go
```

### 2. Docker Compose for Local Development

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: microservice
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  kafka:
    image: confluentinc/cp-kafka:latest
    environment:
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    ports:
      - "9092:9092"
    depends_on:
      - zookeeper

  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - "2181:2181"

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  postgres_data:
  redis_data:
  grafana_data:
```

### 3. Environment Configuration

```bash
# .env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=microservice

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Kafka
KAFKA_BROKERS=localhost:9092

# S3
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET=my-bucket

# OpenAI
OPENAI_API_KEY=your-api-key

# Monitoring
PROMETHEUS_URL=http://localhost:9090
JAEGER_ENDPOINT=http://localhost:14268/api/traces
```

## Staging Environment

### 1. Kubernetes Deployment

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: microservice-staging
```

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: microservice-config
  namespace: microservice-staging
data:
  config.yaml: |
    database:
      postgresql:
        host: postgres-staging
        port: 5432
        user: postgres
        password: ${DB_PASSWORD}
        database: microservice_staging
    
    cache:
      redis:
        host: redis-staging
        port: 6379
        password: ${REDIS_PASSWORD}
    
    messaging:
      kafka:
        brokers:
          - kafka-staging:9092
    
    storage:
      s3:
        region: us-east-1
        bucket: microservice-staging
        access_key_id: ${AWS_ACCESS_KEY_ID}
        secret_access_key: ${AWS_SECRET_ACCESS_KEY}
```

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: microservice-secrets
  namespace: microservice-staging
type: Opaque
data:
  DB_PASSWORD: <base64-encoded-password>
  REDIS_PASSWORD: <base64-encoded-password>
  AWS_ACCESS_KEY_ID: <base64-encoded-access-key>
  AWS_SECRET_ACCESS_KEY: <base64-encoded-secret-key>
  OPENAI_API_KEY: <base64-encoded-api-key>
```

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: microservice
  namespace: microservice-staging
spec:
  replicas: 3
  selector:
    matchLabels:
      app: microservice
  template:
    metadata:
      labels:
        app: microservice
    spec:
      containers:
      - name: microservice
        image: microservice:staging
        ports:
        - containerPort: 8080
        env:
        - name: ENV
          value: "staging"
        envFrom:
        - configMapRef:
            name: microservice-config
        - secretRef:
            name: microservice-secrets
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: microservice-service
  namespace: microservice-staging
spec:
  selector:
    app: microservice
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: microservice-ingress
  namespace: microservice-staging
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: microservice-staging.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: microservice-service
            port:
              number: 80
```

### 2. Helm Chart

```yaml
# helm/microservice/Chart.yaml
apiVersion: v2
name: microservice
description: Microservice application
type: application
version: 0.1.0
appVersion: "1.0.0"
```

```yaml
# helm/microservice/values.yaml
replicaCount: 3

image:
  repository: microservice
  tag: "staging"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 80
  targetPort: 8080

ingress:
  enabled: true
  className: "nginx"
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
  hosts:
    - host: microservice-staging.example.com
      paths:
        - path: /
          pathType: Prefix

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

config:
  database:
    host: postgres-staging
    port: 5432
    user: postgres
    database: microservice_staging
  
  cache:
    host: redis-staging
    port: 6379
  
  messaging:
    brokers:
      - kafka-staging:9092
  
  storage:
    region: us-east-1
    bucket: microservice-staging
```

```yaml
# helm/microservice/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "microservice.fullname" . }}
  labels:
    {{- include "microservice.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "microservice.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "microservice.selectorLabels" . | nindent 8 }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - name: http
              containerPort: {{ .Values.service.targetPort }}
              protocol: TCP
          env:
            - name: ENV
              value: "{{ .Values.environment }}"
          envFrom:
            - configMapRef:
                name: {{ include "microservice.fullname" . }}-config
            - secretRef:
                name: {{ include "microservice.fullname" . }}-secrets
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: http
            initialDelaySeconds: 5
            periodSeconds: 5
```

## Production Environment

### 1. Production Kubernetes Setup

```yaml
# k8s/production/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: microservice-production
  labels:
    name: microservice-production
```

```yaml
# k8s/production/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: microservice-hpa
  namespace: microservice-production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: microservice
  minReplicas: 5
  maxReplicas: 50
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
```

```yaml
# k8s/production/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: microservice-pdb
  namespace: microservice-production
spec:
  minAvailable: 3
  selector:
    matchLabels:
      app: microservice
```

```yaml
# k8s/production/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: microservice-network-policy
  namespace: microservice-production
spec:
  podSelector:
    matchLabels:
      app: microservice
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: microservice-production
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 6379
    - protocol: TCP
      port: 9092
```

### 2. Production Configuration

```yaml
# config/production.yaml
database:
  postgresql:
    host: postgres-production
    port: 5432
    user: postgres
    password: ${DB_PASSWORD}
    database: microservice_production
    max_connections: 100
    max_idle_connections: 10
    connection_max_lifetime: 3600s

cache:
  redis:
    host: redis-production
    port: 6379
    password: ${REDIS_PASSWORD}
    db: 0
    max_retries: 3
    pool_size: 10
    min_idle_conns: 5

messaging:
  kafka:
    brokers:
      - kafka-1:9092
      - kafka-2:9092
      - kafka-3:9092
    group_id: microservice-production
    auto_offset_reset: latest
    enable_auto_commit: true

storage:
  s3:
    region: us-east-1
    bucket: microservice-production
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    max_retries: 3
    timeout: 30s

monitoring:
  prometheus:
    url: http://prometheus:9090
    push_interval: 30s
  
  jaeger:
    endpoint: http://jaeger:14268/api/traces
    service_name: microservice-production

logging:
  level: info
  format: json
  output: stdout

security:
  jwt:
    secret_key: ${JWT_SECRET_KEY}
    expiry: 24h
  
  rate_limit:
    requests_per_minute: 1000
    burst: 100
```

### 3. CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.19
    
    - name: Run tests
      run: go test ./...
    
    - name: Run linter
      run: golangci-lint run

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
    
    - name: Login to Docker Hub
      uses: docker/login-action@v2
      with:
        username: ${{ secrets.DOCKER_USERNAME }}
        password: ${{ secrets.DOCKER_PASSWORD }}
    
    - name: Build and push
      uses: docker/build-push-action@v3
      with:
        context: .
        push: true
        tags: |
          microservice:latest
          microservice:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v1
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG }}
    
    - name: Deploy to Kubernetes
      run: |
        kubectl set image deployment/microservice microservice=microservice:${{ github.sha }} -n microservice-production
        kubectl rollout status deployment/microservice -n microservice-production
```

## Monitoring and Observability

### 1. Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'microservice'
    static_configs:
      - targets: ['microservice:8080']
    metrics_path: /metrics
    scrape_interval: 5s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'kafka'
    static_configs:
      - targets: ['kafka-exporter:9308']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### 2. Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Microservice Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{path}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "5xx errors"
          }
        ]
      }
    ]
  }
}
```

### 3. Alerting Rules

```yaml
# rules/microservice.yml
groups:
- name: microservice
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  - alert: HighResponseTime
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High response time detected"
      description: "95th percentile response time is {{ $value }} seconds"

  - alert: ServiceDown
    expr: up{job="microservice"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Microservice is down"
      description: "Microservice has been down for more than 1 minute"
```

## Security

### 1. Network Security

```yaml
# k8s/security/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: microservice-network-policy
  namespace: microservice-production
spec:
  podSelector:
    matchLabels:
      app: microservice
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: microservice-production
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 6379
    - protocol: TCP
      port: 9092
```

### 2. Pod Security

```yaml
# k8s/security/pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: microservice-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

### 3. RBAC

```yaml
# k8s/security/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: microservice-sa
  namespace: microservice-production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: microservice-role
  namespace: microservice-production
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: microservice-rolebinding
  namespace: microservice-production
subjects:
- kind: ServiceAccount
  name: microservice-sa
  namespace: microservice-production
roleRef:
  kind: Role
  name: microservice-role
  apiGroup: rbac.authorization.k8s.io
```

## Backup and Recovery

### 1. Database Backup

```bash
#!/bin/bash
# backup-db.sh

# Create backup
kubectl exec -n microservice-production postgres-0 -- pg_dump -U postgres microservice_production > backup-$(date +%Y%m%d-%H%M%S).sql

# Upload to S3
aws s3 cp backup-$(date +%Y%m%d-%H%M%S).sql s3://microservice-backups/database/

# Cleanup local backup
rm backup-$(date +%Y%m%d-%H%M%S).sql
```

### 2. Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

# Backup ConfigMaps
kubectl get configmaps -n microservice-production -o yaml > configmaps-$(date +%Y%m%d-%H%M%S).yaml

# Backup Secrets
kubectl get secrets -n microservice-production -o yaml > secrets-$(date +%Y%m%d-%H%M%S).yaml

# Upload to S3
aws s3 cp configmaps-$(date +%Y%m%d-%H%M%S).yaml s3://microservice-backups/config/
aws s3 cp secrets-$(date +%Y%m%d-%H%M%S).yaml s3://microservice-backups/config/
```

## Troubleshooting

### 1. Common Issues

#### Database Connection Issues
```bash
# Check database connectivity
kubectl exec -n microservice-production microservice-0 -- nc -zv postgres-production 5432

# Check database logs
kubectl logs -n microservice-production postgres-0
```

#### Cache Connection Issues
```bash
# Check Redis connectivity
kubectl exec -n microservice-production microservice-0 -- redis-cli -h redis-production ping

# Check Redis logs
kubectl logs -n microservice-production redis-0
```

#### Message Queue Issues
```bash
# Check Kafka connectivity
kubectl exec -n microservice-production microservice-0 -- kafka-topics --bootstrap-server kafka-production:9092 --list

# Check Kafka logs
kubectl logs -n microservice-production kafka-0
```

### 2. Debug Commands

```bash
# Check pod status
kubectl get pods -n microservice-production

# Check pod logs
kubectl logs -n microservice-production microservice-0

# Check pod events
kubectl describe pod -n microservice-production microservice-0

# Check service status
kubectl get services -n microservice-production

# Check ingress status
kubectl get ingress -n microservice-production

# Check HPA status
kubectl get hpa -n microservice-production
```

### 3. Performance Tuning

#### Database Tuning
```sql
-- Check database performance
SELECT * FROM pg_stat_activity;
SELECT * FROM pg_stat_database;

-- Optimize queries
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'user@example.com';
```

#### Cache Tuning
```bash
# Check Redis memory usage
redis-cli info memory

# Check Redis performance
redis-cli --latency-history -i 1
```

#### Message Queue Tuning
```bash
# Check Kafka performance
kafka-consumer-groups --bootstrap-server kafka-production:9092 --describe --group microservice-production

# Check Kafka topics
kafka-topics --bootstrap-server kafka-production:9092 --describe --topic user-events
```

## Maintenance

### 1. Regular Maintenance Tasks

```bash
#!/bin/bash
# maintenance.sh

# Update dependencies
go mod tidy
go mod download

# Run security scan
gosec ./...

# Run tests
go test ./...

# Build and push new image
docker build -t microservice:latest .
docker push microservice:latest

# Deploy to staging
kubectl set image deployment/microservice microservice=microservice:latest -n microservice-staging

# Run integration tests
kubectl exec -n microservice-staging microservice-0 -- go test ./integration/...

# Deploy to production
kubectl set image deployment/microservice microservice=microservice:latest -n microservice-production
```

### 2. Monitoring Maintenance

```bash
#!/bin/bash
# monitoring-maintenance.sh

# Check Prometheus targets
curl http://prometheus:9090/api/v1/targets

# Check Grafana dashboards
curl http://grafana:3000/api/dashboards

# Check Jaeger traces
curl http://jaeger:16686/api/services

# Clean up old metrics
kubectl exec -n monitoring prometheus-0 -- promtool tsdb clean --retention.time=30d
```

### 3. Backup Maintenance

```bash
#!/bin/bash
# backup-maintenance.sh

# Clean up old backups
aws s3 ls s3://microservice-backups/ --recursive | awk '$1 < "'$(date -d '30 days ago' '+%Y-%m-%d')'" {print $4}' | xargs -I {} aws s3 rm s3://microservice-backups/{}

# Verify backup integrity
aws s3 cp s3://microservice-backups/database/backup-20231201-120000.sql - | pg_restore --list
```
