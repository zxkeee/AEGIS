# 📦 Гайд по развертыванию в Production

Этот документ описывает как развернуть AEGIS в production окружении.

## Архитектура Production

```
┌─────────────────────────────────────────────────┐
│          Internet / CDN (Optional)              │
└────────────────┬────────────────────────────────┘
                 │ HTTPS (TLS 1.3)
┌────────────────▼────────────────────────────────┐
│    Load Balancer / Reverse Proxy (nginx/Envoy) │
│         (SSL Termination + WAF Layer 7)        │
└────────────────┬────────────────────────────────┘
                 │ HTTP/2
┌────────────────▼────────────────────────────────┐
│              AEGIS Gateway                      │
│        (3-5 replicas in Kubernetes)             │
│                                                 │
│  - Port 8080: Gateway                          │
│  - Port 8081: Admin API (внутри сети)         │
└────────┬──────────────┬──────────────┬──────────┘
         │              │              │
    ┌────▼──┐       ┌────▼──┐     ┌────▼──┐
    │Redis  │       │PostgreSQL│   │Prometheus│
    │Cluster│       │(Forensic)│   │/Grafana│
    └───────┘       └────────┘     └────────┘
         │
    ┌────▼──────────┐
    │Backend Services│
    │(Internal NAT) │
    └───────────────┘
```

## 1. Kubernetes Deployment

### Предусловия
- Kubernetes кластер 1.25+
- Helm 3.0+
- kubectl configured для вашего кластера
- Docker Registry (для образов)

### Развертывание

#### 1.1 Подготовка образа

```bash
# Соберите Docker образ (если не используете готовый)
docker build -t your-registry/aegis:2.1.0 .

# Push в ваш Docker Registry
docker push your-registry/aegis:2.1.0
```

#### 1.2 Настройка Helm Values

Создайте файл `values-prod.yaml`:

```yaml
# Образ
image:
  repository: your-registry/aegis
  tag: "2.1.0"
  pullPolicy: IfNotPresent

# Реплики (для HA)
replicaCount: 3

# Resources
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "1000m"

# Persistent Volume для логов (опционально)
persistence:
  enabled: true
  size: "10Gi"
  storageClass: "fast-ssd"

# ConfigMap с конфигурацией
config:
  listen: ":8080"
  admin_listen: ":8081"
  admin_auth: true
  admin_secret: "your-super-secret-admin-key"
  redis:
    addr: "redis-cluster:6379"  # Redis Cluster
  forensic_dsn: "postgres://aegis:password@postgres:5432/aegis?sslmode=require"

# Security Policy
securityPolicy:
  enabled: true
  runAsNonRoot: true
  runAsUser: 1000
  fsReadOnlyRootFilesystem: true
  allowPrivilegeEscalation: false

# Network Policy
networkPolicy:
  enabled: true
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: ingress
```

#### 1.3 Развертывание через Helm

```bash
# Создайте namespace
kubectl create namespace security

# Установите AEGIS
helm install aegis-gateway ./charts/aegis \
  -f values-prod.yaml \
  -n security

# Проверьте статус
kubectl get pods -n security
kubectl get svc -n security

# Посмотрите логи
kubectl logs -n security -l app=aegis-gateway -f
```

#### 1.4 Проверка здоровья

```bash
# Port-forward для тестирования
kubectl port-forward -n security svc/aegis-gateway 8080:8080 &

# Проверьте лайвнес
curl http://localhost:8080/healthz

# Проверьте админ-панель
curl -H "Authorization: Bearer your-admin-token" \
  http://localhost:8081/api/v1/status
```

### Обновление в production

```bash
# Обновите Helm Chart с новой версией
helm upgrade aegis-gateway ./charts/aegis \
  -f values-prod.yaml \
  -n security

# Проверьте rollout status
kubectl rollout status deployment/aegis-gateway -n security

# Откатитесь, если нужно
helm rollback aegis-gateway 1 -n security
```

---

## 2. Настройка Ingress (вход в K8s)

### Nginx Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: aegis-ingress
  namespace: security
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"

spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - api.example.com
      secretName: aegis-tls-cert

  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: aegis-gateway
                port:
                  number: 8080
```

### SSL/TLS (Let's Encrypt + cert-manager)

```bash
# Установите cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Создайте ClusterIssuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
```

---

## 3. Настройка High Availability (HA)

### Redis HA (Redis Cluster)

```bash
# Установите Redis Cluster (via Helm)
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install redis bitnami/redis \
  --set architecture=cluster \
  --set redis.auth.enabled=true \
  --set redis.auth.password=your-strong-password \
  -n security
```

### PostgreSQL HA (Primary-Replica)

```bash
# Установите PostgreSQL HA (via Helm)
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgres bitnami/postgresql \
  --set replication.enabled=true \
  --set replication.numReplicas=2 \
  --set primary.persistence.size=50Gi \
  -n security
```

### Load Balancing внутри K8s

AEGIS автоматически использует Kubernetes Service, который балансирует трафик между репликами:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: aegis-gateway
  namespace: security
spec:
  type: ClusterIP
  selector:
    app: aegis-gateway
  ports:
    - port: 8080
      targetPort: 8080
      name: gateway
    - port: 8081
      targetPort: 8081
      name: admin
```

---

## 4. Мониторинг и Observability

### Prometheus

```yaml
apiVersion: v1
kind: Service
metadata:
  name: aegis-prometheus
  namespace: security
spec:
  selector:
    app: prometheus
  ports:
    - port: 9090
      targetPort: 9090
```

Добавьте Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: 'aegis-gateway'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - security
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: aegis-gateway
      - source_labels: [__meta_kubernetes_pod_port_name]
        action: keep
        regex: metrics
```

### Grafana Dashboard

```bash
# Добавьте Prometheus Data Source в Grafana
# Импортируйте Dashboard из: ./dashboards/aegis-gateway.json
# Создайте Alerts для критических метрик
```

### Alerts (AlertManager)

```yaml
groups:
  - name: aegis
    rules:
      - alert: HighWAFBlockRate
        expr: rate(aegis_waf_blocks_total[5m]) > 100
        for: 5m
        annotations:
          summary: "High WAF block rate detected"

      - alert: HighErrorRate
        expr: rate(aegis_requests_total{status=~"5.."}[5m]) > 0.05
        for: 2m
        annotations:
          summary: "High 5xx error rate"

      - alert: RedisConnectionDown
        expr: up{job="aegis-redis"} == 0
        for: 1m
        annotations:
          summary: "Redis connection down"
```

---

## 5. Backup и Disaster Recovery

### PostgreSQL Backups

```bash
# Автоматический backup (ежедневно)
kubectl set env deployment/postgres BACKUP_ENABLED=true -n security

# Manual backup
kubectl exec -n security postgres-0 -- \
  pg_dump -U aegis aegis > backup-$(date +%Y%m%d).sql

# Restore from backup
kubectl exec -n security postgres-0 -- \
  psql -U aegis aegis < backup-20250430.sql
```

### ConfigMap Versioning

```bash
# Сохраняйте конфиги в Git
git add config/gateway.yaml
git commit -m "prod: update gateway config"
git push

# Восстановление из Git
git checkout config/gateway.yaml  # Recover old version
kubectl apply -f config/gateway.yaml
```

---

## 6. Security Best Practices

### Network Security

```yaml
# Network Policy (изолировать трафик)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: aegis-network-policy
  namespace: security
spec:
  podSelector:
    matchLabels:
      app: aegis-gateway
  
  ingress:
    # Трафик от Ingress Controller
    - from:
      - namespaceSelector:
          matchLabels:
            name: ingress-nginx
      ports:
      - protocol: TCP
        port: 8080
    
    # Admin API только из админ-namespace
    - from:
      - namespaceSelector:
          matchLabels:
            name: admin
      ports:
      - protocol: TCP
        port: 8081
  
  egress:
    # Redis
    - to:
      - podSelector:
          matchLabels:
            app: redis
      ports:
      - protocol: TCP
        port: 6379
    
    # PostgreSQL
    - to:
      - podSelector:
          matchLabels:
            app: postgres
      ports:
      - protocol: TCP
        port: 5432
    
    # Backend services (в разных namespace)
    - to:
      - namespaceSelector:
          matchLabels:
            name: backend
      ports:
      - protocol: TCP
        port: 8080
```

### Pod Security Policy

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: aegis-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'MustRunAs'
    seLinuxOptions:
      level: 's0:c123,c456'
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1000
        max: 65535
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  readOnlyRootFilesystem: true
```

---

## 7. Масштабирование (Auto-scaling)

### Horizontal Pod Autoscaler (HPA)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: aegis-gateway-hpa
  namespace: security
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: aegis-gateway
  
  minReplicas: 3
  maxReplicas: 10
  
  metrics:
    # По CPU
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    
    # По памяти
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
    
    # По кастомной метрике (RPS)
    - type: Pods
      pods:
        metric:
          name: http_requests_per_second
        target:
          type: AverageValue
          averageValue: "1k"  # 1000 req/sec per pod
```

---

## 8. Troubleshooting

### Pods не стартуют

```bash
# Проверьте логи
kubectl logs -n security <pod-name>

# Проверьте events
kubectl describe pod -n security <pod-name>

# Проверьте resources
kubectl top pods -n security
```

### Медленные ответы

```bash
# Проверьте метрики
kubectl exec -n security <pod-name> -- curl localhost:8081/metrics | grep latency

# Проверьте Redis
kubectl exec -n security redis-0 -- redis-cli INFO stats

# Проверьте PostgreSQL
kubectl exec -n security postgres-0 -- psql -U aegis aegis -c "SELECT * FROM pg_stat_statements"
```

### Потеря данных

```bash
# Проверьте backup'ы
kubectl get pvc -n security

# Восстановите из backup'а
# (см. раздел Backup and Disaster Recovery)
```

---

## 9. Обновление в Production (Zero-downtime)

```bash
# 1. Создайте новый образ
docker build -t your-registry/aegis:2.2.0 .
docker push your-registry/aegis:2.2.0

# 2. Обновите Helm values
# Измените tag в values-prod.yaml на 2.2.0

# 3. Выполните helm upgrade (Rolling Update)
helm upgrade aegis-gateway ./charts/aegis \
  -f values-prod.yaml \
  -n security \
  --timeout 10m

# 4. Следите за rollout
kubectl rollout status deployment/aegis-gateway -n security -w

# 5. Если что-то не так, откатитесь
helm rollback aegis-gateway -n security
```

---

**Готово к production! Удачи! 🚀**
